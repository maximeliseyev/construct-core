use crate::api::contacts::{Contact, ContactManager};
use crate::api::crypto::CryptoCore;
use crate::auth::TokenManager;
use crate::protocol::long_polling::LongPollingManager;
use crate::protocol::rest_transport::RestClient;
use crate::storage::models::*;
use crate::storage::traits::{DataStorage, SecureStorage};
use crate::utils::error::Result;
use crate::utils::time::current_timestamp;
use base64::Engine;
use std::collections::HashMap;
use std::marker::PhantomData;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

#[cfg(target_arch = "wasm32")]
use crate::storage::indexeddb::IndexedDbStorage;

#[cfg(not(target_arch = "wasm32"))]
use crate::storage::memory::MemoryStorage;

use crate::crypto::CryptoProvider;
use crate::state::conversations::ConversationsManager;

// ConnectionState удален - больше не нужен для REST API
// Long polling управляется через LongPollingManager

/// Состояние UI
#[derive(Debug, Clone)]
pub struct UiState {
    pub is_loading: bool,
    pub error_message: Option<String>,
    pub notification: Option<String>,
}

impl UiState {
    pub fn new() -> Self {
        Self {
            is_loading: false,
            error_message: None,
            notification: None,
        }
    }

    pub fn set_loading(&mut self, loading: bool) {
        self.is_loading = loading;
    }

    pub fn set_error(&mut self, error: String) {
        self.error_message = Some(error);
    }

    pub fn clear_error(&mut self) {
        self.error_message = None;
    }

    pub fn set_notification(&mut self, notification: String) {
        self.notification = Some(notification);
    }

    pub fn clear_notification(&mut self) {
        self.notification = None;
    }
}

impl Default for UiState {
    fn default() -> Self {
        Self::new()
    }
}

// ReconnectState удален - больше не нужен для REST API
// LongPollingManager имеет встроенный exponential backoff

/// Главное состояние всего приложения
///
/// Generic параметры:
/// - `P`: CryptoProvider (Classic, PostQuantum, Hybrid)
/// - `S`: SecureStorage & DataStorage (IndexedDbStorage для Web, MemoryStorage для тестов)
pub struct AppState<P: CryptoProvider, S: SecureStorage + DataStorage> {
    // === Идентификация пользователя ===
    user_id: Option<String>,
    username: Option<String>,

    // === Менеджеры ===
    crypto_manager: CryptoCore<P>,
    contact_manager: ContactManager,
    conversations_manager: ConversationsManager,

    // === Хранилище ===
    /// Unified storage (реализует оба trait: SecureStorage и DataStorage)
    storage: Arc<S>,

    // === REST компоненты ===
    rest_client: Arc<RestClient>,
    token_manager: Arc<TokenManager<S>>,
    long_polling_manager: Option<Arc<LongPollingManager<S>>>,

    // === Состояние ===
    server_url: Option<String>,
    polling_active: Arc<AtomicBool>,

    // === Кеш сообщений (в памяти) ===
    message_cache: HashMap<String, Vec<StoredMessage>>,

    // === Состояние UI ===
    active_conversation: Option<String>,
    ui_state: UiState,

    _phantom: PhantomData<P>,
}

#[cfg(target_arch = "wasm32")]
impl<P: CryptoProvider> AppState<P, IndexedDbStorage> {
    /// Создать новое состояние приложения для Web (WASM)
    ///
    /// # Параметры
    /// - `server_url`: URL сервера для REST API (например, "https://api.example.com")
    pub async fn new(server_url: String) -> Result<Self> {
        // 1. Инициализировать storage
        let mut storage_instance = IndexedDbStorage::new();
        storage_instance.init().await?;

        let storage = Arc::new(storage_instance);

        // 2. Создать REST client
        let rest_client = Arc::new(RestClient::new(server_url.clone()));

        // 3. Создать Token Manager
        use crate::auth::TokenManagerBuilder;
        let token_manager = Arc::new(
            TokenManagerBuilder::new()
                .rest_client(rest_client.clone())
                .storage(storage.clone())
                .refresh_threshold_secs(5 * 60) // 5 минут
                .build()?,
        );

        // 4. Инициализировать Token Manager (загрузить токены из storage)
        token_manager.init().await?;

        // 5. Создать остальные компоненты
        let crypto_manager = CryptoCore::<P>::new()?;
        let contact_manager = ContactManager::new();
        let conversations_manager = ConversationsManager::new();

        Ok(Self {
            user_id: None,
            username: None,
            crypto_manager,
            contact_manager,
            conversations_manager,
            storage,
            rest_client,
            token_manager,
            long_polling_manager: None,
            server_url: Some(server_url),
            polling_active: Arc::new(AtomicBool::new(false)),
            message_cache: HashMap::new(),
            active_conversation: None,
            ui_state: UiState::new(),
            _phantom: PhantomData,
        })
    }
}

// ============================================================================
// Общие методы для всех платформ
// ============================================================================

impl<P: CryptoProvider, S: SecureStorage + DataStorage> AppState<P, S> {
    // === Аутентификация ===

    /// Зарегистрироваться на сервере через REST API
    ///
    /// # Шаги:
    /// 1. Валидация пароля
    /// 2. Экспортировать registration bundle (ключи)
    /// 3. Отправить POST /api/v1/auth/register
    /// 4. Получить access_token, refresh_token, user_id
    /// 5. Сохранить токены через TokenManager
    /// 6. Запустить long polling
    pub async fn register(&mut self, username: String, password: String) -> Result<()> {
        use crate::crypto::master_key;
        use crate::protocol::rest_transport::RegisterRequest;

        self.ui_state.set_loading(true);

        // 1. Валидация пароля
        master_key::validate_password(&password)?;

        // 2. Экспортировать registration bundle
        let bundle = self.crypto_manager.export_registration_bundle_b64()?;

        // 3. Создать RegisterRequest
        let request = RegisterRequest {
            username: username.clone(),
            password,
            public_key: bundle.identity_public, // Base64-encoded identity key
        };

        // 4. Отправить запрос через REST client
        let auth_tokens = self.rest_client.register(request).await?;

        // 5. Сохранить токены через TokenManager
        self.token_manager.set_tokens(auth_tokens.clone()).await?;

        // 6. Сохранить user_id и username
        self.user_id = Some(auth_tokens.user_id.clone());
        self.username = Some(username);

        // 7. Запустить long polling
        self.start_polling().await?;

        self.ui_state.set_loading(false);
        Ok(())
    }

    /// Войти в систему через REST API
    ///
    /// # Шаги:
    /// 1. Отправить POST /api/v1/auth/login
    /// 2. Получить access_token, refresh_token, user_id
    /// 3. Сохранить токены через TokenManager
    /// 4. Загрузить приватные ключи из secure storage
    /// 5. Запустить long polling
    pub async fn login(&mut self, username: String, password: String) -> Result<()> {
        use crate::protocol::rest_transport::LoginRequest;

        self.ui_state.set_loading(true);

        // 1. Создать LoginRequest
        let request = LoginRequest {
            username: username.clone(),
            password,
        };

        // 2. Отправить запрос
        let auth_tokens = self.rest_client.login(request).await?;

        // 3. Сохранить токены
        self.token_manager.set_tokens(auth_tokens.clone()).await?;

        // 4. Сохранить user_id и username
        self.user_id = Some(auth_tokens.user_id.clone());
        self.username = Some(username);

        // 5. Загрузить приватные ключи из secure storage (если есть)
        if let Some(_keys) = self.storage.load_private_keys().await? {
            // TODO: расшифровать и загрузить в CryptoCore
            // self.crypto_manager.load_keys(keys)?;
        }

        // 6. Запустить long polling
        self.start_polling().await?;

        self.ui_state.set_loading(false);
        Ok(())
    }

    /// Выйти из системы
    ///
    /// # Шаги:
    /// 1. Остановить long polling
    /// 2. Очистить токены через TokenManager
    /// 3. Очистить локальное состояние
    pub async fn logout(&mut self) -> Result<()> {
        // 1. Остановить polling
        self.stop_polling();

        // 2. Очистить токены (автоматически вызовет REST endpoint)
        self.token_manager.clear_tokens().await?;

        // 3. Очистить состояние
        self.user_id = None;
        self.username = None;
        self.message_cache.clear();
        self.conversations_manager.clear_all();
        self.contact_manager.clear_all();

        Ok(())
    }

    // === Отправка сообщений ===

    /// Отправить сообщение через REST API
    ///
    /// # Параметры
    /// - `to_contact_id`: ID получателя
    /// - `plaintext`: Текст сообщения
    ///
    /// # Возвращает
    /// ID отправленного сообщения
    pub async fn send_message(&mut self, to_contact_id: &str, plaintext: &str) -> Result<String> {
        self.ui_state.set_loading(true);

        // TODO: зашифровать сообщение через CryptoCore
        // let encrypted = self.crypto_manager.encrypt_message(to_contact_id, plaintext.as_bytes())?;

        // Пока используем заглушку
        let encrypted_content = base64::engine::general_purpose::STANDARD.encode(plaintext);

        // Получить access token
        let access_token = self.token_manager.get_valid_token().await?;

        // Создать запрос (упрощенная версия)
        let message_json = serde_json::json!({
            "recipientId": to_contact_id,
            "suiteId": 1,
            "ciphertext": encrypted_content,
            "timestamp": current_timestamp(),
        });

        // Отправить через REST
        use crate::protocol::rest_transport::RequestOptions;
        let options = RequestOptions {
            access_token: Some(access_token),
            csrf_token: None,
            request_signature: None,
        };

        #[derive(serde::Deserialize)]
        struct SendMessageResponse {
            #[serde(rename = "messageId")]
            message_id: String,
        }

        let response: SendMessageResponse = self
            .rest_client
            .send_message(&message_json, options)
            .await?;

        // Сохранить в local storage
        let stored_message = StoredMessage {
            id: response.message_id.clone(),
            conversation_id: to_contact_id.to_string(),
            from: self.user_id.clone().unwrap(),
            to: to_contact_id.to_string(),
            encrypted_content: encrypted_content.clone(),
            timestamp: current_timestamp(),
            status: MessageStatus::Sent,
        };

        self.storage.save_message(&stored_message).await?;

        // Обновить кеш
        self.message_cache
            .entry(to_contact_id.to_string())
            .or_insert_with(Vec::new)
            .push(stored_message);

        self.ui_state.set_loading(false);
        Ok(response.message_id)
    }

    // === Long Polling ===

    /// Запустить long polling для получения сообщений
    pub async fn start_polling(&mut self) -> Result<()> {
        use crate::protocol::long_polling::{LongPollingManagerBuilder, MessageHandler};
        use std::future::Future;
        use std::pin::Pin;

        // Проверить что не запущен уже
        if self.polling_active.load(Ordering::SeqCst) {
            return Ok(());
        }

        // Создать простой message handler (заглушка)
        struct SimpleMessageHandler;
        impl MessageHandler for SimpleMessageHandler {
            fn handle_message(
                &self,
                message: crate::protocol::long_polling::EncryptedMessage,
            ) -> Pin<Box<dyn Future<Output = Result<()>> + Send>> {
                Box::pin(async move {
                    tracing::info!("Received message: {:?}", message);
                    // TODO: расшифровать и сохранить
                    Ok(())
                })
            }
        }

        // Создать LongPollingManager если не создан
        if self.long_polling_manager.is_none() {
            let manager = LongPollingManagerBuilder::new()
                .rest_client(self.rest_client.clone())
                .token_manager(self.token_manager.clone())
                .message_handler(Arc::new(SimpleMessageHandler))
                .poll_timeout_secs(30)
                .retry_delays(1000, 30000)
                .build()?;

            self.long_polling_manager = Some(Arc::new(manager));
        }

        // Пометить как активный
        self.polling_active.store(true, Ordering::SeqCst);

        // TODO: запустить в фоновой задаче для WASM
        // Для тестов просто помечаем как активный

        Ok(())
    }

    /// Остановить long polling
    /// Остановить long polling
    pub fn stop_polling(&mut self) {
        if let Some(ref manager) = self.long_polling_manager {
            manager.stop();
        }
        self.polling_active.store(false, Ordering::SeqCst);
    }

    /// Проверить активен ли polling
    pub fn is_polling_active(&self) -> bool {
        self.polling_active.load(Ordering::SeqCst)
    }

    // === Геттеры ===

    pub fn get_user_id(&self) -> Option<&str> {
        self.user_id.as_deref()
    }

    pub fn get_username(&self) -> Option<&str> {
        self.username.as_deref()
    }

    pub fn ui_state(&self) -> &UiState {
        &self.ui_state
    }

    pub fn ui_state_mut(&mut self) -> &mut UiState {
        &mut self.ui_state
    }

    pub fn crypto_manager(&self) -> &CryptoCore<P> {
        &self.crypto_manager
    }

    pub fn crypto_manager_mut(&mut self) -> &mut CryptoCore<P> {
        &mut self.crypto_manager
    }

    pub fn conversations_manager(&self) -> &ConversationsManager {
        &self.conversations_manager
    }

    pub fn conversations_manager_mut(&mut self) -> &mut ConversationsManager {
        &mut self.conversations_manager
    }

    pub fn get_server_url(&self) -> Option<&str> {
        self.server_url.as_deref()
    }

    /// Получить все контакты
    pub fn get_contacts(&self) -> Vec<&Contact> {
        self.contact_manager.get_all_contacts()
    }

    /// Установить активную беседу
    pub fn set_active_conversation(&mut self, contact_id: Option<String>) {
        self.active_conversation = contact_id;
    }

    /// Получить активную беседу
    pub fn get_active_conversation(&self) -> Option<&str> {
        self.active_conversation.as_deref()
    }

    /// Добавить контакт
    pub async fn add_contact(&mut self, contact_id: String, username: String) -> Result<()> {
        // 1. Добавить в ContactManager
        let contact = crate::api::contacts::create_contact(contact_id.clone(), username.clone());
        self.contact_manager.add_contact(contact)?;

        // 2. Сохранить в storage
        let stored = StoredContact {
            id: contact_id,
            username,
            public_key_bundle: None,
            added_at: current_timestamp(),
            last_message_at: None,
        };
        self.storage.save_contact(&stored).await?;

        Ok(())
    }

    // === Очистка ===

    /// Очистить все данные
    pub async fn clear_all_data(&mut self) -> Result<()> {
        // Очистить кеши
        self.message_cache.clear();
        self.conversations_manager.clear_all();
        self.contact_manager.clear_all();

        // Очистить хранилище
        self.storage.clear_all().await?;

        // Сбросить состояние
        self.user_id = None;
        self.username = None;
        self.active_conversation = None;

        Ok(())
    }
}

#[cfg(not(target_arch = "wasm32"))]
impl<P: CryptoProvider> AppState<P, MemoryStorage> {
    /// Создать новое состояние приложения для тестов (non-WASM)
    ///
    /// # Параметры
    /// - `server_url`: URL сервера для REST API
    pub fn new_test(server_url: String) -> Result<Self> {
        let storage = Arc::new(MemoryStorage::new());

        let rest_client = Arc::new(RestClient::new(server_url.clone()));

        use crate::auth::TokenManagerBuilder;
        let token_manager = Arc::new(
            TokenManagerBuilder::new()
                .rest_client(rest_client.clone())
                .storage(storage.clone())
                .build()?,
        );

        let crypto_manager = CryptoCore::<P>::new()?;

        Ok(Self {
            user_id: None,
            username: None,
            crypto_manager,
            contact_manager: ContactManager::new(),
            conversations_manager: ConversationsManager::new(),
            storage,
            rest_client,
            token_manager,
            long_polling_manager: None,
            server_url: Some(server_url),
            polling_active: Arc::new(AtomicBool::new(false)),
            message_cache: HashMap::new(),
            active_conversation: None,
            ui_state: UiState::new(),
            _phantom: PhantomData,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::suites::classic::ClassicSuiteProvider;

    #[test]
    #[cfg(not(target_arch = "wasm32"))]
    fn test_app_state_creation() {
        let state = AppState::<ClassicSuiteProvider, MemoryStorage>::new_test(
            "http://localhost:8080".to_string(),
        );
        assert!(state.is_ok());

        let state = state.unwrap();
        assert!(state.get_user_id().is_none());
    }

    // TODO: Add async test for add_contact once async runtime is set up in tests
    // #[test]
    // #[cfg(not(target_arch = "wasm32"))]
    // fn test_app_state_contacts() {
    //     let mut state = AppState::<ClassicSuiteProvider, MemoryStorage>::new_test(
    //         "http://localhost:8080".to_string(),
    //     )
    //     .unwrap();
    //
    //     // Need async runtime to test add_contact
    //     // state.add_contact("contact1".to_string(), "bob".to_string()).await.unwrap();
    //     // let contacts = state.get_contacts();
    //     // assert_eq!(contacts.len(), 1);
    //     // assert_eq!(contacts[0].username, "bob");
    // }
}
