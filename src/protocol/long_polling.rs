// Long Polling Manager для получения сообщений от сервера
//
// Реализует long polling loop для получения сообщений в реальном времени:
// - Автоматическая переподключение при ошибках
// - Exponential backoff при сбоях
// - Graceful shutdown
// - Интеграция с TokenManager для аутентификации

use crate::auth::TokenManager;
use crate::protocol::rest_transport::{RequestOptions, RestClient};
use crate::storage::traits::SecureStorage;
use crate::utils::error::{ConstructError, Result};
use serde::{Deserialize, Serialize};
use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

#[cfg(not(target_arch = "wasm32"))]
use std::time::Duration;

// ============================================================================
// Response Models
// ============================================================================

/// Response от сервера с сообщениями
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PollMessagesResponse {
    /// Массив сообщений
    pub messages: Vec<EncryptedMessage>,

    /// ID последнего сообщения (для следующего запроса)
    #[serde(rename = "lastId")]
    pub last_id: Option<String>,
}

/// Зашифрованное сообщение от сервера
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptedMessage {
    /// ID сообщения (UUID)
    pub id: String,

    /// ID отправителя (UUID)
    #[serde(rename = "senderId")]
    pub sender_id: String,

    /// ID получателя (UUID)
    #[serde(rename = "recipientId")]
    pub recipient_id: String,

    /// Зашифрованное содержимое (Base64)
    pub content: String,

    /// Unix timestamp создания (миллисекунды)
    pub timestamp: i64,
}

// ============================================================================
// Long Polling Manager
// ============================================================================

/// Callback для обработки входящих сообщений
pub trait MessageHandler: Send + Sync {
    /// Обработать входящее сообщение
    ///
    /// # Parameters
    /// - `message`: Зашифрованное сообщение от сервера
    ///
    /// # Returns
    /// - `Ok(())` если сообщение успешно обработано
    /// - `Err(...)` если произошла ошибка
    ///
    /// Примечание: Ошибки в обработке НЕ останавливают polling loop
    fn handle_message(
        &self,
        message: EncryptedMessage,
    ) -> Pin<Box<dyn Future<Output = Result<()>> + Send>>;
}

/// Long Polling Manager
pub struct LongPollingManager<S: SecureStorage> {
    /// REST клиент
    rest_client: Arc<RestClient>,

    /// Token Manager для аутентификации
    token_manager: Arc<TokenManager<S>>,

    /// Обработчик сообщений
    message_handler: Arc<dyn MessageHandler>,

    /// Флаг для остановки polling
    running: Arc<AtomicBool>,

    /// ID последнего полученного сообщения
    last_message_id: Arc<std::sync::Mutex<Option<String>>>,

    /// Таймаут для long polling запроса (секунды)
    poll_timeout_secs: u64,

    /// Минимальная задержка между попытками (миллисекунды)
    min_retry_delay_ms: u64,

    /// Максимальная задержка между попытками (миллисекунды)
    max_retry_delay_ms: u64,
}

impl<S: SecureStorage> LongPollingManager<S> {
    /// Создать новый Long Polling Manager
    ///
    /// # Parameters
    /// - `rest_client`: REST клиент для запросов
    /// - `token_manager`: Token Manager для получения access token
    /// - `message_handler`: Callback для обработки входящих сообщений
    pub fn new(
        rest_client: Arc<RestClient>,
        token_manager: Arc<TokenManager<S>>,
        message_handler: Arc<dyn MessageHandler>,
    ) -> Self {
        Self {
            rest_client,
            token_manager,
            message_handler,
            running: Arc::new(AtomicBool::new(false)),
            last_message_id: Arc::new(std::sync::Mutex::new(None)),
            poll_timeout_secs: 30, // 30 секунд long polling timeout
            min_retry_delay_ms: 1000, // 1 секунда
            max_retry_delay_ms: 30000, // 30 секунд
        }
    }

    /// Настроить таймауты
    pub fn with_timeouts(
        mut self,
        poll_timeout_secs: u64,
        min_retry_delay_ms: u64,
        max_retry_delay_ms: u64,
    ) -> Self {
        self.poll_timeout_secs = poll_timeout_secs;
        self.min_retry_delay_ms = min_retry_delay_ms;
        self.max_retry_delay_ms = max_retry_delay_ms;
        self
    }

    /// Запустить polling loop
    ///
    /// Этот метод запускает бесконечный цикл long polling.
    /// Используйте `stop()` для остановки.
    pub async fn start(&self) -> Result<()> {
        // Проверить что не запущен уже
        if self.running.load(Ordering::SeqCst) {
            return Err(ConstructError::ValidationError(
                "Long polling already running".to_string(),
            ));
        }

        self.running.store(true, Ordering::SeqCst);

        // Счётчик ошибок для exponential backoff
        let mut consecutive_errors = 0u32;

        while self.running.load(Ordering::SeqCst) {
            // Получить валидный токен
            let access_token = match self.token_manager.get_valid_token().await {
                Ok(token) => token,
                Err(e) => {
                    // Ошибка аутентификации - остановить polling
                    tracing::error!("Failed to get access token: {:?}", e);
                    self.running.store(false, Ordering::SeqCst);
                    return Err(e);
                }
            };

            // Получить last_message_id
            let since_id = {
                let lock = self.last_message_id.lock().unwrap();
                lock.clone()
            };

            // Выполнить long polling запрос
            let options = RequestOptions {
                access_token: Some(access_token),
                csrf_token: None,
                request_signature: None,
            };

            match self
                .rest_client
                .poll_messages::<PollMessagesResponse>(since_id.clone(), options)
                .await
            {
                Ok(response) => {
                    // Сбросить счётчик ошибок
                    consecutive_errors = 0;

                    // Обновить last_message_id
                    if let Some(ref last_id) = response.last_id {
                        let mut lock = self.last_message_id.lock().unwrap();
                        *lock = Some(last_id.clone());
                    }

                    // Обработать сообщения
                    for message in response.messages {
                        if let Err(e) = self.message_handler.handle_message(message).await {
                            tracing::warn!("Failed to handle message: {:?}", e);
                            // Продолжаем обработку остальных сообщений
                        }
                    }
                }
                Err(e) => {
                    // Ошибка запроса - exponential backoff
                    consecutive_errors += 1;

                    tracing::warn!(
                        "Long polling error (attempt {}): {:?}",
                        consecutive_errors,
                        e
                    );

                    // Вычислить задержку: min_delay * 2^errors, но не более max_delay
                    let delay_ms = self
                        .min_retry_delay_ms
                        .saturating_mul(2u64.saturating_pow(consecutive_errors))
                        .min(self.max_retry_delay_ms);

                    tracing::info!("Retrying in {} ms", delay_ms);

                    // Подождать перед повтором
                    #[cfg(target_arch = "wasm32")]
                    {
                        // В WASM используем web_sys setTimeout через Promise
                        use wasm_bindgen_futures::JsFuture;
                        use web_sys::window;

                        if let Some(win) = window() {
                            let promise = js_sys::Promise::new(&mut |resolve, _| {
                                let _ = win.set_timeout_with_callback_and_timeout_and_arguments_0(
                                    &resolve,
                                    delay_ms as i32,
                                );
                            });
                            let _ = JsFuture::from(promise).await;
                        }
                    }

                    #[cfg(not(target_arch = "wasm32"))]
                    {
                        // Для non-WASM используем простой std::thread::sleep
                        std::thread::sleep(Duration::from_millis(delay_ms));
                    }
                }
            }
        }

        Ok(())
    }

    /// Остановить polling loop
    pub fn stop(&self) {
        self.running.store(false, Ordering::SeqCst);
    }

    /// Проверить запущен ли polling
    pub fn is_running(&self) -> bool {
        self.running.load(Ordering::SeqCst)
    }

    /// Сбросить last_message_id (например, после logout)
    pub fn reset(&self) {
        let mut lock = self.last_message_id.lock().unwrap();
        *lock = None;
    }
}

// ============================================================================
// Builder
// ============================================================================

pub struct LongPollingManagerBuilder<S: SecureStorage> {
    rest_client: Option<Arc<RestClient>>,
    token_manager: Option<Arc<TokenManager<S>>>,
    message_handler: Option<Arc<dyn MessageHandler>>,
    poll_timeout_secs: u64,
    min_retry_delay_ms: u64,
    max_retry_delay_ms: u64,
}

impl<S: SecureStorage> LongPollingManagerBuilder<S> {
    pub fn new() -> Self {
        Self {
            rest_client: None,
            token_manager: None,
            message_handler: None,
            poll_timeout_secs: 30,
            min_retry_delay_ms: 1000,
            max_retry_delay_ms: 30000,
        }
    }

    pub fn rest_client(mut self, client: Arc<RestClient>) -> Self {
        self.rest_client = Some(client);
        self
    }

    pub fn token_manager(mut self, manager: Arc<TokenManager<S>>) -> Self {
        self.token_manager = Some(manager);
        self
    }

    pub fn message_handler(mut self, handler: Arc<dyn MessageHandler>) -> Self {
        self.message_handler = Some(handler);
        self
    }

    pub fn poll_timeout_secs(mut self, timeout: u64) -> Self {
        self.poll_timeout_secs = timeout;
        self
    }

    pub fn retry_delays(mut self, min_ms: u64, max_ms: u64) -> Self {
        self.min_retry_delay_ms = min_ms;
        self.max_retry_delay_ms = max_ms;
        self
    }

    pub fn build(self) -> Result<LongPollingManager<S>> {
        let rest_client = self.rest_client.ok_or_else(|| {
            ConstructError::InvalidInput("REST client is required".to_string())
        })?;
        let token_manager = self.token_manager.ok_or_else(|| {
            ConstructError::InvalidInput("Token manager is required".to_string())
        })?;
        let message_handler = self.message_handler.ok_or_else(|| {
            ConstructError::InvalidInput("Message handler is required".to_string())
        })?;

        Ok(LongPollingManager {
            rest_client,
            token_manager,
            message_handler,
            running: Arc::new(AtomicBool::new(false)),
            last_message_id: Arc::new(std::sync::Mutex::new(None)),
            poll_timeout_secs: self.poll_timeout_secs,
            min_retry_delay_ms: self.min_retry_delay_ms,
            max_retry_delay_ms: self.max_retry_delay_ms,
        })
    }
}

impl<S: SecureStorage> Default for LongPollingManagerBuilder<S> {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Тестовый MessageHandler
    struct TestMessageHandler;

    impl MessageHandler for TestMessageHandler {
        fn handle_message(
            &self,
            _message: EncryptedMessage,
        ) -> Pin<Box<dyn Future<Output = Result<()>> + Send>> {
            Box::pin(async { Ok(()) })
        }
    }

    #[test]
    fn test_poll_response_serialization() {
        let json = r#"{
            "messages": [
                {
                    "id": "msg1",
                    "senderId": "user1",
                    "recipientId": "user2",
                    "content": "encrypted_content",
                    "timestamp": 1705320000000
                }
            ],
            "lastId": "msg1"
        }"#;

        let response: PollMessagesResponse = serde_json::from_str(json).unwrap();
        assert_eq!(response.messages.len(), 1);
        assert_eq!(response.last_id, Some("msg1".to_string()));
    }

    #[test]
    fn test_exponential_backoff_calculation() {
        let min_delay = 1000u64;
        let max_delay = 30000u64;

        // 1 ошибка: 1000 * 2^1 = 2000ms
        let delay_1 = min_delay.saturating_mul(2u64.pow(1)).min(max_delay);
        assert_eq!(delay_1, 2000);

        // 3 ошибки: 1000 * 2^3 = 8000ms
        let delay_3 = min_delay.saturating_mul(2u64.pow(3)).min(max_delay);
        assert_eq!(delay_3, 8000);

        // 10 ошибок: 1000 * 2^10 = 1024000ms, но max 30000ms
        let delay_10 = min_delay.saturating_mul(2u64.pow(10)).min(max_delay);
        assert_eq!(delay_10, 30000);
    }
}
