// IndexedDB хранилище для WASM

use crate::storage::models::*;
use crate::utils::error::{ConstructError, Result};

#[cfg(target_arch = "wasm32")]
use wasm_bindgen::prelude::*;
#[cfg(target_arch = "wasm32")]
use wasm_bindgen::JsCast;
#[cfg(target_arch = "wasm32")]
use wasm_bindgen_futures::JsFuture;
#[cfg(target_arch = "wasm32")]
use web_sys::{IdbDatabase, IdbRequest};

// Импортируем базовые операции
#[cfg(target_arch = "wasm32")]
use super::indexeddb_ops as ops;

pub struct IndexedDbStorage {
    #[cfg(target_arch = "wasm32")]
    pub(super) db: Option<IdbDatabase>,
}

impl IndexedDbStorage {
    pub fn new() -> Self {
        Self {
            #[cfg(target_arch = "wasm32")]
            db: None,
        }
    }

    /// Инициализировать базу данных
    #[cfg(target_arch = "wasm32")]
    pub async fn init(&mut self) -> Result<()> {
        let window = web_sys::window()
            .ok_or_else(|| ConstructError::StorageError("No window object".to_string()))?;

        let idb = window
            .indexed_db()
            .map_err(|e| ConstructError::StorageError(format!("IndexedDB not available: {:?}", e)))?
            .ok_or_else(|| ConstructError::StorageError("IndexedDB not supported".to_string()))?;

        // Открыть или создать БД (версия 2 для новых object stores)
        let open_request = idb
            .open_with_u32("construct_messenger", 2)
            .map_err(|e| ConstructError::StorageError(format!("Failed to open DB: {:?}", e)))?;

        let onupgradeneeded =
            Closure::wrap(Box::new(move |event: web_sys::IdbVersionChangeEvent| {
                let target = event.target().expect("Event should have target");
                let request: IdbRequest = target.dyn_into().expect("Target should be IdbRequest");
                let db: IdbDatabase = request.result().unwrap().dyn_into().unwrap();

                // Вспомогательная функция для безопасного создания object store
                // В IndexedDB, если store уже существует, create_object_store выбросит ошибку,
                // которую мы игнорируем (стандартный подход для миграций)
                let create_store_safe = |db: &IdbDatabase, name: &str, key_path: &str| -> Option<web_sys::IdbObjectStore> {
                    // Проверить существование через список имен
                    if db.object_store_names().contains(name) {
                        return None;
                    }
                    
                    let mut params = web_sys::IdbObjectStoreParameters::new();
                    params.set_key_path(&JsValue::from_str(key_path));
                    db.create_object_store_with_optional_parameters(name, &params).ok()
                };

                // Создать object stores (игнорируем ошибки если уже существуют)
                // Это безопасно - IndexedDB выбросит ошибку только если store уже существует

                // Secure storage stores
                if let Some(_store) = create_store_safe(&db, "private_keys", "user_id") {
                    // Store создан успешно
                }

                if let Some(store) = create_store_safe(&db, "sessions", "session_id") {
                    // Создать индекс по contact_id
                    let _ = store.create_index_with_str("contact_id", "contact_id");
                }

                if let Some(_store) = create_store_safe(&db, "contacts", "id") {
                    // Store создан
                }

                if let Some(store) = create_store_safe(&db, "messages", "id") {
                    // Создать индексы для поиска
                    let _ = store.create_index_with_str("conversation_id", "conversation_id");
                    let _ = store.create_index_with_str("timestamp", "timestamp");
                }

                if let Some(_store) = create_store_safe(&db, "metadata", "user_id") {
                    // Store создан
                }

                // Новые object stores для REST API (добавлены в версии 2)
                if let Some(_store) = create_store_safe(&db, "auth_tokens", "user_id") {
                    // Store создан
                }

                if let Some(_store) = create_store_safe(&db, "conversations", "id") {
                    // Store создан
                }
            }) as Box<dyn FnMut(_)>);

        open_request.set_onupgradeneeded(Some(onupgradeneeded.as_ref().unchecked_ref()));
        onupgradeneeded.forget();

        // Дождаться открытия БД
        let db_promise = ops::idb_open_request_to_promise(&open_request);
        let db_value = JsFuture::from(db_promise).await.map_err(|e| {
            ConstructError::StorageError(format!("Failed to open database: {:?}", e))
        })?;

        let db: IdbDatabase = db_value
            .dyn_into()
            .map_err(|_| ConstructError::StorageError("Invalid database object".to_string()))?;

        self.db = Some(db);
        Ok(())
    }

    /// Инициализировать базу данных (non-WASM заглушка)
    #[cfg(not(target_arch = "wasm32"))]
    pub async fn init(&mut self) -> Result<()> {
        Ok(())
    }

    // === Вспомогательные методы ===

    #[cfg(target_arch = "wasm32")]
    pub(crate) fn get_db(&self) -> Result<&IdbDatabase> {
        self.db
            .as_ref()
            .ok_or_else(|| ConstructError::StorageError("Database not initialized".to_string()))
    }

    // === Приватные ключи ===

    #[cfg(target_arch = "wasm32")]
    pub async fn save_private_keys(&self, keys: StoredPrivateKeys) -> Result<()> {
        let db = self.get_db()?;
        ops::put_typed(db, "private_keys", &keys).await
    }

    #[cfg(not(target_arch = "wasm32"))]
    pub async fn save_private_keys(&self, _keys: StoredPrivateKeys) -> Result<()> {
        Err(ConstructError::StorageError(
            "IndexedDB only available in WASM".to_string(),
        ))
    }

    #[cfg(target_arch = "wasm32")]
    pub async fn load_private_keys(&self, user_id: &str) -> Result<Option<StoredPrivateKeys>> {
        let db = self.get_db()?;
        ops::get_typed(db, "private_keys", user_id).await
    }

    #[cfg(not(target_arch = "wasm32"))]
    pub async fn load_private_keys(&self, _user_id: &str) -> Result<Option<StoredPrivateKeys>> {
        Ok(None)
    }

    // === Сессии ===

    #[cfg(target_arch = "wasm32")]
    pub async fn save_session(&self, session: StoredSession) -> Result<()> {
        let db = self.get_db()?;
        ops::put_typed(db, "sessions", &session).await
    }

    #[cfg(not(target_arch = "wasm32"))]
    pub async fn save_session(&self, _session: StoredSession) -> Result<()> {
        Err(ConstructError::StorageError(
            "IndexedDB only available in WASM".to_string(),
        ))
    }

    #[cfg(target_arch = "wasm32")]
    pub async fn load_session(&self, session_id: &str) -> Result<Option<StoredSession>> {
        let db = self.get_db()?;
        ops::get_typed(db, "sessions", session_id).await
    }

    #[cfg(not(target_arch = "wasm32"))]
    pub async fn load_session(&self, _session_id: &str) -> Result<Option<StoredSession>> {
        Ok(None)
    }

    #[cfg(target_arch = "wasm32")]
    pub async fn load_all_sessions(&self) -> Result<Vec<StoredSession>> {
        let db = self.get_db()?;
        ops::get_all_typed(db, "sessions").await
    }

    #[cfg(not(target_arch = "wasm32"))]
    pub async fn load_all_sessions(&self) -> Result<Vec<StoredSession>> {
        Ok(Vec::new())
    }

    #[cfg(target_arch = "wasm32")]
    pub async fn delete_session(&self, session_id: &str) -> Result<()> {
        let db = self.get_db()?;
        ops::delete_by_key(db, "sessions", session_id).await
    }

    #[cfg(not(target_arch = "wasm32"))]
    pub async fn delete_session(&self, _session_id: &str) -> Result<()> {
        Ok(())
    }

    // === Контакты ===

    #[cfg(target_arch = "wasm32")]
    pub async fn save_contact(&self, contact: StoredContact) -> Result<()> {
        let db = self.get_db()?;
        ops::put_typed(db, "contacts", &contact).await
    }

    #[cfg(not(target_arch = "wasm32"))]
    pub async fn save_contact(&self, _contact: StoredContact) -> Result<()> {
        Err(ConstructError::StorageError(
            "IndexedDB only available in WASM".to_string(),
        ))
    }

    #[cfg(target_arch = "wasm32")]
    pub async fn load_all_contacts(&self) -> Result<Vec<StoredContact>> {
        let db = self.get_db()?;
        ops::get_all_typed(db, "contacts").await
    }

    #[cfg(not(target_arch = "wasm32"))]
    pub async fn load_all_contacts(&self) -> Result<Vec<StoredContact>> {
        Ok(Vec::new())
    }

    #[cfg(target_arch = "wasm32")]
    pub async fn load_contact(&self, contact_id: &str) -> Result<Option<StoredContact>> {
        let db = self.get_db()?;
        ops::get_typed(db, "contacts", contact_id).await
    }

    #[cfg(not(target_arch = "wasm32"))]
    pub async fn load_contact(&self, _contact_id: &str) -> Result<Option<StoredContact>> {
        Ok(None)
    }

    #[cfg(target_arch = "wasm32")]
    pub async fn delete_contact(&self, contact_id: &str) -> Result<()> {
        let db = self.get_db()?;
        ops::delete_by_key(db, "contacts", contact_id).await
    }

    #[cfg(not(target_arch = "wasm32"))]
    pub async fn delete_contact(&self, _contact_id: &str) -> Result<()> {
        Ok(())
    }

    // === Сообщения ===

    #[cfg(target_arch = "wasm32")]
    pub async fn save_message(&self, msg: StoredMessage) -> Result<()> {
        let db = self.get_db()?;
        ops::put_typed(db, "messages", &msg).await
    }

    #[cfg(not(target_arch = "wasm32"))]
    pub async fn save_message(&self, _msg: StoredMessage) -> Result<()> {
        Err(ConstructError::StorageError(
            "IndexedDB only available in WASM".to_string(),
        ))
    }

    #[cfg(target_arch = "wasm32")]
    pub async fn load_messages_for_conversation(
        &self,
        conversation_id: &str,
        limit: usize,
        offset: usize,
    ) -> Result<Vec<StoredMessage>> {
        let db = self.get_db()?;

        let mut messages: Vec<StoredMessage> =
            ops::get_all_typed_by_index(db, "messages", "conversation_id", conversation_id).await?;

        // Сортировать по timestamp
        messages.sort_by_key(|m| m.timestamp);

        // Применить offset и limit
        let messages: Vec<StoredMessage> = messages.into_iter().skip(offset).take(limit).collect();

        Ok(messages)
    }

    #[cfg(not(target_arch = "wasm32"))]
    pub async fn load_messages_for_conversation(
        &self,
        _conversation_id: &str,
        _limit: usize,
        _offset: usize,
    ) -> Result<Vec<StoredMessage>> {
        Ok(Vec::new())
    }

    #[cfg(target_arch = "wasm32")]
    pub async fn load_message(&self, message_id: &str) -> Result<Option<StoredMessage>> {
        let db = self.get_db()?;
        ops::get_typed(db, "messages", message_id).await
    }

    #[cfg(not(target_arch = "wasm32"))]
    pub async fn load_message(&self, _message_id: &str) -> Result<Option<StoredMessage>> {
        Ok(None)
    }

    #[cfg(target_arch = "wasm32")]
    pub async fn delete_message(&self, message_id: &str) -> Result<()> {
        let db = self.get_db()?;
        ops::delete_by_key(db, "messages", message_id).await
    }

    #[cfg(not(target_arch = "wasm32"))]
    pub async fn delete_message(&self, _message_id: &str) -> Result<()> {
        Ok(())
    }

    // === Метаданные ===

    #[cfg(target_arch = "wasm32")]
    pub async fn save_metadata(&self, metadata: StoredAppMetadata) -> Result<()> {
        let db = self.get_db()?;
        ops::put_typed(db, "metadata", &metadata).await
    }

    #[cfg(not(target_arch = "wasm32"))]
    pub async fn save_metadata(&self, _metadata: StoredAppMetadata) -> Result<()> {
        Err(ConstructError::StorageError(
            "IndexedDB only available in WASM".to_string(),
        ))
    }

    #[cfg(target_arch = "wasm32")]
    pub async fn load_metadata(&self, user_id: &str) -> Result<Option<StoredAppMetadata>> {
        let db = self.get_db()?;
        ops::get_typed(db, "metadata", user_id).await
    }

    #[cfg(not(target_arch = "wasm32"))]
    pub async fn load_metadata(&self, _user_id: &str) -> Result<Option<StoredAppMetadata>> {
        Ok(None)
    }

    /// Очистить все данные (WASM версия)
    ///
    /// Этот метод удаляет все данные из всех object stores.
    /// Используется при logout или для полного сброса данных.
    #[cfg(target_arch = "wasm32")]
    pub async fn clear_all(&mut self) -> Result<()> {
        // Используем реализацию из DataStorage trait
        // которая очищает все данные включая secure storage
        use super::traits::DataStorage;
        DataStorage::clear_all(self).await
    }

    /// Очистить все данные (non-WASM заглушка)
    #[cfg(not(target_arch = "wasm32"))]
    pub async fn clear_all(&mut self) -> Result<()> {
        Ok(())
    }
}

impl Default for IndexedDbStorage {
    fn default() -> Self {
        Self::new()
    }
}

// Для совместимости с существующим кодом
pub type KeyStorage = IndexedDbStorage;
