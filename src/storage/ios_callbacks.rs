// iOS Storage Callbacks
//
// Этот модуль определяет callback интерфейсы для интеграции с iOS Keychain
// и нативным хранилищем. iOS клиент должен предоставить реализации этих
// callbacks для операций с Keychain и Core Data/UserDefaults.

use crate::utils::error::Result;
use std::sync::Arc;

/// Callback интерфейс для secure storage (Keychain)
/// iOS клиент должен предоставить реализацию через Swift
#[cfg_attr(feature = "uniffi", uniffi::export(with_foreign))]
pub trait SecureStorageCallback: Send + Sync {
    /// Сохранить токены авторизации в Keychain
    fn save_auth_tokens(&self, user_id: String, tokens_json: String) -> Result<()>;

    /// Загрузить токены авторизации из Keychain
    fn load_auth_tokens(&self, user_id: String) -> Result<Option<String>>;

    /// Удалить токены авторизации из Keychain
    fn delete_auth_tokens(&self, user_id: String) -> Result<()>;

    /// Сохранить приватные ключи в Keychain
    fn save_private_keys(&self, user_id: String, keys_json: String) -> Result<()>;

    /// Загрузить приватные ключи из Keychain
    fn load_private_keys(&self, user_id: String) -> Result<Option<String>>;

    /// Удалить приватные ключи из Keychain
    fn delete_private_keys(&self, user_id: String) -> Result<()>;

    /// Сохранить сессию в Keychain
    fn save_session(&self, session_id: String, session_json: String) -> Result<()>;

    /// Загрузить сессию из Keychain
    fn load_session(&self, session_id: String) -> Result<Option<String>>;

    /// Загрузить все сессии для контакта
    fn load_sessions_by_contact(&self, contact_id: String) -> Result<Vec<String>>;

    /// Удалить сессию из Keychain
    fn delete_session(&self, session_id: String) -> Result<()>;

    /// Очистить все secure данные
    fn clear_all_secure_data(&self) -> Result<()>;
}

/// Callback интерфейс для data storage (Core Data/UserDefaults)
/// iOS клиент должен предоставить реализацию через Swift
#[cfg_attr(feature = "uniffi", uniffi::export(with_foreign))]
pub trait DataStorageCallback: Send + Sync {
    /// Сохранить сообщение
    fn save_message(&self, message_json: String) -> Result<()>;

    /// Загрузить сообщение по ID
    fn load_message(&self, message_id: String) -> Result<Option<String>>;

    /// Загрузить сообщения для разговора
    fn load_messages(
        &self,
        conversation_id: String,
        limit: u32,
        offset: u32,
    ) -> Result<Vec<String>>;

    /// Удалить сообщение
    fn delete_message(&self, message_id: String) -> Result<()>;

    /// Удалить все сообщения в разговоре
    fn delete_messages_in_conversation(&self, conversation_id: String) -> Result<()>;

    /// Подсчитать количество сообщений
    fn count_messages(&self, conversation_id: String) -> Result<u32>;

    /// Сохранить контакт
    fn save_contact(&self, contact_json: String) -> Result<()>;

    /// Загрузить контакт по ID
    fn load_contact(&self, contact_id: String) -> Result<Option<String>>;

    /// Загрузить все контакты
    fn load_contacts(&self) -> Result<Vec<String>>;

    /// Удалить контакт
    fn delete_contact(&self, contact_id: String) -> Result<()>;

    /// Сохранить разговор
    fn save_conversation(&self, conversation_json: String) -> Result<()>;

    /// Загрузить разговор по ID
    fn load_conversation(&self, conversation_id: String) -> Result<Option<String>>;

    /// Загрузить все разговоры
    fn load_conversations(&self) -> Result<Vec<String>>;

    /// Удалить разговор
    fn delete_conversation(&self, conversation_id: String) -> Result<()>;

    /// Сохранить метаданные приложения
    fn save_metadata(&self, user_id: String, metadata_json: String) -> Result<()>;

    /// Загрузить метаданные приложения
    fn load_metadata(&self, user_id: String) -> Result<Option<String>>;

    /// Очистить все данные
    fn clear_all_data(&self) -> Result<()>;
}

/// Адаптер для iOS storage, использующий callbacks
pub struct IOSStorageAdapter {
    user_id: String,
    secure_callback: Arc<dyn SecureStorageCallback>,
    data_callback: Arc<dyn DataStorageCallback>,
}

impl IOSStorageAdapter {
    /// Создать новый iOS storage адаптер
    pub fn new(
        user_id: String,
        secure_callback: Arc<dyn SecureStorageCallback>,
        data_callback: Arc<dyn DataStorageCallback>,
    ) -> Self {
        Self {
            user_id,
            secure_callback,
            data_callback,
        }
    }

    /// Получить user ID
    pub(crate) fn user_id(&self) -> &str {
        &self.user_id
    }

    /// Получить secure callback
    pub(crate) fn secure_callback(&self) -> &Arc<dyn SecureStorageCallback> {
        &self.secure_callback
    }

    /// Получить data callback
    pub(crate) fn data_callback(&self) -> &Arc<dyn DataStorageCallback> {
        &self.data_callback
    }
}

// Вспомогательные функции для сериализации/десериализации

/// Сериализовать значение в JSON строку
pub(crate) fn serialize_to_json<T: serde::Serialize>(value: &T) -> Result<String> {
    serde_json::to_string(value).map_err(|e| {
        crate::utils::error::ConstructError::SerializationError(format!(
            "Failed to serialize to JSON: {:?}",
            e
        ))
    })
}

/// Десериализовать JSON строку в значение
pub(crate) fn deserialize_from_json<T: serde::de::DeserializeOwned>(json: &str) -> Result<T> {
    serde_json::from_str(json).map_err(|e| {
        crate::utils::error::ConstructError::SerializationError(format!(
            "Failed to deserialize from JSON: {:?}",
            e
        ))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_serialize_deserialize() {
        use crate::storage::models::MessageStatus;

        let status = MessageStatus::Sent;
        let json = serialize_to_json(&status).unwrap();
        let deserialized: MessageStatus = deserialize_from_json(&json).unwrap();

        assert_eq!(status, deserialized);
    }
}
