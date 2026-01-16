// Реализация Storage traits для IndexedDbStorage
//
// Этот модуль добавляет поддержку новых SecureStorage и DataStorage traits
// для существующего IndexedDbStorage.

use super::indexeddb::IndexedDbStorage;
use super::models::*;
use super::traits::{AuthTokens, DataStorage, SecureStorage};
use crate::utils::error::{ConstructError, Result};

#[cfg(target_arch = "wasm32")]
use super::indexeddb_ops as ops;

// ============================================================================
// SecureStorage Implementation
// ============================================================================

impl SecureStorage for IndexedDbStorage {
    /// Сохранить токены аутентификации
    async fn save_auth_tokens(&self, tokens: &AuthTokens) -> Result<()> {
        #[cfg(target_arch = "wasm32")]
        {
            let db = self.db.as_ref().ok_or_else(|| {
                ConstructError::StorageError("Database not initialized".to_string())
            })?;

            // Object store uses user_id as keyPath, extracted automatically from tokens
            ops::put_typed(db, "auth_tokens", tokens).await
        }

        #[cfg(not(target_arch = "wasm32"))]
        {
            let _ = tokens;
            Err(ConstructError::StorageError(
                "IndexedDB only available in WASM".to_string(),
            ))
        }
    }

    /// Загрузить токены аутентификации
    ///
    /// # Single-User Scenario
    /// В текущей реализации приложение поддерживает только одного пользователя на устройстве.
    /// Метод загружает все токены из хранилища и возвращает первый найденный.
    /// Object store использует `user_id` как keyPath.
    async fn load_auth_tokens(&self) -> Result<Option<AuthTokens>> {
        #[cfg(target_arch = "wasm32")]
        {
            let db = self.db.as_ref().ok_or_else(|| {
                ConstructError::StorageError("Database not initialized".to_string())
            })?;

            // Get all tokens and return the first one (single user scenario)
            // В будущем можно оптимизировать если будет известен user_id
            let all_tokens: Vec<AuthTokens> = ops::get_all_typed(db, "auth_tokens").await?;

            // Для single-user приложения должен быть только один набор токенов
            if all_tokens.len() > 1 {
                // Логируем предупреждение если найдено несколько токенов (не должно быть)
                #[cfg(target_arch = "wasm32")]
                web_sys::console::warn_1(
                    &format!(
                        "Found {} auth token sets, expected only 1 (single-user scenario)",
                        all_tokens.len()
                    )
                    .into(),
                );
            }

            Ok(all_tokens.into_iter().next())
        }

        #[cfg(not(target_arch = "wasm32"))]
        {
            Ok(None)
        }
    }

    /// Очистить токены аутентификации
    async fn clear_auth_tokens(&self) -> Result<()> {
        #[cfg(target_arch = "wasm32")]
        {
            let db = self.db.as_ref().ok_or_else(|| {
                ConstructError::StorageError("Database not initialized".to_string())
            })?;

            // Load to get the user_id, then delete by key
            if let Some(tokens) = SecureStorage::load_auth_tokens(self).await? {
                ops::delete_by_key(db, "auth_tokens", &tokens.user_id).await?;
            }
            Ok(())
        }

        #[cfg(not(target_arch = "wasm32"))]
        {
            Ok(())
        }
    }

    /// Сохранить приватные ключи
    async fn save_private_keys(&self, keys: &StoredPrivateKeys) -> Result<()> {
        #[cfg(target_arch = "wasm32")]
        {
            let db = self.db.as_ref().ok_or_else(|| {
                ConstructError::StorageError("Database not initialized".to_string())
            })?;

            // Object store uses user_id as keyPath, extracted automatically from keys
            ops::put_typed(db, "private_keys", keys).await
        }

        #[cfg(not(target_arch = "wasm32"))]
        {
            let _ = keys;
            Err(ConstructError::StorageError(
                "IndexedDB only available in WASM".to_string(),
            ))
        }
    }

    /// Загрузить приватные ключи
    async fn load_private_keys(&self) -> Result<Option<StoredPrivateKeys>> {
        #[cfg(target_arch = "wasm32")]
        {
            let db = self.db.as_ref().ok_or_else(|| {
                ConstructError::StorageError("Database not initialized".to_string())
            })?;

            // Get all keys and return the first one (single user scenario)
            let all_keys: Vec<StoredPrivateKeys> = ops::get_all_typed(db, "private_keys").await?;
            Ok(all_keys.into_iter().next())
        }

        #[cfg(not(target_arch = "wasm32"))]
        {
            Ok(None)
        }
    }

    /// Очистить приватные ключи
    async fn clear_private_keys(&self) -> Result<()> {
        #[cfg(target_arch = "wasm32")]
        {
            let db = self.db.as_ref().ok_or_else(|| {
                ConstructError::StorageError("Database not initialized".to_string())
            })?;

            // Load to get the user_id, then delete by key
            if let Some(keys) = SecureStorage::load_private_keys(self).await? {
                ops::delete_by_key(db, "private_keys", &keys.user_id).await?;
            }
            Ok(())
        }

        #[cfg(not(target_arch = "wasm32"))]
        {
            Ok(())
        }
    }

    /// Сохранить сессию для контакта
    async fn save_session(&self, _contact_id: &str, session: &StoredSession) -> Result<()> {
        #[cfg(target_arch = "wasm32")]
        {
            let db = self.db.as_ref().ok_or_else(|| {
                ConstructError::StorageError("Database not initialized".to_string())
            })?;

            // Object store uses session_id as keyPath, extracted automatically from session
            // contact_id is stored as part of the session object and indexed
            ops::put_typed(db, "sessions", session).await
        }

        #[cfg(not(target_arch = "wasm32"))]
        {
            let _ = session;
            Err(ConstructError::StorageError(
                "IndexedDB only available in WASM".to_string(),
            ))
        }
    }

    /// Загрузить сессию для контакта
    async fn load_session(&self, contact_id: &str) -> Result<Option<StoredSession>> {
        #[cfg(target_arch = "wasm32")]
        {
            let db = self.db.as_ref().ok_or_else(|| {
                ConstructError::StorageError("Database not initialized".to_string())
            })?;

            // Query by contact_id index (not by session_id key)
            let sessions: Vec<StoredSession> =
                ops::get_all_typed_by_index(db, "sessions", "contact_id", contact_id).await?;
            Ok(sessions.into_iter().next())
        }

        #[cfg(not(target_arch = "wasm32"))]
        {
            let _ = contact_id;
            Ok(None)
        }
    }

    /// Удалить сессию для контакта
    async fn delete_session(&self, contact_id: &str) -> Result<()> {
        #[cfg(target_arch = "wasm32")]
        {
            let db = self.db.as_ref().ok_or_else(|| {
                ConstructError::StorageError("Database not initialized".to_string())
            })?;

            // Load session to get session_id, then delete by session_id
            if let Some(session) = self.load_session(contact_id).await? {
                ops::delete_by_key(db, "sessions", &session.session_id).await?;
            }
            Ok(())
        }

        #[cfg(not(target_arch = "wasm32"))]
        {
            let _ = contact_id;
            Ok(())
        }
    }

    /// Получить список всех contact_id с сохранёнными сессиями
    async fn list_sessions(&self) -> Result<Vec<String>> {
        #[cfg(target_arch = "wasm32")]
        {
            let db = self.db.as_ref().ok_or_else(|| {
                ConstructError::StorageError("Database not initialized".to_string())
            })?;

            let sessions: Vec<StoredSession> = ops::get_all_typed(db, "sessions").await?;
            Ok(sessions.into_iter().map(|s| s.contact_id).collect())
        }

        #[cfg(not(target_arch = "wasm32"))]
        {
            Ok(Vec::new())
        }
    }

    /// Очистить все сессии
    async fn clear_all_sessions(&self) -> Result<()> {
        #[cfg(target_arch = "wasm32")]
        {
            let db = self.db.as_ref().ok_or_else(|| {
                ConstructError::StorageError("Database not initialized".to_string())
            })?;

            // Get all sessions and delete each by session_id
            let sessions: Vec<StoredSession> = ops::get_all_typed(db, "sessions").await?;
            for session in sessions {
                ops::delete_by_key(db, "sessions", &session.session_id).await?;
            }
            Ok(())
        }

        #[cfg(not(target_arch = "wasm32"))]
        {
            Ok(())
        }
    }

    /// Сохранить метаданные приложения
    async fn save_app_metadata(&self, metadata: &StoredAppMetadata) -> Result<()> {
        #[cfg(target_arch = "wasm32")]
        {
            let db = self.db.as_ref().ok_or_else(|| {
                ConstructError::StorageError("Database not initialized".to_string())
            })?;

            // Object store uses user_id as keyPath, extracted automatically
            ops::put_typed(db, "metadata", metadata).await
        }

        #[cfg(not(target_arch = "wasm32"))]
        {
            let _ = metadata;
            Err(ConstructError::StorageError(
                "IndexedDB only available in WASM".to_string(),
            ))
        }
    }

    /// Загрузить метаданные приложения
    async fn load_app_metadata(&self) -> Result<Option<StoredAppMetadata>> {
        #[cfg(target_arch = "wasm32")]
        {
            let db = self.db.as_ref().ok_or_else(|| {
                ConstructError::StorageError("Database not initialized".to_string())
            })?;

            // Get all metadata and return the first one (single user scenario)
            let all_metadata: Vec<StoredAppMetadata> = ops::get_all_typed(db, "metadata").await?;
            Ok(all_metadata.into_iter().next())
        }

        #[cfg(not(target_arch = "wasm32"))]
        {
            Ok(None)
        }
    }
}

// ============================================================================
// DataStorage Implementation
// ============================================================================

impl DataStorage for IndexedDbStorage {
    // === Messages ===

    /// Сохранить сообщение
    async fn save_message(&self, message: &StoredMessage) -> Result<()> {
        #[cfg(target_arch = "wasm32")]
        {
            let db = self.db.as_ref().ok_or_else(|| {
                ConstructError::StorageError("Database not initialized".to_string())
            })?;

            // Object store uses id as keyPath, extracted automatically
            ops::put_typed(db, "messages", message).await
        }

        #[cfg(not(target_arch = "wasm32"))]
        {
            let _ = message;
            Err(ConstructError::StorageError(
                "IndexedDB only available in WASM".to_string(),
            ))
        }
    }

    /// Обновить статус сообщения
    async fn update_message_status(&self, message_id: &str, status: MessageStatus) -> Result<()> {
        #[cfg(target_arch = "wasm32")]
        {
            let db = self.db.as_ref().ok_or_else(|| {
                ConstructError::StorageError("Database not initialized".to_string())
            })?;

            // Load message, update status, save back
            if let Some(mut message) = self.load_message(message_id).await? {
                message.status = status;
                ops::put_typed(db, "messages", &message).await?;
            }
            Ok(())
        }

        #[cfg(not(target_arch = "wasm32"))]
        {
            let _ = (message_id, status);
            Ok(())
        }
    }

    /// Загрузить сообщения из беседы
    async fn load_messages(
        &self,
        conversation_id: &str,
        limit: usize,
        offset: usize,
    ) -> Result<Vec<StoredMessage>> {
        #[cfg(target_arch = "wasm32")]
        {
            let db = self.db.as_ref().ok_or_else(|| {
                ConstructError::StorageError("Database not initialized".to_string())
            })?;

            // Query by conversation_id index
            let mut messages: Vec<StoredMessage> =
                ops::get_all_typed_by_index(db, "messages", "conversation_id", conversation_id)
                    .await?;

            // Sort by timestamp
            messages.sort_by_key(|m| m.timestamp);

            // Apply offset and limit
            let messages: Vec<StoredMessage> =
                messages.into_iter().skip(offset).take(limit).collect();

            Ok(messages)
        }

        #[cfg(not(target_arch = "wasm32"))]
        {
            let _ = (conversation_id, limit, offset);
            Ok(Vec::new())
        }
    }

    /// Загрузить сообщение по ID
    async fn load_message(&self, message_id: &str) -> Result<Option<StoredMessage>> {
        #[cfg(target_arch = "wasm32")]
        {
            let db = self.db.as_ref().ok_or_else(|| {
                ConstructError::StorageError("Database not initialized".to_string())
            })?;

            ops::get_typed(db, "messages", message_id).await
        }

        #[cfg(not(target_arch = "wasm32"))]
        {
            let _ = message_id;
            Ok(None)
        }
    }

    /// Удалить сообщение
    async fn delete_message(&self, message_id: &str) -> Result<()> {
        #[cfg(target_arch = "wasm32")]
        {
            let db = self.db.as_ref().ok_or_else(|| {
                ConstructError::StorageError("Database not initialized".to_string())
            })?;

            ops::delete_by_key(db, "messages", message_id).await
        }

        #[cfg(not(target_arch = "wasm32"))]
        {
            let _ = message_id;
            Ok(())
        }
    }

    /// Удалить все сообщения из беседы
    async fn delete_messages_in_conversation(&self, conversation_id: &str) -> Result<()> {
        #[cfg(target_arch = "wasm32")]
        {
            let db = self.db.as_ref().ok_or_else(|| {
                ConstructError::StorageError("Database not initialized".to_string())
            })?;

            // Load all messages for conversation, then delete each
            let messages: Vec<StoredMessage> =
                ops::get_all_typed_by_index(db, "messages", "conversation_id", conversation_id)
                    .await?;

            for message in messages {
                ops::delete_by_key(db, "messages", &message.id).await?;
            }
            Ok(())
        }

        #[cfg(not(target_arch = "wasm32"))]
        {
            let _ = conversation_id;
            Ok(())
        }
    }

    /// Получить количество сообщений в беседе
    async fn count_messages(&self, conversation_id: &str) -> Result<usize> {
        #[cfg(target_arch = "wasm32")]
        {
            let db = self.db.as_ref().ok_or_else(|| {
                ConstructError::StorageError("Database not initialized".to_string())
            })?;

            let messages: Vec<StoredMessage> =
                ops::get_all_typed_by_index(db, "messages", "conversation_id", conversation_id)
                    .await?;
            Ok(messages.len())
        }

        #[cfg(not(target_arch = "wasm32"))]
        {
            let _ = conversation_id;
            Ok(0)
        }
    }

    // === Contacts ===

    /// Сохранить контакт
    async fn save_contact(&self, contact: &StoredContact) -> Result<()> {
        #[cfg(target_arch = "wasm32")]
        {
            let db = self.db.as_ref().ok_or_else(|| {
                ConstructError::StorageError("Database not initialized".to_string())
            })?;

            // Object store uses id as keyPath, extracted automatically
            ops::put_typed(db, "contacts", contact).await
        }

        #[cfg(not(target_arch = "wasm32"))]
        {
            let _ = contact;
            Err(ConstructError::StorageError(
                "IndexedDB only available in WASM".to_string(),
            ))
        }
    }

    /// Загрузить контакт по ID
    async fn load_contact(&self, contact_id: &str) -> Result<Option<StoredContact>> {
        #[cfg(target_arch = "wasm32")]
        {
            let db = self.db.as_ref().ok_or_else(|| {
                ConstructError::StorageError("Database not initialized".to_string())
            })?;

            ops::get_typed(db, "contacts", contact_id).await
        }

        #[cfg(not(target_arch = "wasm32"))]
        {
            let _ = contact_id;
            Ok(None)
        }
    }

    /// Загрузить все контакты
    async fn load_contacts(&self) -> Result<Vec<StoredContact>> {
        #[cfg(target_arch = "wasm32")]
        {
            let db = self.db.as_ref().ok_or_else(|| {
                ConstructError::StorageError("Database not initialized".to_string())
            })?;

            ops::get_all_typed(db, "contacts").await
        }

        #[cfg(not(target_arch = "wasm32"))]
        {
            Ok(Vec::new())
        }
    }

    /// Обновить время последнего сообщения контакта
    async fn update_contact_last_message(&self, contact_id: &str, timestamp: i64) -> Result<()> {
        #[cfg(target_arch = "wasm32")]
        {
            let db = self.db.as_ref().ok_or_else(|| {
                ConstructError::StorageError("Database not initialized".to_string())
            })?;

            // Load contact, update timestamp, save back
            if let Some(mut contact) = self.load_contact(contact_id).await? {
                contact.last_message_at = Some(timestamp);
                ops::put_typed(db, "contacts", &contact).await?;
            }
            Ok(())
        }

        #[cfg(not(target_arch = "wasm32"))]
        {
            let _ = (contact_id, timestamp);
            Ok(())
        }
    }

    /// Удалить контакт
    async fn delete_contact(&self, contact_id: &str) -> Result<()> {
        #[cfg(target_arch = "wasm32")]
        {
            let db = self.db.as_ref().ok_or_else(|| {
                ConstructError::StorageError("Database not initialized".to_string())
            })?;

            ops::delete_by_key(db, "contacts", contact_id).await
        }

        #[cfg(not(target_arch = "wasm32"))]
        {
            let _ = contact_id;
            Ok(())
        }
    }

    /// Сохранить беседу
    async fn save_conversation(&self, conversation: &Conversation) -> Result<()> {
        #[cfg(target_arch = "wasm32")]
        {
            let db = self.db.as_ref().ok_or_else(|| {
                ConstructError::StorageError("Database not initialized".to_string())
            })?;

            // Object store uses id as keyPath, extracted automatically
            ops::put_typed(db, "conversations", conversation).await
        }

        #[cfg(not(target_arch = "wasm32"))]
        {
            let _ = conversation;
            Err(ConstructError::StorageError(
                "IndexedDB only available in WASM".to_string(),
            ))
        }
    }

    /// Загрузить беседу по ID
    async fn load_conversation(&self, conversation_id: &str) -> Result<Option<Conversation>> {
        #[cfg(target_arch = "wasm32")]
        {
            let db = self.db.as_ref().ok_or_else(|| {
                ConstructError::StorageError("Database not initialized".to_string())
            })?;

            ops::get_typed(db, "conversations", conversation_id).await
        }

        #[cfg(not(target_arch = "wasm32"))]
        {
            let _ = conversation_id;
            Ok(None)
        }
    }

    /// Загрузить все беседы
    async fn load_conversations(&self) -> Result<Vec<Conversation>> {
        #[cfg(target_arch = "wasm32")]
        {
            let db = self.db.as_ref().ok_or_else(|| {
                ConstructError::StorageError("Database not initialized".to_string())
            })?;

            let mut conversations: Vec<Conversation> =
                ops::get_all_typed(db, "conversations").await?;

            // Sort by last message timestamp (most recent first)
            conversations.sort_by(|a, b| {
                b.last_message_timestamp
                    .unwrap_or(0)
                    .cmp(&a.last_message_timestamp.unwrap_or(0))
            });

            Ok(conversations)
        }

        #[cfg(not(target_arch = "wasm32"))]
        {
            Ok(Vec::new())
        }
    }

    /// Обновить непрочитанное количество
    async fn update_conversation_unread(&self, conversation_id: &str, count: u32) -> Result<()> {
        #[cfg(target_arch = "wasm32")]
        {
            let db = self.db.as_ref().ok_or_else(|| {
                ConstructError::StorageError("Database not initialized".to_string())
            })?;

            // Load conversation, update count, save back
            if let Some(mut conversation) = self.load_conversation(conversation_id).await? {
                conversation.unread_count = count;
                ops::put_typed(db, "conversations", &conversation).await?;
            }
            Ok(())
        }

        #[cfg(not(target_arch = "wasm32"))]
        {
            let _ = (conversation_id, count);
            Ok(())
        }
    }

    /// Удалить беседу
    async fn delete_conversation(&self, conversation_id: &str) -> Result<()> {
        #[cfg(target_arch = "wasm32")]
        {
            let db = self.db.as_ref().ok_or_else(|| {
                ConstructError::StorageError("Database not initialized".to_string())
            })?;

            ops::delete_by_key(db, "conversations", conversation_id).await
        }

        #[cfg(not(target_arch = "wasm32"))]
        {
            let _ = conversation_id;
            Ok(())
        }
    }

    // === Maintenance ===

    /// Очистить все данные
    async fn clear_all(&self) -> Result<()> {
        #[cfg(target_arch = "wasm32")]
        {
            let db = self.db.as_ref().ok_or_else(|| {
                ConstructError::StorageError("Database not initialized".to_string())
            })?;

            // Delete all messages
            let messages: Vec<StoredMessage> = ops::get_all_typed(db, "messages").await?;
            for message in messages {
                ops::delete_by_key(db, "messages", &message.id).await?;
            }

            // Delete all contacts
            let contacts: Vec<StoredContact> = ops::get_all_typed(db, "contacts").await?;
            for contact in contacts {
                ops::delete_by_key(db, "contacts", &contact.id).await?;
            }

            // Delete all conversations
            let conversations: Vec<Conversation> = ops::get_all_typed(db, "conversations").await?;
            for conversation in conversations {
                ops::delete_by_key(db, "conversations", &conversation.id).await?;
            }

            // Delete all sessions
            let sessions: Vec<StoredSession> = ops::get_all_typed(db, "sessions").await?;
            for session in sessions {
                ops::delete_by_key(db, "sessions", &session.session_id).await?;
            }

            // Delete all auth tokens
            let auth_tokens: Vec<AuthTokens> = ops::get_all_typed(db, "auth_tokens").await?;
            for tokens in auth_tokens {
                ops::delete_by_key(db, "auth_tokens", &tokens.user_id).await?;
            }

            // Delete all private keys
            let private_keys: Vec<StoredPrivateKeys> =
                ops::get_all_typed(db, "private_keys").await?;
            for keys in private_keys {
                ops::delete_by_key(db, "private_keys", &keys.user_id).await?;
            }

            // Delete all metadata
            let metadata: Vec<StoredAppMetadata> = ops::get_all_typed(db, "metadata").await?;
            for meta in metadata {
                ops::delete_by_key(db, "metadata", &meta.user_id).await?;
            }

            Ok(())
        }

        #[cfg(not(target_arch = "wasm32"))]
        {
            Ok(())
        }
    }
}
