// iOS Storage Adapter Implementation
//
// Реализация SecureStorage и DataStorage traits для iOS,
// использующая callback интерфейсы для интеграции с Keychain и Core Data.

use crate::storage::ios_callbacks::{
    deserialize_from_json, serialize_to_json, DataStorageCallback, IOSStorageAdapter,
    SecureStorageCallback,
};
use crate::storage::models::*;
use crate::storage::traits::{AuthTokens, DataStorage, SecureStorage};
use crate::utils::error::{ConstructError, Result};
use std::sync::Arc;

// ============================================================================
// SecureStorage Implementation (Keychain через callbacks)
// ============================================================================

impl SecureStorage for IOSStorageAdapter {
    fn save_auth_tokens(
        &self,
        tokens: &AuthTokens,
    ) -> impl std::future::Future<Output = Result<()>> + Send {
        let user_id = self.user_id().to_string();
        let json = serialize_to_json(tokens);
        let callback = self.secure_callback().clone();
        async move {
            let json = json?;
            callback
                .save_auth_tokens(user_id, json)
                .map_err(ConstructError::from)
        }
    }

    fn load_auth_tokens(
        &self,
    ) -> impl std::future::Future<Output = Result<Option<AuthTokens>>> + Send {
        let user_id = self.user_id().to_string();
        let callback = self.secure_callback().clone();
        async move {
            match callback
                .load_auth_tokens(user_id)
                .map_err(ConstructError::from)?
            {
                Some(json) => Ok(Some(deserialize_from_json(&json)?)),
                None => Ok(None),
            }
        }
    }

    fn clear_auth_tokens(&self) -> impl std::future::Future<Output = Result<()>> + Send {
        let user_id = self.user_id().to_string();
        let callback = self.secure_callback().clone();
        async move {
            callback
                .delete_auth_tokens(user_id)
                .map_err(ConstructError::from)
        }
    }

    fn save_private_keys(
        &self,
        keys: &StoredPrivateKeys,
    ) -> impl std::future::Future<Output = Result<()>> + Send {
        let user_id = self.user_id().to_string();
        let json = serialize_to_json(keys);
        let callback = self.secure_callback().clone();
        async move {
            let json = json?;
            callback
                .save_private_keys(user_id, json)
                .map_err(ConstructError::from)
        }
    }

    fn load_private_keys(
        &self,
    ) -> impl std::future::Future<Output = Result<Option<StoredPrivateKeys>>> + Send {
        let user_id = self.user_id().to_string();
        let callback = self.secure_callback().clone();
        async move {
            match callback
                .load_private_keys(user_id)
                .map_err(ConstructError::from)?
            {
                Some(json) => Ok(Some(deserialize_from_json(&json)?)),
                None => Ok(None),
            }
        }
    }

    fn clear_private_keys(&self) -> impl std::future::Future<Output = Result<()>> + Send {
        let user_id = self.user_id().to_string();
        let callback = self.secure_callback().clone();
        async move {
            callback
                .delete_private_keys(user_id)
                .map_err(ConstructError::from)
        }
    }

    fn save_session(
        &self,
        _contact_id: &str,
        session: &StoredSession,
    ) -> impl std::future::Future<Output = Result<()>> + Send {
        let session_id = session.session_id.clone();
        let json = serialize_to_json(session);
        let callback = self.secure_callback().clone();
        async move {
            let json = json?;
            callback
                .save_session(session_id, json)
                .map_err(ConstructError::from)
        }
    }

    fn load_session(
        &self,
        contact_id: &str,
    ) -> impl std::future::Future<Output = Result<Option<StoredSession>>> + Send {
        let contact_id = contact_id.to_string();
        let callback = self.secure_callback().clone();
        async move {
            let sessions_json = callback
                .load_sessions_by_contact(contact_id)
                .map_err(ConstructError::from)?;

            if sessions_json.is_empty() {
                return Ok(None);
            }

            Ok(Some(deserialize_from_json(&sessions_json[0])?))
        }
    }

    fn delete_session(
        &self,
        contact_id: &str,
    ) -> impl std::future::Future<Output = Result<()>> + Send {
        let contact_id = contact_id.to_string();
        let callback = self.secure_callback().clone();
        async move {
            let sessions_json = callback
                .load_sessions_by_contact(contact_id.clone())
                .map_err(ConstructError::from)?;

            for json in sessions_json {
                let session: StoredSession = deserialize_from_json(&json)?;
                callback
                    .delete_session(session.session_id.clone())
                    .map_err(ConstructError::from)?;
            }

            Ok(())
        }
    }

    async fn list_sessions(&self) -> Result<Vec<String>> {
        self.secure_callback()
            .list_session_contact_ids()
            .map_err(ConstructError::from)
    }

    fn clear_all_sessions(&self) -> impl std::future::Future<Output = Result<()>> + Send {
        let callback = self.secure_callback().clone();
        async move {
            callback
                .clear_all_secure_data()
                .map_err(ConstructError::from)
        }
    }

    fn save_app_metadata(
        &self,
        metadata: &StoredAppMetadata,
    ) -> impl std::future::Future<Output = Result<()>> + Send {
        let user_id = self.user_id().to_string();
        let json = serialize_to_json(metadata);
        let callback = self.data_callback().clone();
        async move {
            let json = json?;
            callback
                .save_metadata(user_id, json)
                .map_err(ConstructError::from)
        }
    }

    fn load_app_metadata(
        &self,
    ) -> impl std::future::Future<Output = Result<Option<StoredAppMetadata>>> + Send {
        let user_id = self.user_id().to_string();
        let callback = self.data_callback().clone();
        async move {
            match callback
                .load_metadata(user_id)
                .map_err(ConstructError::from)?
            {
                Some(json) => Ok(Some(deserialize_from_json(&json)?)),
                None => Ok(None),
            }
        }
    }
}

// ============================================================================
// DataStorage Implementation (Core Data/UserDefaults через callbacks)
// ============================================================================

impl DataStorage for IOSStorageAdapter {
    fn save_message(
        &self,
        message: &StoredMessage,
    ) -> impl std::future::Future<Output = Result<()>> + Send {
        let json = serialize_to_json(message);
        let callback = self.data_callback().clone();
        async move {
            let json = json?;
            callback.save_message(json).map_err(ConstructError::from)
        }
    }

    fn update_message_status(
        &self,
        message_id: &str,
        status: MessageStatus,
    ) -> impl std::future::Future<Output = Result<()>> + Send {
        let message_id = message_id.to_string();
        let callback = self.data_callback().clone();
        async move {
            let json_opt = callback
                .load_message(message_id.clone())
                .map_err(ConstructError::from)?;
            match json_opt {
                Some(json) => {
                    let mut message: StoredMessage = deserialize_from_json(&json)?;
                    message.status = status;
                    let json = serialize_to_json(&message)?;
                    callback.save_message(json).map_err(ConstructError::from)
                }
                None => Err(ConstructError::NotFound(format!(
                    "Message {} not found",
                    message_id
                ))),
            }
        }
    }

    fn load_messages(
        &self,
        conversation_id: &str,
        limit: usize,
        offset: usize,
    ) -> impl std::future::Future<Output = Result<Vec<StoredMessage>>> + Send {
        let conversation_id = conversation_id.to_string();
        let callback = self.data_callback().clone();
        async move {
            let messages_json = callback
                .load_messages(conversation_id, limit as u32, offset as u32)
                .map_err(ConstructError::from)?;

            let mut messages = Vec::new();
            for json in messages_json {
                messages.push(deserialize_from_json(&json)?);
            }

            Ok(messages)
        }
    }

    fn load_message(
        &self,
        message_id: &str,
    ) -> impl std::future::Future<Output = Result<Option<StoredMessage>>> + Send {
        let message_id = message_id.to_string();
        let callback = self.data_callback().clone();
        async move {
            match callback
                .load_message(message_id)
                .map_err(ConstructError::from)?
            {
                Some(json) => Ok(Some(deserialize_from_json(&json)?)),
                None => Ok(None),
            }
        }
    }

    fn delete_message(
        &self,
        message_id: &str,
    ) -> impl std::future::Future<Output = Result<()>> + Send {
        let message_id = message_id.to_string();
        let callback = self.data_callback().clone();
        async move {
            callback
                .delete_message(message_id)
                .map_err(ConstructError::from)
        }
    }

    fn delete_messages_in_conversation(
        &self,
        conversation_id: &str,
    ) -> impl std::future::Future<Output = Result<()>> + Send {
        let conversation_id = conversation_id.to_string();
        let callback = self.data_callback().clone();
        async move {
            callback
                .delete_messages_in_conversation(conversation_id)
                .map_err(ConstructError::from)
        }
    }

    fn count_messages(
        &self,
        conversation_id: &str,
    ) -> impl std::future::Future<Output = Result<usize>> + Send {
        let conversation_id = conversation_id.to_string();
        let callback = self.data_callback().clone();
        async move {
            let count = callback
                .count_messages(conversation_id)
                .map_err(ConstructError::from)?;
            Ok(count as usize)
        }
    }

    fn save_contact(
        &self,
        contact: &StoredContact,
    ) -> impl std::future::Future<Output = Result<()>> + Send {
        let json = serialize_to_json(contact);
        let callback = self.data_callback().clone();
        async move {
            let json = json?;
            callback.save_contact(json).map_err(ConstructError::from)
        }
    }

    fn load_contact(
        &self,
        contact_id: &str,
    ) -> impl std::future::Future<Output = Result<Option<StoredContact>>> + Send {
        let contact_id = contact_id.to_string();
        let callback = self.data_callback().clone();
        async move {
            match callback
                .load_contact(contact_id)
                .map_err(ConstructError::from)?
            {
                Some(json) => Ok(Some(deserialize_from_json(&json)?)),
                None => Ok(None),
            }
        }
    }

    fn load_contacts(
        &self,
    ) -> impl std::future::Future<Output = Result<Vec<StoredContact>>> + Send {
        let callback = self.data_callback().clone();
        async move {
            let contacts_json = callback.load_contacts().map_err(ConstructError::from)?;

            let mut contacts = Vec::new();
            for json in contacts_json {
                contacts.push(deserialize_from_json(&json)?);
            }

            Ok(contacts)
        }
    }

    fn update_contact_last_message(
        &self,
        contact_id: &str,
        timestamp: i64,
    ) -> impl std::future::Future<Output = Result<()>> + Send {
        let contact_id = contact_id.to_string();
        let callback = self.data_callback().clone();
        async move {
            let json_opt = callback
                .load_contact(contact_id.clone())
                .map_err(ConstructError::from)?;
            match json_opt {
                Some(json) => {
                    let mut contact: StoredContact = deserialize_from_json(&json)?;
                    contact.last_message_at = Some(timestamp);
                    let json = serialize_to_json(&contact)?;
                    callback.save_contact(json).map_err(ConstructError::from)
                }
                None => Err(ConstructError::NotFound(format!(
                    "Contact {} not found",
                    contact_id
                ))),
            }
        }
    }

    fn delete_contact(
        &self,
        contact_id: &str,
    ) -> impl std::future::Future<Output = Result<()>> + Send {
        let contact_id = contact_id.to_string();
        let callback = self.data_callback().clone();
        async move {
            callback
                .delete_contact(contact_id)
                .map_err(ConstructError::from)
        }
    }

    fn save_conversation(
        &self,
        conversation: &Conversation,
    ) -> impl std::future::Future<Output = Result<()>> + Send {
        let json = serialize_to_json(conversation);
        let callback = self.data_callback().clone();
        async move {
            let json = json?;
            callback
                .save_conversation(json)
                .map_err(ConstructError::from)
        }
    }

    fn load_conversation(
        &self,
        conversation_id: &str,
    ) -> impl std::future::Future<Output = Result<Option<Conversation>>> + Send {
        let conversation_id = conversation_id.to_string();
        let callback = self.data_callback().clone();
        async move {
            match callback
                .load_conversation(conversation_id)
                .map_err(ConstructError::from)?
            {
                Some(json) => Ok(Some(deserialize_from_json(&json)?)),
                None => Ok(None),
            }
        }
    }

    fn load_conversations(
        &self,
    ) -> impl std::future::Future<Output = Result<Vec<Conversation>>> + Send {
        let callback = self.data_callback().clone();
        async move {
            let conversations_json = callback
                .load_conversations()
                .map_err(ConstructError::from)?;

            let mut conversations = Vec::new();
            for json in conversations_json {
                conversations.push(deserialize_from_json(&json)?);
            }

            Ok(conversations)
        }
    }

    fn update_conversation_unread(
        &self,
        conversation_id: &str,
        count: u32,
    ) -> impl std::future::Future<Output = Result<()>> + Send {
        let conversation_id = conversation_id.to_string();
        let callback = self.data_callback().clone();
        async move {
            let json_opt = callback
                .load_conversation(conversation_id.clone())
                .map_err(ConstructError::from)?;
            match json_opt {
                Some(json) => {
                    let mut conversation: Conversation = deserialize_from_json(&json)?;
                    conversation.unread_count = count;
                    let json = serialize_to_json(&conversation)?;
                    callback
                        .save_conversation(json)
                        .map_err(ConstructError::from)
                }
                None => Err(ConstructError::NotFound(format!(
                    "Conversation {} not found",
                    conversation_id
                ))),
            }
        }
    }

    fn delete_conversation(
        &self,
        conversation_id: &str,
    ) -> impl std::future::Future<Output = Result<()>> + Send {
        let conversation_id = conversation_id.to_string();
        let callback = self.data_callback().clone();
        async move {
            callback
                .delete_conversation(conversation_id)
                .map_err(ConstructError::from)
        }
    }

    fn clear_all(&self) -> impl std::future::Future<Output = Result<()>> + Send {
        let callback = self.data_callback().clone();
        async move { callback.clear_all_data().map_err(ConstructError::from) }
    }
}

// ============================================================================
// Convenience Functions for iOS
// ============================================================================

/// Создать iOS storage адаптер (удобная функция для UniFFI)
pub fn create_ios_storage(
    user_id: String,
    secure_callback: Arc<dyn SecureStorageCallback>,
    data_callback: Arc<dyn DataStorageCallback>,
) -> IOSStorageAdapter {
    IOSStorageAdapter::new(user_id, secure_callback, data_callback)
}
