// API для управления контактами

use crate::storage::models::StoredContact;
use crate::utils::error::{ConstructError, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Информация о контакте
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Contact {
    pub id: String,
    pub username: String,
    pub public_key_bundle: Option<PublicKeyBundle>,
    pub added_at: i64,
    pub last_message_at: Option<i64>,
}

/// Публичный ключевой bundle контакта
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PublicKeyBundle {
    pub identity_public: String,
    pub signed_prekey_public: String,
    pub signature: String,
    pub verifying_key: String,
}

/// Менеджер контактов
pub struct ContactManager {
    contacts: HashMap<String, Contact>,
}

impl ContactManager {
    /// Создать новый менеджер контактов
    pub fn new() -> Self {
        Self {
            contacts: HashMap::new(),
        }
    }

    /// Добавить контакт
    pub fn add_contact(&mut self, contact: Contact) -> Result<()> {
        if self.contacts.contains_key(&contact.id) {
            return Err(ConstructError::ValidationError(format!(
                "Contact already exists: {}",
                contact.id
            )));
        }

        self.contacts.insert(contact.id.clone(), contact);
        Ok(())
    }

    /// Получить контакт по ID
    pub fn get_contact(&self, user_id: &str) -> Option<&Contact> {
        self.contacts.get(user_id)
    }

    /// Получить контакт по username
    pub fn get_contact_by_username(&self, username: &str) -> Option<&Contact> {
        self.contacts.values().find(|c| c.username == username)
    }

    /// Обновить публичные ключи контакта
    pub fn update_contact_keys(&mut self, user_id: &str, bundle: PublicKeyBundle) -> Result<()> {
        let contact = self.contacts.get_mut(user_id).ok_or_else(|| {
            ConstructError::ValidationError(format!("Contact not found: {}", user_id))
        })?;

        contact.public_key_bundle = Some(bundle);
        Ok(())
    }

    /// Обновить время последнего сообщения
    pub fn update_last_message_time(&mut self, user_id: &str, timestamp: i64) -> Result<()> {
        let contact = self.contacts.get_mut(user_id).ok_or_else(|| {
            ConstructError::ValidationError(format!("Contact not found: {}", user_id))
        })?;

        contact.last_message_at = Some(timestamp);
        Ok(())
    }

    /// Удалить контакт
    pub fn remove_contact(&mut self, user_id: &str) -> Option<Contact> {
        self.contacts.remove(user_id)
    }

    /// Получить список всех контактов
    pub fn get_all_contacts(&self) -> Vec<&Contact> {
        self.contacts.values().collect()
    }

    /// Получить список ID всех контактов
    pub fn get_contact_ids(&self) -> Vec<String> {
        self.contacts.keys().cloned().collect()
    }

    /// Проверить существование контакта
    pub fn has_contact(&self, user_id: &str) -> bool {
        self.contacts.contains_key(user_id)
    }

    /// Количество контактов
    pub fn contact_count(&self) -> usize {
        self.contacts.len()
    }

    /// Поиск контактов по username (начинается с)
    pub fn search_contacts(&self, query: &str) -> Vec<&Contact> {
        let query_lower = query.to_lowercase();
        self.contacts
            .values()
            .filter(|c| c.username.to_lowercase().starts_with(&query_lower))
            .collect()
    }

    /// Экспорт контактов для сохранения
    pub fn export_contacts(&self) -> Result<Vec<u8>> {
        let contacts: Vec<&Contact> = self.contacts.values().collect();
        bincode::serialize(&contacts)
            .map_err(|e| ConstructError::SerializationError(format!("Failed to export contacts: {}", e)))
    }

    /// Импорт контактов
    pub fn import_contacts(&mut self, data: &[u8]) -> Result<()> {
        let contacts: Vec<Contact> = bincode::deserialize(data)
            .map_err(|e| ConstructError::SerializationError(format!("Failed to import contacts: {}", e)))?;

        for contact in contacts {
            self.contacts.insert(contact.id.clone(), contact);
        }

        Ok(())
    }

    /// Очистить все контакты
    pub fn clear_all(&mut self) {
        self.contacts.clear();
    }
}

impl Default for ContactManager {
    fn default() -> Self {
        Self::new()
    }
}

/// Создать новый контакт
pub fn create_contact(id: String, username: String) -> Contact {
    Contact {
        id,
        username,
        public_key_bundle: None,
        added_at: crate::utils::time::current_timestamp(),
        last_message_at: None,
    }
}

/// Конвертировать StoredContact в Contact
impl From<StoredContact> for Contact {
    fn from(stored: StoredContact) -> Self {
        Contact {
            id: stored.id,
            username: stored.username,
            public_key_bundle: None, // Ключи хранятся отдельно
            added_at: crate::utils::time::current_timestamp(),
            last_message_at: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_contact_manager_add_get() {
        let mut manager = ContactManager::new();
        let contact = create_contact("user1".to_string(), "alice".to_string());

        manager.add_contact(contact.clone()).unwrap();

        assert!(manager.has_contact("user1"));
        assert_eq!(manager.contact_count(), 1);

        let retrieved = manager.get_contact("user1").unwrap();
        assert_eq!(retrieved.username, "alice");
    }

    #[test]
    fn test_contact_manager_search() {
        let mut manager = ContactManager::new();

        manager
            .add_contact(create_contact("1".to_string(), "alice".to_string()))
            .unwrap();
        manager
            .add_contact(create_contact("2".to_string(), "bob".to_string()))
            .unwrap();
        manager
            .add_contact(create_contact("3".to_string(), "alex".to_string()))
            .unwrap();

        let results = manager.search_contacts("al");
        assert_eq!(results.len(), 2); // alice и alex
    }

    #[test]
    fn test_contact_manager_remove() {
        let mut manager = ContactManager::new();
        let contact = create_contact("user1".to_string(), "alice".to_string());

        manager.add_contact(contact).unwrap();
        assert!(manager.has_contact("user1"));

        manager.remove_contact("user1");
        assert!(!manager.has_contact("user1"));
    }
}
