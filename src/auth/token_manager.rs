// Token Manager для управления access/refresh tokens
//
// Основной функционал:
// - Хранение access и refresh tokens
// - Автоматический refresh при истечении access token
// - Интеграция с SecureStorage для персистентности
// - Thread-safe операции

use crate::protocol::rest_transport::{AuthTokens, RestClient};
use crate::storage::traits::SecureStorage;
use crate::utils::error::{ConstructError, Result};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

/// Token Manager для управления аутентификацией
///
/// Generic по типу storage для поддержки разных реализаций
/// (IndexedDbStorage для Web, IOSStorageAdapter для iOS)
pub struct TokenManager<S: SecureStorage> {
    /// REST клиент для refresh запросов
    rest_client: Arc<RestClient>,

    /// Secure storage для персистентности
    storage: Arc<S>,

    /// Текущие токены (в памяти)
    tokens: Arc<Mutex<Option<AuthTokens>>>,

    /// Минимальное время до истечения для автоматического refresh (в секундах)
    /// По умолчанию 5 минут - если токен истекает через менее чем 5 минут, обновляем
    refresh_threshold_secs: i64,
}

impl<S: SecureStorage> TokenManager<S> {
    /// Создать новый Token Manager
    ///
    /// # Parameters
    /// - `rest_client`: REST клиент для refresh запросов
    /// - `storage`: Secure storage для хранения токенов
    pub fn new(rest_client: Arc<RestClient>, storage: Arc<S>) -> Self {
        Self {
            rest_client,
            storage,
            tokens: Arc::new(Mutex::new(None)),
            refresh_threshold_secs: 5 * 60, // 5 минут
        }
    }

    /// Установить порог для автоматического refresh (в секундах)
    pub fn set_refresh_threshold(&mut self, threshold_secs: i64) {
        self.refresh_threshold_secs = threshold_secs;
    }

    /// Инициализировать менеджер (загрузить токены из storage)
    pub async fn init(&self) -> Result<()> {
        // Загрузить токены из storage
        let stored_tokens = self.storage.load_auth_tokens().await?;

        if let Some(tokens) = stored_tokens {
            // Проверить не истекли ли токены
            if !self.is_expired(&tokens) {
                let mut tokens_lock = self.tokens.lock().unwrap();
                *tokens_lock = Some(tokens);
            } else {
                // Если access token истек, попробуем refresh
                // Но refresh token тоже может быть истекшим
                if self.can_refresh(&tokens) {
                    drop(self.refresh_tokens_internal().await);
                }
            }
        }

        Ok(())
    }

    /// Установить новые токены (например, после логина)
    pub async fn set_tokens(&self, tokens: AuthTokens) -> Result<()> {
        // Сохранить в storage
        self.storage.save_auth_tokens(&tokens).await?;

        // Обновить в памяти
        let mut tokens_lock = self.tokens.lock().unwrap();
        *tokens_lock = Some(tokens);

        Ok(())
    }

    /// Получить валидный access token
    ///
    /// Если токен истекает скоро, автоматически обновляет его
    /// Если refresh token истек, возвращает ошибку Unauthenticated
    pub async fn get_valid_token(&self) -> Result<String> {
        let needs_refresh = {
            let tokens = self.tokens.lock().unwrap();
            if let Some(current_tokens) = tokens.as_ref() {
                self.needs_refresh(current_tokens)
            } else {
                return Err(ConstructError::Unauthenticated(
                    "No tokens available. Please login.".to_string(),
                ));
            }
        };

        if needs_refresh {
            // Обновить токены
            self.refresh_tokens().await?;
        }

        // Получить токен
        let tokens = self.tokens.lock().unwrap();
        Ok(tokens
            .as_ref()
            .ok_or_else(|| ConstructError::Unauthenticated("No tokens available".to_string()))?
            .access_token
            .clone())
    }

    /// Обновить токены через refresh token
    pub async fn refresh_tokens(&self) -> Result<()> {
        self.refresh_tokens_internal().await
    }

    /// Очистить токены (logout)
    pub async fn clear_tokens(&self) -> Result<()> {
        // Очистить в storage
        self.storage.clear_auth_tokens().await?;

        // Очистить в памяти
        let mut tokens_lock = self.tokens.lock().unwrap();
        *tokens_lock = None;

        Ok(())
    }

    /// Получить текущие токены (если есть)
    pub fn get_tokens(&self) -> Option<AuthTokens> {
        let tokens = self.tokens.lock().unwrap();
        tokens.clone()
    }

    /// Проверить есть ли валидные токены
    pub fn has_valid_tokens(&self) -> bool {
        let tokens = self.tokens.lock().unwrap();
        if let Some(current_tokens) = tokens.as_ref() {
            !self.is_expired(current_tokens) && self.can_refresh(current_tokens)
        } else {
            false
        }
    }

    // === Private Methods ===

    /// Внутренняя реализация refresh токенов
    async fn refresh_tokens_internal(&self) -> Result<()> {
        let refresh_token = {
            let tokens = self.tokens.lock().unwrap();
            tokens
                .as_ref()
                .ok_or_else(|| {
                    ConstructError::Unauthenticated("No refresh token available".to_string())
                })?
                .refresh_token
                .clone()
        };

        // Выполнить refresh запрос
        let new_tokens = self
            .rest_client
            .refresh_token(refresh_token)
            .await
            .map_err(|e| {
                ConstructError::Unauthenticated(format!("Failed to refresh tokens: {:?}", e))
            })?;

        // Сохранить новые токены
        self.set_tokens(new_tokens).await?;

        Ok(())
    }

    /// Проверить истек ли access token
    fn is_expired(&self, tokens: &AuthTokens) -> bool {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;

        tokens.expires_at <= now
    }

    /// Проверить нужно ли обновить токен
    /// (истекает в течение refresh_threshold_secs)
    fn needs_refresh(&self, tokens: &AuthTokens) -> bool {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;

        // Если токен истекает через меньше чем threshold секунд
        (tokens.expires_at - now) < self.refresh_threshold_secs
    }

    /// Проверить можно ли использовать refresh token
    /// (refresh token обычно живет 30 дней, но мы не храним его expires_at отдельно)
    fn can_refresh(&self, tokens: &AuthTokens) -> bool {
        // Если у нас есть refresh token, предполагаем что он валиден
        // Реальная проверка произойдет при попытке refresh
        !tokens.refresh_token.is_empty()
    }
}

// ============================================================================
// Builder для удобного создания TokenManager
// ============================================================================

pub struct TokenManagerBuilder<S: SecureStorage> {
    rest_client: Option<Arc<RestClient>>,
    storage: Option<Arc<S>>,
    refresh_threshold_secs: i64,
}

impl<S: SecureStorage> TokenManagerBuilder<S> {
    pub fn new() -> Self {
        Self {
            rest_client: None,
            storage: None,
            refresh_threshold_secs: 5 * 60, // 5 минут по умолчанию
        }
    }

    pub fn rest_client(mut self, client: Arc<RestClient>) -> Self {
        self.rest_client = Some(client);
        self
    }

    pub fn storage(mut self, storage: Arc<S>) -> Self {
        self.storage = Some(storage);
        self
    }

    pub fn refresh_threshold_secs(mut self, threshold: i64) -> Self {
        self.refresh_threshold_secs = threshold;
        self
    }

    pub fn build(self) -> Result<TokenManager<S>> {
        let rest_client = self
            .rest_client
            .ok_or_else(|| ConstructError::InvalidInput("REST client is required".to_string()))?;
        let storage = self
            .storage
            .ok_or_else(|| ConstructError::InvalidInput("Storage is required".to_string()))?;

        let mut manager = TokenManager::new(rest_client, storage);
        manager.set_refresh_threshold(self.refresh_threshold_secs);

        Ok(manager)
    }
}

impl<S: SecureStorage> Default for TokenManagerBuilder<S> {
    fn default() -> Self {
        Self::new()
    }
}
