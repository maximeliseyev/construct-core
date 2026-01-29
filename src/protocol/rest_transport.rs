// REST API Transport Layer
//
// Реализует HTTP клиент для REST API сервера construct-messenger
// Поддерживает:
// - Auth endpoints (login, register, refresh)
// - Message endpoints (send, poll)
// - Keys endpoints (upload, get public key)
// - CSRF protection
// - Request signing (опционально)

use crate::utils::error::{ConstructError, Result};
use serde::{Deserialize, Serialize};

// Re-export AuthTokens from storage traits
pub use crate::storage::traits::AuthTokens;

// ============================================================================
// Request/Response Models
// ============================================================================

/// Запрос на логин
#[derive(Debug, Serialize)]
pub struct LoginRequest {
    pub username: String,
    pub password: String,
}

/// Запрос на регистрацию
#[derive(Debug, Serialize)]
pub struct RegisterRequest {
    pub username: String,
    pub password: String,
    #[serde(rename = "publicKey")]
    pub public_key: String, // Base64-encoded identity key
}

/// Запрос на обновление токена
#[derive(Debug, Serialize)]
pub struct RefreshTokenRequest {
    #[serde(rename = "refreshToken")]
    pub refresh_token: String,
}

/// CSRF токен response
#[derive(Debug, Deserialize)]
pub struct CsrfTokenResponse {
    #[serde(rename = "csrfToken")]
    pub csrf_token: String,
}

/// Подпись запроса (для request signing)
#[derive(Debug, Clone, Serialize)]
pub struct RequestSignature {
    pub signature: String, // Base64-encoded Ed25519 signature
    #[serde(rename = "publicKey")]
    pub public_key: String, // Base64-encoded Ed25519 public key
    pub timestamp: i64,    // Unix epoch seconds
}

/// Опции для HTTP запроса
#[derive(Debug, Clone, Default)]
pub struct RequestOptions {
    pub access_token: Option<String>,
    pub csrf_token: Option<String>,
    pub request_signature: Option<RequestSignature>,
}

// ============================================================================
// REST Client (WASM implementation)
// ============================================================================

#[cfg(target_arch = "wasm32")]
use wasm_bindgen::prelude::*;
#[cfg(target_arch = "wasm32")]
use wasm_bindgen::JsCast;
#[cfg(target_arch = "wasm32")]
use wasm_bindgen_futures::JsFuture;
#[cfg(target_arch = "wasm32")]
use web_sys::{Request, RequestInit, RequestMode, Response};

/// REST API клиент
pub struct RestClient {
    base_url: String,
}

impl RestClient {
    /// Создать новый REST клиент
    pub fn new(base_url: String) -> Self {
        Self { base_url }
    }

    /// Получить базовый URL
    pub fn base_url(&self) -> &str {
        &self.base_url
    }

    // === Auth Endpoints ===

    /// Логин
    pub async fn login(&self, request: LoginRequest) -> Result<AuthTokens> {
        let url = format!("{}/api/v1/auth/login", self.base_url);
        self.post_json(&url, &request, RequestOptions::default())
            .await
    }

    /// Регистрация
    pub async fn register(&self, request: RegisterRequest) -> Result<AuthTokens> {
        let url = format!("{}/api/v1/auth/register", self.base_url);
        self.post_json(&url, &request, RequestOptions::default())
            .await
    }

    /// Обновить access token
    pub async fn refresh_token(&self, refresh_token: String) -> Result<AuthTokens> {
        let url = format!("{}/auth/refresh", self.base_url);
        let request = RefreshTokenRequest { refresh_token };
        self.post_json(&url, &request, RequestOptions::default())
            .await
    }

    /// Получить CSRF токен (для браузерных клиентов)
    pub async fn get_csrf_token(&self) -> Result<String> {
        let url = format!("{}/api/csrf-token", self.base_url);
        let response: CsrfTokenResponse = self.get_json(&url, RequestOptions::default()).await?;
        Ok(response.csrf_token)
    }

    // === Message Endpoints ===

    /// Отправить сообщение
    pub async fn send_message<T: Serialize, R: for<'de> Deserialize<'de>>(
        &self,
        message: &T,
        options: RequestOptions,
    ) -> Result<R> {
        let url = format!("{}/api/v1/messages", self.base_url);
        self.post_json(&url, message, options).await
    }

    /// Получить сообщения (long polling)
    pub async fn poll_messages<R: for<'de> Deserialize<'de>>(
        &self,
        since_id: Option<String>,
        options: RequestOptions,
    ) -> Result<R> {
        let mut url = format!("{}/api/v1/messages", self.base_url);
        if let Some(id) = since_id {
            url.push_str(&format!("?since={}", id));
        }
        self.get_json(&url, options).await
    }

    // === Keys Endpoints ===

    /// Загрузить ключи (prekeys, signed prekey)
    pub async fn upload_keys<T: Serialize, R: for<'de> Deserialize<'de>>(
        &self,
        bundle: &T,
        options: RequestOptions,
    ) -> Result<R> {
        let url = format!("{}/api/v1/keys/upload", self.base_url);
        self.post_json(&url, bundle, options).await
    }

    /// Получить публичный ключ пользователя
    pub async fn get_public_key<R: for<'de> Deserialize<'de>>(
        &self,
        user_id: &str,
        options: RequestOptions,
    ) -> Result<R> {
        let url = format!("{}/api/v1/users/{}/public-key", self.base_url, user_id);
        self.get_json(&url, options).await
    }

    // === Low-level HTTP Methods ===

    #[cfg(target_arch = "wasm32")]
    async fn post_json<T: Serialize, R: for<'de> Deserialize<'de>>(
        &self,
        url: &str,
        body: &T,
        options: RequestOptions,
    ) -> Result<R> {
        let json_body = serde_json::to_string(body).map_err(|e| {
            ConstructError::SerializationError(format!("Failed to serialize request: {:?}", e))
        })?;

        let init = RequestInit::new();
        init.set_method("POST");
        init.set_mode(RequestMode::Cors);
        init.set_body(&JsValue::from_str(&json_body));

        let headers = self.build_headers("POST", &options, Some(&json_body))?;

        let request = Request::new_with_str_and_init(url, &init).map_err(|e| {
            ConstructError::NetworkError(format!("Failed to create request: {:?}", e))
        })?;

        // Set headers
        for (key, value) in headers {
            request.headers().set(&key, &value).map_err(|e| {
                ConstructError::NetworkError(format!("Failed to set header: {:?}", e))
            })?;
        }

        self.fetch_json(request).await
    }

    #[cfg(target_arch = "wasm32")]
    async fn get_json<R: for<'de> Deserialize<'de>>(
        &self,
        url: &str,
        options: RequestOptions,
    ) -> Result<R> {
        let init = RequestInit::new();
        init.set_method("GET");
        init.set_mode(RequestMode::Cors);

        let headers = self.build_headers("GET", &options, None)?;

        let request = Request::new_with_str_and_init(url, &init).map_err(|e| {
            ConstructError::NetworkError(format!("Failed to create request: {:?}", e))
        })?;

        // Set headers
        for (key, value) in headers {
            request.headers().set(&key, &value).map_err(|e| {
                ConstructError::NetworkError(format!("Failed to set header: {:?}", e))
            })?;
        }

        self.fetch_json(request).await
    }

    #[cfg(target_arch = "wasm32")]
    async fn fetch_json<R: for<'de> Deserialize<'de>>(&self, request: Request) -> Result<R> {
        let window = web_sys::window()
            .ok_or_else(|| ConstructError::NetworkError("No window object".to_string()))?;

        let response_promise = window.fetch_with_request(&request);
        let response_value = JsFuture::from(response_promise)
            .await
            .map_err(|e| ConstructError::NetworkError(format!("Fetch failed: {:?}", e)))?;

        let response: Response = response_value
            .dyn_into()
            .map_err(|_| ConstructError::NetworkError("Invalid response object".to_string()))?;

        // Check status
        if !response.ok() {
            let status = response.status();
            let text_promise = response.text().map_err(|e| {
                ConstructError::NetworkError(format!("Failed to read error response: {:?}", e))
            })?;
            let text_value = JsFuture::from(text_promise).await.map_err(|e| {
                ConstructError::NetworkError(format!("Failed to read error text: {:?}", e))
            })?;
            let error_text = text_value
                .as_string()
                .unwrap_or_else(|| "Unknown error".to_string());

            return Err(ConstructError::NetworkError(format!(
                "HTTP {} - {}",
                status, error_text
            )));
        }

        // Parse JSON response
        let json_promise = response
            .json()
            .map_err(|e| ConstructError::NetworkError(format!("Failed to parse JSON: {:?}", e)))?;
        let json_value = JsFuture::from(json_promise)
            .await
            .map_err(|e| ConstructError::NetworkError(format!("Failed to read JSON: {:?}", e)))?;

        serde_wasm_bindgen::from_value(json_value).map_err(|e| {
            ConstructError::SerializationError(format!("Failed to deserialize response: {:?}", e))
        })
    }

    #[cfg(target_arch = "wasm32")]
    fn build_headers(
        &self,
        _method: &str,
        options: &RequestOptions,
        _body: Option<&str>,
    ) -> Result<Vec<(String, String)>> {
        let mut headers = vec![("Content-Type".to_string(), "application/json".to_string())];

        // Authorization header
        if let Some(token) = &options.access_token {
            headers.push(("Authorization".to_string(), format!("Bearer {}", token)));
        }

        // CSRF token
        if let Some(csrf) = &options.csrf_token {
            headers.push(("X-CSRF-Token".to_string(), csrf.clone()));
        } else {
            // Для мобильных клиентов - альтернатива CSRF токену
            headers.push(("X-Requested-With".to_string(), "XMLHttpRequest".to_string()));
        }

        // Request signature (если предоставлен)
        if let Some(signature) = &options.request_signature {
            let signature_json = serde_json::to_string(signature).map_err(|e| {
                ConstructError::SerializationError(format!(
                    "Failed to serialize signature: {:?}",
                    e
                ))
            })?;
            headers.push(("X-Request-Signature".to_string(), signature_json));
        }

        Ok(headers)
    }
}

// ============================================================================
// REST Client (non-WASM stub)
// ============================================================================

#[cfg(not(target_arch = "wasm32"))]
impl RestClient {
    async fn post_json<T: Serialize, R: for<'de> Deserialize<'de>>(
        &self,
        _url: &str,
        _body: &T,
        _options: RequestOptions,
    ) -> Result<R> {
        Err(ConstructError::NetworkError(
            "REST client only available in WASM target".to_string(),
        ))
    }

    async fn get_json<R: for<'de> Deserialize<'de>>(
        &self,
        _url: &str,
        _options: RequestOptions,
    ) -> Result<R> {
        Err(ConstructError::NetworkError(
            "REST client only available in WASM target".to_string(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_auth_tokens_serialization() {
        let tokens = AuthTokens {
            access_token: "access123".to_string(),
            refresh_token: "refresh456".to_string(),
            expires_at: 1705320000,
            user_id: "user789".to_string(),
        };

        let json = serde_json::to_string(&tokens).unwrap();
        assert!(json.contains("accessToken"));
        assert!(json.contains("refreshToken"));
        assert!(json.contains("expiresAt"));
        assert!(json.contains("userId"));
    }

    #[test]
    fn test_login_request_serialization() {
        let request = LoginRequest {
            username: "user@example.com".to_string(),
            password: "password123".to_string(),
        };

        let json = serde_json::to_string(&request).unwrap();
        assert!(json.contains("username"));
        assert!(json.contains("password"));
    }
}
