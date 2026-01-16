// Модуль аутентификации и управления токенами

pub mod token_manager;

// Re-export для удобства
pub use token_manager::{TokenManager, TokenManagerBuilder};
