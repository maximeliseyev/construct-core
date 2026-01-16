// WASM bindings
// wasm-bindgen automatically generates bindings from #[wasm_bindgen] attributes

use crate::crypto::suites::classic::ClassicSuiteProvider;
use crate::state::app::AppState;
use crate::storage::indexeddb::IndexedDbStorage;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use wasm_bindgen::prelude::*;

// Type alias for convenience
// AppState now uses IndexedDbStorage for WASM
type AppStateType = AppState<ClassicSuiteProvider, IndexedDbStorage>;
type AppStateArc = Arc<Mutex<AppStateType>>;
type AppStateMap = HashMap<String, AppStateArc>;

// Global storage for AppState instances
// Key: state_id (String), Value: Arc<Mutex<AppState<ClassicSuiteProvider, IndexedDbStorage>>>
thread_local! {
    static APP_STATES: std::cell::RefCell<AppStateMap> =
        std::cell::RefCell::new(AppStateMap::new());
}

/// Create a new AppState instance and return its ID
///
/// # Parameters
/// - `server_url`: URL of the REST API server (e.g., "https://api.construct.net")
#[wasm_bindgen]
pub async fn create_app_state(server_url: String) -> Result<String, JsValue> {
    let state = AppStateType::new(server_url)
        .await
        .map_err(|e| JsValue::from_str(&format!("Failed to create app state: {}", e)))?;

    let state_id = uuid::Uuid::new_v4().to_string();
    let state_arc: AppStateArc = Arc::new(Mutex::new(state));

    APP_STATES.with(|states: &std::cell::RefCell<AppStateMap>| {
        states.borrow_mut().insert(state_id.clone(), state_arc);
    });

    Ok(state_id)
}

/// Destroy an AppState instance
#[wasm_bindgen]
pub fn destroy_app_state(state_id: String) {
    APP_STATES.with(|states: &std::cell::RefCell<AppStateMap>| {
        states.borrow_mut().remove(&state_id);
    });
}

fn get_app_state(state_id: &str) -> Result<AppStateArc, JsValue> {
    APP_STATES.with(|states: &std::cell::RefCell<AppStateMap>| {
        states
            .borrow()
            .get(state_id)
            .cloned()
            .ok_or_else(|| JsValue::from_str(&format!("AppState {} not found", state_id)))
    })
}

/// Register a new user via REST API
///
/// # Parameters
/// - `state_id`: AppState instance ID
/// - `username`: Username for the new account
/// - `password`: Password (will be validated and used for key derivation)
///
/// # Returns
/// - `Ok(user_id)`: Registration successful, returns the assigned user ID
/// - `Err(JsValue)`: Registration failed with error message
#[wasm_bindgen]
pub async fn app_state_register(
    state_id: String,
    username: String,
    password: String,
) -> Result<String, JsValue> {
    let state_arc = get_app_state(&state_id)?;
    let mut state = state_arc
        .lock()
        .map_err(|e| JsValue::from_str(&format!("Failed to lock state: {}", e)))?;

    state
        .register(username, password)
        .await
        .map_err(|e| JsValue::from_str(&format!("Failed to register: {}", e)))?;

    // Return the user_id after successful registration
    state
        .get_user_id()
        .ok_or_else(|| JsValue::from_str("Registration succeeded but user_id is missing"))
        .map(|s| s.to_string())
}

/// Login an existing user via REST API
///
/// # Parameters
/// - `state_id`: AppState instance ID
/// - `username`: Username
/// - `password`: Password
///
/// # Returns
/// - `Ok(())`: Login successful
/// - `Err(JsValue)`: Login failed with error message
#[wasm_bindgen]
pub async fn app_state_login(
    state_id: String,
    username: String,
    password: String,
) -> Result<(), JsValue> {
    let state_arc = get_app_state(&state_id)?;
    let mut state = state_arc
        .lock()
        .map_err(|e| JsValue::from_str(&format!("Failed to lock state: {}", e)))?;

    state
        .login(username, password)
        .await
        .map_err(|e| JsValue::from_str(&format!("Failed to login: {}", e)))?;

    Ok(())
}

/// Logout the current user
///
/// # Parameters
/// - `state_id`: AppState instance ID
///
/// # Returns
/// - `Ok(())`: Logout successful
/// - `Err(JsValue)`: Logout failed with error message
#[wasm_bindgen]
pub async fn app_state_logout(state_id: String) -> Result<(), JsValue> {
    let state_arc = get_app_state(&state_id)?;
    let mut state = state_arc
        .lock()
        .map_err(|e| JsValue::from_str(&format!("Failed to lock state: {}", e)))?;

    state
        .logout()
        .await
        .map_err(|e| JsValue::from_str(&format!("Failed to logout: {}", e)))?;

    Ok(())
}

/// Get current user ID
#[wasm_bindgen]
pub fn app_state_get_user_id(state_id: String) -> Option<String> {
    let state_arc = get_app_state(&state_id).ok()?;
    let state = state_arc.lock().ok()?;
    state.get_user_id().map(|s: &str| s.to_string())
}

/// Get current username
#[wasm_bindgen]
pub fn app_state_get_username(state_id: String) -> Option<String> {
    let state_arc = get_app_state(&state_id).ok()?;
    let state = state_arc.lock().ok()?;
    state.get_username().map(|s: &str| s.to_string())
}

/// Add a contact
#[wasm_bindgen]
pub async fn app_state_add_contact(
    state_id: String,
    contact_id: String,
    username: String,
) -> Result<(), JsValue> {
    let state_arc = get_app_state(&state_id)?;
    let mut state = state_arc
        .lock()
        .map_err(|e| JsValue::from_str(&format!("Failed to lock state: {}", e)))?;

    state
        .add_contact(contact_id, username)
        .await
        .map_err(|e| JsValue::from_str(&format!("Failed to add contact: {}", e)))?;

    Ok(())
}

/// Get all contacts
#[wasm_bindgen]
pub fn app_state_get_contacts(state_id: String) -> Result<JsValue, JsValue> {
    let state_arc = get_app_state(&state_id)?;
    let state = state_arc
        .lock()
        .map_err(|e| JsValue::from_str(&format!("Failed to lock state: {}", e)))?;

    let contacts = state.get_contacts();
    serde_wasm_bindgen::to_value(&contacts)
        .map_err(|e| JsValue::from_str(&format!("Failed to serialize contacts: {}", e)))
}

/// Send a message via REST API
///
/// # Parameters
/// - `state_id`: AppState instance ID
/// - `to_contact_id`: Recipient's user ID
/// - `text`: Plain text message content
///
/// # Returns
/// - `Ok(message_id)`: Message sent successfully, returns message ID
/// - `Err(JsValue)`: Failed to send message
#[wasm_bindgen]
pub async fn app_state_send_message(
    state_id: String,
    to_contact_id: String,
    text: String,
) -> Result<String, JsValue> {
    let state_arc = get_app_state(&state_id)?;
    let mut state = state_arc
        .lock()
        .map_err(|e| JsValue::from_str(&format!("Failed to lock state: {}", e)))?;

    let message_id = state
        .send_message(&to_contact_id, &text)
        .await
        .map_err(|e| JsValue::from_str(&format!("Failed to send message: {}", e)))?;

    Ok(message_id)
}

/// Start long polling for incoming messages
///
/// # Parameters
/// - `state_id`: AppState instance ID
///
/// # Returns
/// - `Ok(())`: Long polling started successfully
/// - `Err(JsValue)`: Failed to start long polling
#[wasm_bindgen]
pub async fn app_state_start_polling(state_id: String) -> Result<(), JsValue> {
    let state_arc = get_app_state(&state_id)?;
    let mut state = state_arc
        .lock()
        .map_err(|e| JsValue::from_str(&format!("Failed to lock state: {}", e)))?;

    state
        .start_polling()
        .await
        .map_err(|e| JsValue::from_str(&format!("Failed to start polling: {}", e)))?;

    Ok(())
}

/// Stop long polling for incoming messages
///
/// # Parameters
/// - `state_id`: AppState instance ID
#[wasm_bindgen]
pub fn app_state_stop_polling(state_id: String) -> Result<(), JsValue> {
    let state_arc = get_app_state(&state_id)?;
    let mut state = state_arc
        .lock()
        .map_err(|e| JsValue::from_str(&format!("Failed to lock state: {}", e)))?;

    state.stop_polling();

    Ok(())
}

/// Check if long polling is active
///
/// # Parameters
/// - `state_id`: AppState instance ID
///
/// # Returns
/// - `true` if polling is active, `false` otherwise
#[wasm_bindgen]
pub fn app_state_is_polling(state_id: String) -> bool {
    let state_arc = match get_app_state(&state_id) {
        Ok(arc) => arc,
        Err(_) => return false,
    };

    let state = match state_arc.lock() {
        Ok(s) => s,
        Err(_) => return false,
    };

    state.is_polling_active()
}

// Console logging module for WASM
pub mod console {
    use web_sys;

    pub fn log(msg: &str) {
        web_sys::console::log_1(&msg.into());
    }
}
