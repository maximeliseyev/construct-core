// WASM bindings
// wasm-bindgen automatically generates bindings from #[wasm_bindgen] attributes

use crate::crypto::suites::classic::ClassicSuiteProvider;
use crate::state::app::AppState;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use wasm_bindgen::prelude::*;

// Type alias for convenience
type AppStateType = AppState<ClassicSuiteProvider>;
type AppStateArc = Arc<Mutex<AppStateType>>;
type AppStateMap = HashMap<String, AppStateArc>;

// Global storage for AppState instances
// Key: state_id (String), Value: Arc<Mutex<AppState<ClassicSuiteProvider>>>
thread_local! {
    static APP_STATES: std::cell::RefCell<AppStateMap> =
        std::cell::RefCell::new(AppStateMap::new());
}

/// Create a new AppState instance and return its ID
#[wasm_bindgen]
pub async fn create_app_state(_db_name: String) -> Result<String, JsValue> {
    let state: AppStateType = AppState::<ClassicSuiteProvider>::new()
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

/// Initialize a new user (create keys, don't save yet)
#[wasm_bindgen]
pub async fn app_state_initialize_user(
    state_id: String,
    username: String,
    password: String,
) -> Result<(), JsValue> {
    let state_arc = get_app_state(&state_id)?;
    let mut state = state_arc
        .lock()
        .map_err(|e| JsValue::from_str(&format!("Failed to lock state: {}", e)))?;

    state
        .initialize_user(username, password)
        .await
        .map_err(|e| JsValue::from_str(&format!("Failed to initialize user: {}", e)))?;

    Ok(())
}

/// Load an existing user
#[wasm_bindgen]
pub async fn app_state_load_user(
    state_id: String,
    user_id: String,
    password: String,
) -> Result<(), JsValue> {
    let state_arc = get_app_state(&state_id)?;
    let mut state = state_arc
        .lock()
        .map_err(|e| JsValue::from_str(&format!("Failed to lock state: {}", e)))?;

    state
        .load_user(user_id, password)
        .await
        .map_err(|e| JsValue::from_str(&format!("Failed to load user: {}", e)))?;

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

/// Send a message
#[wasm_bindgen]
pub async fn app_state_send_message(
    state_id: String,
    to_contact_id: String,
    session_id: String,
    text: String,
) -> Result<String, JsValue> {
    let state_arc = get_app_state(&state_id)?;
    let mut state = state_arc
        .lock()
        .map_err(|e| JsValue::from_str(&format!("Failed to lock state: {}", e)))?;

    let message_id = state
        .send_message(&to_contact_id, &session_id, &text)
        .await
        .map_err(|e| JsValue::from_str(&format!("Failed to send message: {}", e)))?;

    Ok(message_id)
}

/// Load conversation messages
#[wasm_bindgen]
pub async fn app_state_load_conversation(
    state_id: String,
    contact_id: String,
) -> Result<JsValue, JsValue> {
    let state_arc = get_app_state(&state_id)?;
    let mut state = state_arc
        .lock()
        .map_err(|e| JsValue::from_str(&format!("Failed to lock state: {}", e)))?;

    let messages = state
        .load_conversation(&contact_id)
        .await
        .map_err(|e| JsValue::from_str(&format!("Failed to load conversation: {}", e)))?;

    serde_wasm_bindgen::to_value(&messages)
        .map_err(|e| JsValue::from_str(&format!("Failed to serialize messages: {}", e)))
}

/// Get connection state
#[wasm_bindgen]
pub fn app_state_connection_state(state_id: String) -> String {
    let state_arc = match get_app_state(&state_id) {
        Ok(arc) => arc,
        Err(_) => return "error".to_string(),
    };

    let state: std::sync::MutexGuard<'_, AppStateType> = match state_arc.lock() {
        Ok(s) => s,
        Err(_) => return "error".to_string(),
    };

    match state.connection_state() {
        crate::state::app::ConnectionState::Disconnected => "disconnected",
        crate::state::app::ConnectionState::Connecting => "connecting",
        crate::state::app::ConnectionState::Connected => "connected",
        crate::state::app::ConnectionState::Reconnecting => "reconnecting",
        crate::state::app::ConnectionState::Error => "error",
    }
    .to_string()
}

/// Connect to server
#[wasm_bindgen]
pub fn app_state_connect(state_id: String, server_url: String) -> Result<(), JsValue> {
    let state_arc = get_app_state(&state_id)?;
    let mut state = state_arc
        .lock()
        .map_err(|e| JsValue::from_str(&format!("Failed to lock state: {}", e)))?;

    state
        .connect(&server_url)
        .map_err(|e| JsValue::from_str(&format!("Failed to connect: {}", e)))?;

    Ok(())
}

/// Disconnect from server
#[wasm_bindgen]
pub fn app_state_disconnect(state_id: String) -> Result<(), JsValue> {
    let state_arc = get_app_state(&state_id)?;
    let mut state = state_arc
        .lock()
        .map_err(|e| JsValue::from_str(&format!("Failed to lock state: {}", e)))?;

    state
        .disconnect()
        .map_err(|e| JsValue::from_str(&format!("Failed to disconnect: {}", e)))?;

    Ok(())
}

/// Register on server
#[wasm_bindgen]
pub fn app_state_register_on_server(state_id: String, password: String) -> Result<(), JsValue> {
    let state_arc = get_app_state(&state_id)?;
    let state = state_arc
        .lock()
        .map_err(|e| JsValue::from_str(&format!("Failed to lock state: {}", e)))?;

    state
        .register_on_server(password)
        .map_err(|e| JsValue::from_str(&format!("Failed to register: {}", e)))?;

    Ok(())
}

/// Finalize registration
#[wasm_bindgen]
pub async fn app_state_finalize_registration(
    state_id: String,
    user_id: String,
    session_token: String,
    password: String,
) -> Result<(), JsValue> {
    let state_arc = get_app_state(&state_id)?;
    let mut state = state_arc
        .lock()
        .map_err(|e| JsValue::from_str(&format!("Failed to lock state: {}", e)))?;

    state
        .finalize_registration(user_id, session_token, password)
        .await
        .map_err(|e| JsValue::from_str(&format!("Failed to finalize registration: {}", e)))?;

    Ok(())
}

// Console logging module for WASM
pub mod console {
    use web_sys;

    pub fn log(msg: &str) {
        web_sys::console::log_1(&msg.into());
    }
}
