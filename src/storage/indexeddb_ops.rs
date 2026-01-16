// Базовые операции для IndexedDB
//
// Этот модуль содержит низкоуровневые функции для работы с IndexedDB,
// которые используются как в IndexedDbStorage, так и в trait реализациях.
//
// Выделение общей логики решает проблему циклических зависимостей.

#[cfg(target_arch = "wasm32")]
use crate::utils::error::{ConstructError, Result};

#[cfg(target_arch = "wasm32")]
use wasm_bindgen::prelude::*;
#[cfg(target_arch = "wasm32")]
use wasm_bindgen::JsCast;
#[cfg(target_arch = "wasm32")]
use wasm_bindgen_futures::JsFuture;
#[cfg(target_arch = "wasm32")]
use web_sys::{IdbDatabase, IdbRequest, IdbTransactionMode};

// ============================================================================
// Core Operations
// ============================================================================

/// Поместить значение в object store
#[cfg(target_arch = "wasm32")]
pub async fn put_value(db: &IdbDatabase, store_name: &str, value: &JsValue) -> Result<()> {
    let transaction = db
        .transaction_with_str_and_mode(store_name, IdbTransactionMode::Readwrite)
        .map_err(|e| {
            ConstructError::StorageError(format!("Failed to create transaction: {:?}", e))
        })?;

    let store = transaction
        .object_store(store_name)
        .map_err(|e| ConstructError::StorageError(format!("Failed to get store: {:?}", e)))?;

    let request = store
        .put(value)
        .map_err(|e| ConstructError::StorageError(format!("Failed to put value: {:?}", e)))?;

    let promise = idb_request_to_promise(&request);
    JsFuture::from(promise)
        .await
        .map_err(|e| ConstructError::StorageError(format!("Put operation failed: {:?}", e)))?;

    Ok(())
}

/// Получить значение из object store по ключу
#[cfg(target_arch = "wasm32")]
pub async fn get_value(
    db: &IdbDatabase,
    store_name: &str,
    key: &JsValue,
) -> Result<Option<JsValue>> {
    let transaction = db.transaction_with_str(store_name).map_err(|e| {
        ConstructError::StorageError(format!("Failed to create transaction: {:?}", e))
    })?;

    let store = transaction
        .object_store(store_name)
        .map_err(|e| ConstructError::StorageError(format!("Failed to get store: {:?}", e)))?;

    let request = store
        .get(key)
        .map_err(|e| ConstructError::StorageError(format!("Failed to get value: {:?}", e)))?;

    let promise = idb_request_to_promise(&request);
    let result = JsFuture::from(promise)
        .await
        .map_err(|e| ConstructError::StorageError(format!("Get operation failed: {:?}", e)))?;

    if result.is_null() || result.is_undefined() {
        Ok(None)
    } else {
        Ok(Some(result))
    }
}

/// Получить все значения из object store
#[cfg(target_arch = "wasm32")]
pub async fn get_all_values(db: &IdbDatabase, store_name: &str) -> Result<Vec<JsValue>> {
    let transaction = db.transaction_with_str(store_name).map_err(|e| {
        ConstructError::StorageError(format!("Failed to create transaction: {:?}", e))
    })?;

    let store = transaction
        .object_store(store_name)
        .map_err(|e| ConstructError::StorageError(format!("Failed to get store: {:?}", e)))?;

    let request = store
        .get_all()
        .map_err(|e| ConstructError::StorageError(format!("Failed to get all: {:?}", e)))?;

    let promise = idb_request_to_promise(&request);
    let result = JsFuture::from(promise).await.map_err(|e| {
        ConstructError::StorageError(format!("GetAll operation failed: {:?}", e))
    })?;

    let array: js_sys::Array = result
        .dyn_into()
        .map_err(|_| ConstructError::StorageError("Invalid array result".to_string()))?;

    Ok(array.iter().collect())
}

/// Удалить значение из object store
#[cfg(target_arch = "wasm32")]
pub async fn delete_value(db: &IdbDatabase, store_name: &str, key: &JsValue) -> Result<()> {
    let transaction = db
        .transaction_with_str_and_mode(store_name, IdbTransactionMode::Readwrite)
        .map_err(|e| {
            ConstructError::StorageError(format!("Failed to create transaction: {:?}", e))
        })?;

    let store = transaction
        .object_store(store_name)
        .map_err(|e| ConstructError::StorageError(format!("Failed to get store: {:?}", e)))?;

    let request = store
        .delete(key)
        .map_err(|e| ConstructError::StorageError(format!("Failed to delete: {:?}", e)))?;

    let promise = idb_request_to_promise(&request);
    JsFuture::from(promise).await.map_err(|e| {
        ConstructError::StorageError(format!("Delete operation failed: {:?}", e))
    })?;

    Ok(())
}

/// Получить значения по индексу
#[cfg(target_arch = "wasm32")]
pub async fn get_by_index(
    db: &IdbDatabase,
    store_name: &str,
    index_name: &str,
    key: &JsValue,
) -> Result<Option<JsValue>> {
    let transaction = db.transaction_with_str(store_name).map_err(|e| {
        ConstructError::StorageError(format!("Failed to create transaction: {:?}", e))
    })?;

    let store = transaction
        .object_store(store_name)
        .map_err(|e| ConstructError::StorageError(format!("Failed to get store: {:?}", e)))?;

    let index = store
        .index(index_name)
        .map_err(|e| ConstructError::StorageError(format!("Failed to get index: {:?}", e)))?;

    let request = index
        .get(key)
        .map_err(|e| ConstructError::StorageError(format!("Failed to get by index: {:?}", e)))?;

    let promise = idb_request_to_promise(&request);
    let result = JsFuture::from(promise).await.map_err(|e| {
        ConstructError::StorageError(format!("Get by index failed: {:?}", e))
    })?;

    if result.is_null() || result.is_undefined() {
        Ok(None)
    } else {
        Ok(Some(result))
    }
}

/// Получить все значения по индексу
#[cfg(target_arch = "wasm32")]
pub async fn get_all_by_index(
    db: &IdbDatabase,
    store_name: &str,
    index_name: &str,
    key: &JsValue,
) -> Result<Vec<JsValue>> {
    let transaction = db.transaction_with_str(store_name).map_err(|e| {
        ConstructError::StorageError(format!("Failed to create transaction: {:?}", e))
    })?;

    let store = transaction
        .object_store(store_name)
        .map_err(|e| ConstructError::StorageError(format!("Failed to get store: {:?}", e)))?;

    let index = store
        .index(index_name)
        .map_err(|e| ConstructError::StorageError(format!("Failed to get index: {:?}", e)))?;

    let request = index
        .get_all_with_key(key)
        .map_err(|e| ConstructError::StorageError(format!("Failed to get all by index: {:?}", e)))?;

    let promise = idb_request_to_promise(&request);
    let result = JsFuture::from(promise).await.map_err(|e| {
        ConstructError::StorageError(format!("Get all by index failed: {:?}", e))
    })?;

    let array: js_sys::Array = result
        .dyn_into()
        .map_err(|_| ConstructError::StorageError("Invalid array result".to_string()))?;

    Ok(array.iter().collect())
}

// ============================================================================
// Promise Helpers
// ============================================================================

/// Конвертировать IdbRequest в Promise
#[cfg(target_arch = "wasm32")]
pub fn idb_request_to_promise(request: &IdbRequest) -> js_sys::Promise {
    js_sys::Promise::new(&mut |resolve, reject| {
        let onsuccess = Closure::wrap(Box::new(move |event: web_sys::Event| {
            let target = event.target().expect("Event target is missing");
            let req = target.dyn_into::<web_sys::IdbRequest>().unwrap();
            let result = req.result().unwrap();
            resolve.call1(&JsValue::NULL, &result).unwrap();
        }) as Box<dyn FnMut(_)>);

        let onerror = Closure::wrap(Box::new(move |_event: web_sys::Event| {
            _event.prevent_default();
            reject
                .call1(
                    &JsValue::NULL,
                    &JsValue::from_str("IndexedDB operation failed"),
                )
                .unwrap();
        }) as Box<dyn FnMut(_)>);

        request.set_onsuccess(Some(onsuccess.as_ref().unchecked_ref()));
        request.set_onerror(Some(onerror.as_ref().unchecked_ref()));

        onsuccess.forget();
        onerror.forget();
    })
}

/// Конвертировать IdbOpenDbRequest в Promise
#[cfg(target_arch = "wasm32")]
pub fn idb_open_request_to_promise(request: &web_sys::IdbOpenDbRequest) -> js_sys::Promise {
    idb_request_to_promise(request)
}

// ============================================================================
// Serialization Helpers
// ============================================================================

/// Сериализовать значение в JsValue
#[cfg(target_arch = "wasm32")]
pub fn serialize_to_jsvalue<T: serde::Serialize>(value: &T) -> Result<JsValue> {
    serde_wasm_bindgen::to_value(value).map_err(|e| {
        ConstructError::SerializationError(format!("Failed to serialize: {:?}", e))
    })
}

/// Десериализовать JsValue в тип
#[cfg(target_arch = "wasm32")]
pub fn deserialize_from_jsvalue<T: serde::de::DeserializeOwned>(value: JsValue) -> Result<T> {
    serde_wasm_bindgen::from_value(value).map_err(|e| {
        ConstructError::SerializationError(format!("Failed to deserialize: {:?}", e))
    })
}

// ============================================================================
// Typed Operations (удобные обёртки)
// ============================================================================

/// Поместить типизированное значение
#[cfg(target_arch = "wasm32")]
pub async fn put_typed<T: serde::Serialize>(
    db: &IdbDatabase,
    store_name: &str,
    value: &T,
) -> Result<()> {
    let js_value = serialize_to_jsvalue(value)?;
    put_value(db, store_name, &js_value).await
}

/// Получить типизированное значение
#[cfg(target_arch = "wasm32")]
pub async fn get_typed<T: serde::de::DeserializeOwned>(
    db: &IdbDatabase,
    store_name: &str,
    key: &str,
) -> Result<Option<T>> {
    let key_js = JsValue::from_str(key);
    match get_value(db, store_name, &key_js).await? {
        Some(value) => Ok(Some(deserialize_from_jsvalue(value)?)),
        None => Ok(None),
    }
}

/// Получить все типизированные значения
#[cfg(target_arch = "wasm32")]
pub async fn get_all_typed<T: serde::de::DeserializeOwned>(
    db: &IdbDatabase,
    store_name: &str,
) -> Result<Vec<T>> {
    let values = get_all_values(db, store_name).await?;

    let mut results = Vec::new();
    for value in values {
        results.push(deserialize_from_jsvalue(value)?);
    }

    Ok(results)
}

/// Удалить по строковому ключу
#[cfg(target_arch = "wasm32")]
pub async fn delete_by_key(db: &IdbDatabase, store_name: &str, key: &str) -> Result<()> {
    let key_js = JsValue::from_str(key);
    delete_value(db, store_name, &key_js).await
}

/// Получить типизированное значение по индексу
#[cfg(target_arch = "wasm32")]
pub async fn get_typed_by_index<T: serde::de::DeserializeOwned>(
    db: &IdbDatabase,
    store_name: &str,
    index_name: &str,
    key: &str,
) -> Result<Option<T>> {
    let key_js = JsValue::from_str(key);
    match get_by_index(db, store_name, index_name, &key_js).await? {
        Some(value) => Ok(Some(deserialize_from_jsvalue(value)?)),
        None => Ok(None),
    }
}

/// Получить все типизированные значения по индексу
#[cfg(target_arch = "wasm32")]
pub async fn get_all_typed_by_index<T: serde::de::DeserializeOwned>(
    db: &IdbDatabase,
    store_name: &str,
    index_name: &str,
    key: &str,
) -> Result<Vec<T>> {
    let key_js = JsValue::from_str(key);
    let values = get_all_by_index(db, store_name, index_name, &key_js).await?;

    let mut results = Vec::new();
    for value in values {
        results.push(deserialize_from_jsvalue(value)?);
    }

    Ok(results)
}

#[cfg(test)]
mod tests {
    // Тесты требуют wasm-bindgen-test
    // Можно добавить позже
}
