// Время и таймеры

/// Получить текущее время в секундах с UNIX epoch (u64)
pub fn now() -> u64 {
    #[cfg(target_arch = "wasm32")]
    {
        (js_sys::Date::now() / 1000.0) as u64
    }

    #[cfg(not(target_arch = "wasm32"))]
    {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
    }
}

/// Получить текущий timestamp в секундах с UNIX epoch (i64)
pub fn current_timestamp() -> i64 {
    #[cfg(target_arch = "wasm32")]
    {
        (js_sys::Date::now() / 1000.0) as i64
    }

    #[cfg(not(target_arch = "wasm32"))]
    {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64
    }
}

/// Получить текущее время в миллисекундах с UNIX epoch
pub fn current_timestamp_millis() -> i64 {
    #[cfg(target_arch = "wasm32")]
    {
        js_sys::Date::now() as i64
    }

    #[cfg(not(target_arch = "wasm32"))]
    {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as i64
    }
}

/// Получить текущий timestamp в ISO8601 формате с fractional seconds
/// Формат: "2026-01-13T07:22:06.209+00:00"
pub fn current_timestamp_iso8601() -> String {
    #[cfg(target_arch = "wasm32")]
    {
        // В WASM используем js_sys::Date для ISO8601
        let date = js_sys::Date::new_0();
        date.to_iso_string().as_string().unwrap_or_default()
    }

    #[cfg(not(target_arch = "wasm32"))]
    {
        // В non-WASM используем chrono
        use chrono::Utc;
        Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true)
    }
}
