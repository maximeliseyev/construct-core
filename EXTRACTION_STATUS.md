# Статус экстракции ядра

## ✅ Выполнено

1. Создана базовая структура репозитория
2. Создан Cargo.toml с feature flags (ios, wasm, post-quantum)
3. Создан README.md
4. Создан .gitignore
5. Создана структура директорий:
   - `src/crypto/`
   - `src/api/`
   - `src/protocol/`
   - `src/utils/`
   - `src/platforms/ios/`
   - `src/platforms/wasm/`
6. Создан `src/lib.rs` с условной компиляцией
7. Создан `src/error.rs`
8. Созданы модули для платформ

## 📋 Следующие шаги

### 1. Копирование файлов

Нужно скопировать следующие директории из `construct-messenger/packages/core/src/`:

- `crypto/` → `src/crypto/` (все файлы)
- `api/` → `src/api/` (все файлы)
- `protocol/` → `src/protocol/` (все файлы, кроме transport.rs для WASM)
- `utils/` → `src/utils/` (все файлы)
- `config.rs` → `src/config.rs`

### 2. Платформо-специфичный код

- `uniffi_bindings.rs` → `src/platforms/ios/uniffi_bindings.rs`
- `construct_core.udl` → `src/platforms/ios/construct_core.udl`
- WASM-специфичный код → `src/platforms/wasm/`

### 3. Обновление импортов

- Обновить все `use crate::` пути
- Обновить условную компиляцию `#[cfg(not(target_arch = "wasm32"))]` → `#[cfg(feature = "ios")]`
- Обновить `#[cfg(target_arch = "wasm32")]` → `#[cfg(feature = "wasm")]`

### 4. Тестирование

- Проверить компиляцию для iOS: `cargo build --target aarch64-apple-ios --features ios`
- Проверить компиляцию для WASM: `cargo build --target wasm32-unknown-unknown --features wasm`

### 5. Интеграция в iOS проект

- Обновить `construct-messenger/Cargo.toml` для использования git dependency
- Обновить `generate_swift_bindings.sh`

## 📝 Команды для копирования

```bash
# Из директории construct-messenger
cd /Users/maximeliseyev/Code/construct-messenger

# Копировать основные модули
cp -r packages/core/src/crypto ../construct-core/src/
cp -r packages/core/src/api ../construct-core/src/
cp -r packages/core/src/protocol ../construct-core/src/
cp -r packages/core/src/utils ../construct-core/src/
cp packages/core/src/config.rs ../construct-core/src/

# Копировать iOS-специфичный код
cp packages/core/src/uniffi_bindings.rs ../construct-core/src/platforms/ios/
cp packages/core/src/construct_core.udl ../construct-core/src/platforms/ios/

# Копировать build.rs и скрипты
cp packages/core/build.rs ../construct-core/
cp packages/core/patch_uniffi_unsafe.sh ../construct-core/
```

## ⚠️ Важные замечания

1. **Не копировать:**
   - `storage/` - платформо-специфичный, будет реализован отдельно
   - `state/` - платформо-специфичный
   - `traffic_protection/` - можно добавить позже

2. **Нужно обновить:**
   - Все пути импортов
   - Условную компиляцию
   - Cargo.toml зависимости (если нужно)
