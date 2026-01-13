# GitHub Actions CI/CD для construct-core

## Рекомендации по настройке GitHub Actions

Для автоматической сборки библиотек для обеих платформ (iOS/Swift и Web/WASM) рекомендуется настроить GitHub Actions workflow.

## Структура workflow

### 1. Сборка WASM библиотеки

```yaml
name: Build WASM

on:
  push:
    branches: [ main, develop ]
  pull_request:
    branches: [ main, develop ]

jobs:
  build-wasm:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      
      - name: Install Rust
        uses: actions-rs/toolchain@v1
        with:
          toolchain: stable
          target: wasm32-unknown-unknown
          override: true
      
      - name: Install wasm-pack
        run: |
          curl https://rustwasm.github.io/wasm-pack/installer/init.sh -sSf | sh
      
      - name: Build WASM
        run: |
          wasm-pack build --target web --out-dir pkg --features wasm
      
      - name: Upload WASM artifacts
        uses: actions/upload-artifact@v3
        with:
          name: wasm-pkg
          path: pkg/
```

### 2. Сборка iOS/Swift библиотеки (UniFFI)

```yaml
name: Build iOS

on:
  push:
    branches: [ main, develop ]
  pull_request:
    branches: [ main, develop ]

jobs:
  build-ios:
    runs-on: macos-latest
    steps:
      - uses: actions/checkout@v4
      
      - name: Install Rust
        uses: actions-rs/toolchain@v1
        with:
          toolchain: stable
          override: true
      
      - name: Install UniFFI
        run: |
          cargo install --locked uniffi_bindgen
      
      - name: Build iOS framework
        run: |
          cargo build --release --features ios
          uniffi-bindgen generate src/construct_core.udl --language swift
      
      - name: Upload iOS artifacts
        uses: actions/upload-artifact@v3
        with:
          name: ios-bindings
          path: |
            bindings/ios/
            target/release/libconstruct_core.a
```

### 3. Комбинированный workflow (рекомендуется)

```yaml
name: CI

on:
  push:
    branches: [ main, develop ]
  pull_request:
    branches: [ main, develop ]
  release:
    types: [ created ]

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      
      - name: Install Rust
        uses: actions-rs/toolchain@v1
        with:
          toolchain: stable
          override: true
      
      - name: Run tests
        run: cargo test --features test

  build-wasm:
    runs-on: ubuntu-latest
    needs: test
    steps:
      - uses: actions/checkout@v4
      
      - name: Install Rust
        uses: actions-rs/toolchain@v1
        with:
          toolchain: stable
          target: wasm32-unknown-unknown
          override: true
      
      - name: Install wasm-pack
        run: |
          curl https://rustwasm.github.io/wasm-pack/installer/init.sh -sSf | sh
      
      - name: Build WASM
        run: |
          wasm-pack build --target web --out-dir pkg --features wasm
      
      - name: Upload WASM artifacts
        uses: actions/upload-artifact@v3
        with:
          name: wasm-pkg
          path: pkg/
          retention-days: 30

  build-ios:
    runs-on: macos-latest
    needs: test
    steps:
      - uses: actions/checkout@v4
      
      - name: Install Rust
        uses: actions-rs/toolchain@v1
        with:
          toolchain: stable
          override: true
      
      - name: Install UniFFI
        run: |
          cargo install --locked uniffi_bindgen
      
      - name: Build iOS framework
        run: |
          cargo build --release --features ios
          uniffi-bindgen generate src/construct_core.udl --language swift
      
      - name: Upload iOS artifacts
        uses: actions/upload-artifact@v3
        with:
          name: ios-bindings
          path: |
            bindings/ios/
            target/release/libconstruct_core.a
          retention-days: 30

  release:
    runs-on: ubuntu-latest
    needs: [build-wasm, build-ios]
    if: github.event_name == 'release'
    steps:
      - uses: actions/download-artifact@v3
        with:
          name: wasm-pkg
          path: release/wasm/
      
      - uses: actions/download-artifact@v3
        with:
          name: ios-bindings
          path: release/ios/
      
      - name: Create release archive
        run: |
          cd release
          tar -czf construct-core-wasm.tar.gz wasm/
          tar -czf construct-core-ios.tar.gz ios/
      
      - name: Upload to release
        uses: softprops/action-gh-release@v1
        with:
          files: |
            release/construct-core-wasm.tar.gz
            release/construct-core-ios.tar.gz
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
```

## Важные замечания

### 1. Версионирование

Рекомендуется использовать semantic versioning и автоматически создавать теги при релизах:

```yaml
- name: Create tag
  if: startsWith(github.ref, 'refs/tags/')
  run: |
    git tag -a ${{ github.ref_name }} -m "Release ${{ github.ref_name }}"
    git push origin ${{ github.ref_name }}
```

### 2. Кэширование зависимостей

Для ускорения сборки можно кэшировать Cargo dependencies:

```yaml
- name: Cache Cargo dependencies
  uses: actions/cache@v3
  with:
    path: |
      ~/.cargo/bin/
      ~/.cargo/registry/index/
      ~/.cargo/registry/cache/
      ~/.cargo/git/db/
      target/
    key: ${{ runner.os }}-cargo-${{ hashFiles('**/Cargo.lock') }}
```

### 3. Проверка безопасности

Добавьте проверку зависимостей:

```yaml
- name: Audit dependencies
  run: |
    cargo install cargo-audit
    cargo audit
```

### 4. Проверка формата кода

```yaml
- name: Check formatting
  run: cargo fmt -- --check

- name: Run clippy
  run: cargo clippy -- -D warnings
```

## Использование в проектах

### Web проект (construct-messenger-web)

```bash
# В package.json или build script
npm run build:wasm
# или использовать pre-built из GitHub releases
```

### iOS проект (construct-messenger)

```swift
// Использовать bindings из GitHub releases
// или клонировать репозиторий как git submodule
```

## Рекомендации

1. **Автоматическая сборка при каждом push** - для быстрого обнаружения проблем
2. **Артефакты хранить 30 дней** - для возможности отката
3. **Релизы создавать вручную** - для контроля версий
4. **Тесты запускать перед сборкой** - для гарантии качества
5. **Кэшировать зависимости** - для ускорения сборки
