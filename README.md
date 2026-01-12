# 🔐 Construct Core

**Core cryptographic engine for Construct Messenger with end-to-end encryption**

[![Rust](https://img.shields.io/badge/Rust-1.75+-orange.svg)](https://www.rust-lang.org/)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

## 🎯 About

Construct Core is the cryptographic engine powering Construct Messenger. It provides:

- ✅ **Double Ratchet Protocol** (Signal Protocol) for forward secrecy
- ✅ **X3DH** for asynchronous key agreement
- ✅ **Crypto-Agility** to support various cryptographic algorithms
- ✅ **Post-Quantum Ready** architecture for hybrid schemes
- ✅ **Multi-Platform** support (iOS via UniFFI, Web via WASM)

## 🏗️ Architecture

```
construct-core/
├── src/
│   ├── crypto/              # Cryptographic primitives
│   │   ├── handshake/        # X3DH key agreement
│   │   ├── messaging/        # Double Ratchet
│   │   ├── suites/           # Crypto suites (Classic, PQ-Hybrid)
│   │   └── provider.rs       # CryptoProvider trait
│   ├── api/                  # High-level API
│   ├── protocol/             # Protocol structures
│   ├── error.rs              # Error types
│   └── platforms/            # Platform-specific code
│       ├── ios/               # iOS bindings (UniFFI)
│       └── wasm/              # WASM bindings
└── Cargo.toml
```

## 🚀 Quick Start

### For iOS

```toml
[dependencies]
construct-core = { git = "https://github.com/your-org/construct-core", features = ["ios"] }
```

### For Web (WASM)

```toml
[dependencies]
construct-core = { git = "https://github.com/your-org/construct-core", features = ["wasm"] }
```

## 🔐 Cryptography

### Classic Suite (v1)

| Component     | Algorithm             |
|---------------|-----------------------|
| Key Agreement | X25519 (ECDH)        |
| Signatures    | Ed25519              |
| AEAD          | ChaCha20-Poly1305    |
| KDF           | HKDF-SHA256          |

### Post-Quantum Hybrid Suite (v2) - In Development

| Component     | Algorithm                |
|---------------|--------------------------|
| Key Agreement | X25519 ⊕ Kyber768        |
| Signatures    | Ed25519 + Dilithium3     |
| AEAD          | ChaCha20-Poly1305        |

## 📦 Features

- `ios` - iOS/macOS bindings via UniFFI
- `wasm` - WebAssembly bindings via wasm-bindgen
- `post-quantum` - Post-quantum cryptography support
- `desktop` - Desktop testing support (Tokio runtime)

## 🧪 Testing

```bash
cargo test --all-features
```

## 📄 License

MIT License - see [LICENSE](LICENSE) for details
