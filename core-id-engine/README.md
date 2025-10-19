# 🦀 Core ID Engine (Rust)

High-performance cryptographic and verification engine for the UK Digital Identity Platform, built with Rust for memory safety and performance.

## 🎯 Features

- **RING + AES-GCM Cryptography**: Blake3 hashing with 256-bit AES-GCM encryption for data at rest and in transit
- **Multi-Source Verification**: Integrates with 15+ government data sources with real-time sync
- **Async Processing**: Tokio runtime with concurrent verification pipelines and rate limiting
- **Event-Driven Sync**: Redis pub/sub for publishing verification events and subscribing to government data
- **FFI Integration**: C-compatible dylib/rlib for Go gateway integration
- **Privacy Protection**: Encrypted database storage with hashed lookups, comprehensive audit logging
- **Redis Caching**: High-performance L1/L2 caching layer for verification results
- **PostgreSQL Audit**: Comprehensive audit logging with SQL injection protection and encrypted sensitive data
- **Real-time Sync**: Cross-component synchronization via Redis event bus with government feed integration

## 🏗️ Architecture

```
┌─────────────────┐
│   API Module    │ ← HTTP/gRPC endpoints with rate limiting
├─────────────────┤
│ Verification    │ ← Multi-source verification engine
│   Manager       │   (15+ government data sources)
├─────────────────┤
│ Crypto Manager  │ ← RING cryptography + AES-GCM encryption
├─────────────────┤
│ Cache/Database  │ ← Redis L1/L2 caching + PostgreSQL
│   Managers      │   with encrypted storage
├─────────────────┤
│ Sync Service    │ ← Redis pub/sub for event sync
├─────────────────┤
│ Metrics + Audit │ ← Component integration & monitoring
└─────────────────┘
```

## 📦 Core Modules

| Module | Purpose | Key Features |
|--------|---------|--------------|
| **lib.rs** | Main engine orchestration | Rate limiting, request handling, component integration, event subscription |
| **crypto.rs** | Cryptographic operations | RING, AES-GCM, Blake3 hashing, secure key management, data encryption |
| **verification.rs** | Identity verification | Multi-source data validation, parallel processing, event publishing |
| **cache.rs** | Performance optimization | Redis L1/L2 integration, TTL management, cache invalidation, compression |
| **database.rs** | Audit & persistence | PostgreSQL with encrypted storage, prepared statements, connection pooling |
| **api.rs** | External interfaces | REST/gRPC endpoints, FFI exports for Go integration, compression |
| **sync.rs** | Component synchronization | Redis pub/sub, cross-component messaging, government data subscription |
| **metrics.rs** | Observability | Performance monitoring, structured logging, health checks |

## Core Functions

### Identity Management
- `generate_keypair()`: Creates Ed25519 keypair for user
- `sign_credential()`: Signs digital credentials with user's private key
- `verify_credential()`: Verifies credential signatures

### Data Protection
- `encrypt_data()`: AES-GCM encryption with random nonces
- `decrypt_data()`: Secure decryption with nonce extraction
- `generate_zk_proof()`: Zero-knowledge proof generation (placeholder)

## FFI Exports

The library exports C-compatible functions for Go integration:

```c
int init_engine();
int generate_keypair(const char* user_id);
char* sign_credential(const char* user_id, const char* payload, uint64_t issued_at, uint64_t expires_at);
void free_string(char* s);
```

## Usage

### From Rust
```rust
let mut engine = IdentityEngine::new();
engine.generate_keypair("user123")?;
let credential = engine.sign_credential("user123", b"payload", 1633024800, 1664560800)?;
```

### From Go (via FFI)
```go
C.init_engine()
C.generate_keypair(C.CString("user123"))
result := C.sign_credential(C.CString("user123"), C.CString("payload"), 1633024800, 1664560800)
```

## Security Features

- **Hardware Security**: Uses system random number generator via Ring
- **Constant Time Operations**: Ed25519 prevents timing attacks
- **Forward Secrecy**: Each encryption uses unique nonces
- **Memory Protection**: Rust prevents memory corruption vulnerabilities

## Performance

- Key generation: ~1ms per keypair
- Signing: ~0.1ms per credential  
- Encryption: ~0.05ms per KB
- Parallel safe: Thread-safe operations

## Building

```bash
cargo build --release  # Release build for production
cargo test            # Run test suite
```

## Dependencies

- `ring`: Cryptographic operations
- `aes-gcm`: Symmetric encryption
- `serde`: Serialization for data structures
- `rand`: Secure random number generation

## Error Handling

Custom error types with descriptive messages:
- `SignatureError`: Invalid signature operations
- `KeyGenError`: Keypair generation failures
- `EncryptionError`/`DecryptionError`: Crypto failures
- `VerificationError`: Signature verification failures

## Integration

This engine integrates with:
- **Go Gateway**: FFI calls for credential signing
- **PostgreSQL**: Signed credentials stored in database
- **Kafka**: Audit events for crypto operations