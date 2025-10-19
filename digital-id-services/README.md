# 🚀 Digital ID Services (Go)

High-performance microservices suite providing comprehensive API gateway and identity management for the UK Digital Identity Platform.

## 🎯 Features

- **Gin Web Framework**: HTTP/2 API gateway with JWT authentication, bcrypt hashing, and AES encryption
- **Microservices Architecture**: Separate services for Gateway, Registration, Verification, Credential, Audit with event sync
- **Rate Limiting**: 100 req/min token bucket algorithm with Redis backend and distributed caching
- **Event-Driven Sync**: Redis pub/sub for cross-system synchronization and government data subscription
- **Enterprise Integrations**: GORM PostgreSQL, Kafka streaming, Redis caching, Elasticsearch logging
- **CGO Integration**: Direct FFI calls to Rust core engine for cryptographic operations
- **Privacy Protection**: AES encryption for sensitive data, secure password hashing, encrypted storage
- **Observability**: Prometheus metrics, Jaeger tracing, structured JSON logging with Zap
- **Security**: CORS, input validation, JWT middleware, circuit breakers with Hystrix, encrypted communication

## 🏗️ Microservices Architecture

```
┌──────────────┐    ┌─────────────────┐    ┌─────────────────┐
│ Web/Mobile   │───▶│   API Gateway   │───▶│   PostgreSQL    │
│ Clients      │    │   (Port 8081)   │    │   + GORM ORM    │
└──────────────┘    └─────────────────┘    └─────────────────┘
                            │
        ┌───────────────────┼───────────────────┐
        │                   │                   │
┌───────▼────────┐ ┌───────▼────────┐ ┌───────▼────────┐
│ Registration   │ │ Verification   │ │  Credential    │
│  Service       │ │    Service     │ │   Service      │ 
│ (Port 8082)    │ │ (Port 8083)    │ │ (Port 8084)    │
└────────────────┘ └────────────────┘ └────────────────┘
        │                   │                   │
        └───────────────────┼───────────────────┘
                            │
    ┌───────────────────────┼───────────────────────┐
    │                       │                       │
┌───▼────┐       ┌─────────▼──────────┐      ┌─────▼──────┐
│ Redis  │       │   Rust Core FFI    │      │   Kafka    │
│ Pub/Sub│       │  (Crypto Engine)   │      │   Streams  │
└────────┘       └────────────────────┘      └────────────┘
```

## 📦 Service Components

| Service | Port | Purpose | Key Dependencies |
|---------|------|---------|------------------|
| **API Gateway** | 8081 | Request routing, auth, rate limiting, event sync | Gin, JWT, CORS, Prometheus, Redis |
| **Registration** | 8082 | User onboarding, document validation, event publishing | GORM, Validator, Kafka, Redis |
| **Verification** | 8083 | Identity verification, government APIs, data subscription | WebClient, Circuit Breaker, Redis |
| **Credential** | 8084 | Digital credential issuance/management, encrypted storage | FFI to Rust, Redis cache, AES |
| **Audit** | 8085 | Compliance logging, event streaming, government sync | Kafka producer, Elasticsearch, Redis |

## API Endpoints

### Authentication
- `POST /register` - User registration with automatic keypair generation
- `POST /login` - JWT token generation with credential validation

### Credentials  
- `POST /verify` - Identity verification with HMRC eligibility check
- `POST /issue-credential` - Digital credential issuance with Rust signing
- `GET /credential/:id` - Credential retrieval with ownership validation

### Health
- `GET /health` - Service health check

## Data Models

### User
```go
type User struct {
    ID        uint      `json:"id" gorm:"primaryKey"`
    Name      string    `json:"name" validate:"required,min=2,max=50"`
    Email     string    `json:"email" gorm:"unique" validate:"required,email"`
    Password  string    `json:"-" validate:"required,min=8"`
    PublicKey string    `json:"public_key"`
    CreatedAt time.Time
}
```

### Credential
```go
type Credential struct {
    ID        uint   `json:"id" gorm:"primaryKey"`
    UserID    uint   `json:"user_id"`
    Payload   string `json:"payload"`
    Signature string `json:"signature"`
    IssuedAt  int64  `json:"issued_at"`
    ExpiresAt int64  `json:"expires_at"`
}
```

## Security Features

- **Password Hashing**: bcrypt with default cost (10 rounds)
- **JWT Signing**: HS256 with configurable secret
- **Input Validation**: Comprehensive validation with go-playground/validator
- **Rate Limiting**: Token bucket algorithm (100 req/min)
- **CORS Protection**: Restricted origins for web portals
- **Auth Middleware**: JWT verification on protected endpoints

## Performance Optimizations

- **Connection Pooling**: PostgreSQL connection reuse via GORM
- **Async Kafka**: Non-blocking audit event publishing
- **FFI Integration**: Direct Rust calls for crypto operations
- **Timeout Handling**: 5-second timeouts for external calls
- **Structured Logging**: JSON logs for efficient parsing

## Environment Configuration

```bash
DATABASE_URL=host=postgres user=user password=password dbname=digital_id port=5432 sslmode=disable
JWT_SECRET=your-secure-jwt-secret-key
```

## Integration Points

### Rust Core Engine (FFI)
```go
// Initialize crypto engine
initRustEngine()

// Generate Ed25519 keypair for new user
generateKeypairRust(userID)

// Sign digital credential
signedCred, err := signCredentialRust(userID, payload, issuedAt, expiresAt)
```

### Kotlin HMRC Service (HTTP)
```go
// Check citizen eligibility via government connectors
eligibility, err := checkEligibilityHMRC(userID)
```

### Kafka Audit Stream
```go
// Publish audit events for fraud detection
kafkaWriter.WriteMessages(ctx, kafka.Message{
    Value: []byte("User registered: " + email)
})
```

## Error Handling

- **Structured Errors**: JSON error responses with HTTP status codes
- **Logging**: Error details logged with context fields
- **Graceful Degradation**: Fallback responses for external service failures
- **Validation Errors**: Detailed field-level validation messages

## Building & Running

```bash
go mod tidy                    # Install dependencies
go run main.go                 # Development server
go build -o gateway main.go    # Production binary
```

## Dependencies

- `gin-gonic/gin`: High-performance HTTP framework
- `gorm.io/gorm`: ORM with PostgreSQL driver  
- `golang-jwt/jwt`: JWT token generation/validation
- `segmentio/kafka-go`: Kafka client for audit events
- `sirupsen/logrus`: Structured logging
- `gin-contrib/cors`: CORS middleware
- `go-playground/validator`: Input validation

## Monitoring

- Health check endpoint at `/health`
- Prometheus metrics (when configured)
- Structured JSON logs for monitoring systems
- Request ID tracing for distributed debugging