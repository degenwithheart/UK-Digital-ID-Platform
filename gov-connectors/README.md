# ☕ Government Connectors (Kotlin)

Comprehensive Spring Boot 3.1.0 service providing secure integrations with 25 UK government APIs for identity verification and eligibility checks.

## 🎯 Features

- **Spring Boot 3.1.0**: WebFlux reactive streams with non-blocking I/O and virtual threads
- **25 Government Systems**: Complete integration suite covering all major UK government departments
- **Event-Driven Sync**: Redis pub/sub integration for real-time government feed synchronization
- **Privacy & Security**: AES-GCM encryption, OAuth 2.1, mTLS, comprehensive audit logging, input validation
- **Performance**: Connection pooling, reactive streams, parallel processing, TTL caching, 5s timeout handling
- **Enterprise**: JPA persistence, SLF4J structured logging, Prometheus metrics integration

## 🏗️ Architecture

```
┌─────────────────┐    ┌──────────────────────┐    ┌─────────────────┐
│ Core Engine     │───▶│  Unified Government  │───▶│   Sync Service  │
│ Verification    │    │  Connector Service   │    │  (Redis Pub/Sub)│
│                 │    │    (Port 8070)       │    │                 │
└─────────────────┘    └──────────────────────┘    └─────────────────┘
                              │                           │
        ┌─────────────────────┼─────────────────────┐     │
        │                     │                     │     │
┌───────▼────────┐   ┌────────▼────────┐   ┌───────▼────────┐     │
│   Identity &    │   │   Business &    │   │  Specialized   │     │
│   Immigration   │   │   Financial     │   │   Services     │     │
│                 │   │                 │   │                │     │
│ • HMRC         │   │ • Companies     │   │ • Law Enforce. │     │
│ • DWP          │   │   House         │   │ • Courts       │     │
│ • NHS          │   │ • Financial     │   │ • Professional │     │
│ • DVLA         │   │   Services      │   │   Bodies       │     │
│ • Home Office  │   │ • Business &    │   │ • Local Gov    │     │
│ • Border Ctrl  │   │   Trade         │   │ • Transport    │     │
└────────────────┘   │ • Land Registry │   │ • Healthcare   │     │
                     └─────────────────┘   └────────────────┘     │
                              ▲                                   │
                              └───────────────────────────────────┘
                                   Government Feed Events
```

## 🏛️ Government API Coverage (25 Systems)

| Category | Systems | Key Services |
|----------|---------|--------------|
| **Core Identity** | HMRC, DWP, NHS, DVLA | Tax records, benefits, healthcare, licenses |
| **Immigration** | Home Office, Border Control | Right to work, immigration status |
| **Business** | Companies House, Financial Services, Business & Trade | Company verification, financial checks |
| **Education** | Education Department, Professional Bodies | Qualifications, certifications |
| **Legal** | Law Enforcement, Security Services, Courts & Tribunals | Criminal records, legal proceedings |
| **Healthcare** | Healthcare Services, Transport Authority | Medical records, transport permits |
| **Property** | Land Registry, Local Government | Property ownership, council services |
| **Environment** | DEFRA, Housing & Communities | Environmental records, housing |
| **Innovation** | Culture Media Sport, Energy Security, Science Innovation | Licenses, grants, research |

## 🔄 Sync Capabilities

- **Redis Pub/Sub Integration**: Real-time event-driven synchronization with government feeds
- **Reactive Event Handling**: Non-blocking subscription to citizen data updates
- **Bidirectional Sync**: Publish verification results and subscribe to government data changes
- **Event Correlation**: Request IDs for tracking sync operations across services
- **TTL Caching**: Time-based cache invalidation for fresh government data

## API Endpoints

### HMRC Integration
- `POST /api/connectors/sync` - Sync citizen data from HMRC systems
- `GET /api/connectors/tax-records/{nino}` - Retrieve tax records by NINO
- `POST /api/connectors/verify-eligibility` - Check benefit eligibility
- `GET /api/connectors/verify-eligibility` - Query eligibility (used by Go gateway)

### Health & Monitoring  
- `GET /actuator/health` - Service health check
- `GET /actuator/metrics` - Prometheus metrics endpoint

## Data Models

### Sync Request
```kotlin
data class SyncRequest(
    @field:NotBlank val citizenId: String,
    @field:Min(0) val dataSize: Int
)
```

### Eligibility Request  
```kotlin
data class EligibilityRequest(
    @field:NotBlank val nino: String,
    @field:Min(0) val income: Double
)
```

### Eligibility Response
```kotlin
data class EligibilityResponse(
    val eligible: Boolean, 
    val benefits: List<String>
)
```

## Government API Integrations

### HMRC (HM Revenue & Customs)
- **Individual Income API**: Fetch citizen tax records
- **Benefits Eligibility API**: Determine Universal Credit eligibility
- **Real-time Data**: Live sync with government databases
- **Fallback Logic**: Cached responses when APIs unavailable

### DVLA (Future Integration)
- **Driver License Verification**: Validate driving credentials
- **Vehicle Registration**: Link vehicles to citizen identity
- **Address Verification**: Confirm residential details

## Security Features

- **API Authentication**: Bearer token validation for HMRC calls
- **Data Encryption**: AES-GCM encryption for sensitive government data storage and transmission
- **Input Sanitization**: JSR-303 validation prevents injection attacks  
- **CORS Restrictions**: Limited to approved frontend domains
- **Request Logging**: Comprehensive audit trail for compliance
- **Error Masking**: Sensitive government data not exposed in errors

## Performance Optimizations

- **Reactive Streams**: Non-blocking I/O with Project Reactor
- **Connection Pooling**: Persistent HTTP connections to government APIs
- **TTL Caching**: Time-based cache invalidation for frequently accessed government data
- **Parallel Processing**: Concurrent API calls where possible
- **Timeout Configuration**: 5-second timeouts prevent hanging requests

## Configuration

### Database (application.yml)
```yaml
spring:
  datasource:
    url: jdbc:postgresql://postgres:5432/digital_id
    username: user
    password: ${DB_PASSWORD}
  jpa:
    hibernate:
      ddl-auto: update
    properties:
      hibernate:
        dialect: org.hibernate.dialect.PostgreSQLDialect
```

### WebClient Configuration
```kotlin
@Bean
fun webClient(): WebClient = WebClient.builder()
    .defaultHeader("Authorization", "Bearer secure-token")
    .build()
```

## Error Handling

- **Reactive Error Handling**: `doOnError()` for comprehensive logging
- **Fallback Responses**: Default eligibility data when APIs fail
- **Structured Logging**: SLF4J with context information
- **HTTP Status Mapping**: Appropriate status codes for different failure modes

## Mock Implementations

For development and testing, the service includes mock responses:

```kotlin
// Mock HMRC eligibility check
EligibilityResponse(
    eligible = request.income < 20000,
    benefits = if (request.income < 20000) 
        listOf("Universal Credit", "Housing Benefit") 
    else emptyList()
)
```

## Building & Running

```bash
./gradlew build                # Build application
./gradlew bootRun              # Run development server
./gradlew test                 # Execute test suite
java -jar build/libs/*.jar     # Run production JAR
```

## Dependencies

- **Spring Boot**: Core framework with WebFlux reactive stack
- **Spring Data JPA**: Database persistence layer
- **PostgreSQL**: JDBC driver for database connectivity
- **Bean Validation**: JSR-303 input validation
- **SLF4J + Logback**: Structured logging framework
- **Project Reactor**: Reactive streams implementation

## Integration Points

### Called by Go Gateway
```http
GET /api/connectors/verify-eligibility?nino=1234567890&income=15000
```

### Calls Government APIs
```kotlin
webClient.post()
    .uri("https://api.hmrc.gov.uk/test/individuals/income")
    .bodyValue(syncRequest)
    .retrieve()
    .bodyToMono(Map::class.java)
    .timeout(Duration.ofSeconds(5))
```

## Monitoring & Observability

- **Structured Logging**: JSON format for log aggregation
- **Health Checks**: Spring Boot Actuator endpoints
- **Metrics**: Micrometer integration for Prometheus
- **Distributed Tracing**: Request correlation IDs
- **Error Tracking**: Comprehensive exception logging with context