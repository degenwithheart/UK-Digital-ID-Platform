# 📡 UK Digital Identity Platform - API Reference

## 📘 Overview

This document provides comprehensive API reference documentation for the UK Digital Identity Platform. The platform exposes RESTful APIs for identity management, verification, credential issuance, and administrative operations.

## 🏗️ API Architecture

### Base URLs

| Environment | Base URL | Purpose |
|-------------|----------|---------|
| **Production** | `https://api.digital-identity.gov.uk` | Production API |
| **Staging** | `https://staging-api.digital-identity.gov.uk` | Staging/Testing |
| **Development** | `http://localhost:8081` | Local development |

### API Structure
```
/api/v1/
├── auth/           # Authentication endpoints
├── users/          # User management
├── credentials/    # Digital credential operations
├── verify/         # Identity verification
├── gov/           # Government API integrations
├── admin/         # Administrative operations
└── health/        # System health checks
```

## 🔐 Authentication

### JWT Authentication
All API endpoints require JWT authentication unless otherwise specified.

```http
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
Content-Type: application/json
X-Requested-With: XMLHttpRequest
```

### Authentication Flow
```mermaid
sequenceDiagram
    participant Client
    participant API Gateway
    participant Auth Service
    participant Core Engine
    
    Client->>API Gateway: POST /api/v1/auth/login
    API Gateway->>Auth Service: Validate credentials
    Auth Service->>Core Engine: Verify user (FFI)
    Core Engine-->>Auth Service: User validation
    Auth Service-->>API Gateway: JWT token
    API Gateway-->>Client: Token response
    
    Note over Client: Include token in subsequent requests
    Client->>API Gateway: GET /api/v1/users/profile (+ JWT)
    API Gateway->>Auth Service: Validate JWT
    Auth Service-->>API Gateway: Token valid
    API Gateway-->>Client: Profile data
```

## 🔑 Authentication Endpoints

### POST `/api/v1/auth/login`
Authenticate user and receive JWT token.

**Request Body:**
```json
{
  "email": "citizen@example.com",
  "password": "SecurePassword123!",
  "remember_me": false
}
```

**Response (200 OK):**
```json
{
  "success": true,
  "data": {
    "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
    "refresh_token": "def50200a8b9c5d2f1e7...",
    "expires_in": 900,
    "user": {
      "id": "550e8400-e29b-41d4-a716-446655440000",
      "email": "citizen@example.com",
      "name": "John Smith",
      "role": "citizen",
      "verification_level": 2,
      "created_at": "2025-01-01T10:00:00Z"
    }
  }
}
```

**Error Response (401 Unauthorized):**
```json
{
  "success": false,
  "error": {
    "code": "INVALID_CREDENTIALS",
    "message": "Invalid email or password",
    "details": {
      "attempts_remaining": 2,
      "lockout_duration": 900
    }
  }
}
```

### POST `/api/v1/auth/register`
Register new user account.

**Request Body:**
```json
{
  "name": "John Smith",
  "email": "citizen@example.com",
  "password": "SecurePassword123!",
  "date_of_birth": "1985-06-15",
  "nationality": "British",
  "consent": {
    "terms_and_conditions": true,
    "privacy_policy": true,
    "data_processing": true
  }
}
```

**Response (201 Created):**
```json
{
  "success": true,
  "data": {
    "user_id": "550e8400-e29b-41d4-a716-446655440000",
    "verification_required": true,
    "next_steps": [
      "document_upload",
      "biometric_enrollment"
    ]
  }
}
```

### POST `/api/v1/auth/refresh`
Refresh JWT token using refresh token.

**Request Body:**
```json
{
  "refresh_token": "def50200a8b9c5d2f1e7..."
}
```

**Response (200 OK):**
```json
{
  "success": true,
  "data": {
    "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
    "expires_in": 900
  }
}
```

## 👤 User Management Endpoints

### GET `/api/v1/users/profile`
Retrieve current user's profile information.

**Headers:**
```http
Authorization: Bearer {jwt_token}
```

**Response (200 OK):**
```json
{
  "success": true,
  "data": {
    "id": "550e8400-e29b-41d4-a716-446655440000",
    "name": "John Smith",
    "email": "citizen@example.com",
    "phone": "+44 7700 900123",
    "date_of_birth": "1985-06-15",
    "nationality": "British",
    "verification_level": 2,
    "verification_status": "verified",
    "credentials": [
      {
        "id": "cred_123456789",
        "type": "identity_credential",
        "status": "active",
        "issued_at": "2025-01-01T10:00:00Z",
        "expires_at": "2030-01-01T10:00:00Z"
      }
    ],
    "privacy_settings": {
      "data_sharing": "minimal",
      "marketing_consent": false,
      "analytics_consent": true
    },
    "created_at": "2025-01-01T10:00:00Z",
    "last_login": "2025-10-09T14:30:00Z"
  }
}
```

### PUT `/api/v1/users/profile`
Update user profile information.

**Request Body:**
```json
{
  "name": "John A. Smith",
  "phone": "+44 7700 900456",
  "privacy_settings": {
    "data_sharing": "enhanced",
    "marketing_consent": false,
    "analytics_consent": true
  }
}
```

**Response (200 OK):**
```json
{
  "success": true,
  "message": "Profile updated successfully",
  "data": {
    "updated_fields": ["name", "phone", "privacy_settings"],
    "updated_at": "2025-10-09T14:35:00Z"
  }
}
```

## 📋 Credential Management Endpoints

### GET `/api/v1/credentials`
List user's digital credentials.

**Query Parameters:**
- `status` (optional): Filter by status (`active`, `expired`, `revoked`)
- `type` (optional): Filter by credential type
- `limit` (optional): Number of results (default: 10, max: 100)
- `offset` (optional): Pagination offset (default: 0)

**Response (200 OK):**
```json
{
  "success": true,
  "data": {
    "credentials": [
      {
        "id": "cred_123456789",
        "type": "identity_credential",
        "status": "active",
        "subject": {
          "name": "John Smith",
          "date_of_birth": "1985-06-15",
          "nationality": "British"
        },
        "issuer": {
          "name": "UK Government Digital Identity Service",
          "did": "did:gov:uk:digital-identity"
        },
        "issuance_date": "2025-01-01T10:00:00Z",
        "expiration_date": "2030-01-01T10:00:00Z",
        "verification_level": 2,
        "proof": {
          "type": "Ed25519Signature2020",
          "verification_method": "did:gov:uk:digital-identity#key-1",
          "signature": "z5s8bKf7...truncated"
        }
      }
    ],
    "pagination": {
      "total": 1,
      "limit": 10,
      "offset": 0,
      "has_more": false
    }
  }
}
```

### POST `/api/v1/credentials/issue`
Issue new digital credential.

**Request Body:**
```json
{
  "type": "identity_credential",
  "subject_data": {
    "verification_documents": [
      {
        "type": "passport",
        "document_id": "doc_987654321",
        "verified": true
      }
    ],
    "biometric_data": {
      "template_hash": "sha256:a4b2c8d9e5f1...",
      "template_type": "fingerprint",
      "verified": true
    }
  },
  "validity_period": "5_years"
}
```

**Response (201 Created):**
```json
{
  "success": true,
  "data": {
    "credential_id": "cred_246813579",
    "type": "identity_credential",
    "status": "active",
    "qr_code": "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAA...",
    "download_url": "https://api.digital-identity.gov.uk/credentials/cred_246813579/download",
    "issued_at": "2025-10-09T14:40:00Z",
    "expires_at": "2030-10-09T14:40:00Z"
  }
}
```

### GET `/api/v1/credentials/{credential_id}`
Retrieve specific credential details.

**Response (200 OK):**
```json
{
  "success": true,
  "data": {
    "id": "cred_123456789",
    "type": "identity_credential",
    "status": "active",
    "credential": {
      "@context": [
        "https://www.w3.org/2018/credentials/v1",
        "https://identity.gov.uk/contexts/v1"
      ],
      "id": "https://api.digital-identity.gov.uk/credentials/cred_123456789",
      "type": ["VerifiableCredential", "IdentityCredential"],
      "issuer": "did:gov:uk:digital-identity",
      "issuanceDate": "2025-01-01T10:00:00Z",
      "expirationDate": "2030-01-01T10:00:00Z",
      "credentialSubject": {
        "id": "did:user:550e8400-e29b-41d4-a716-446655440000",
        "name": "John Smith",
        "dateOfBirth": "1985-06-15",
        "nationality": "British",
        "verificationLevel": 2
      },
      "proof": {
        "type": "Ed25519Signature2020",
        "created": "2025-01-01T10:00:00Z",
        "verificationMethod": "did:gov:uk:digital-identity#key-1",
        "proofPurpose": "assertionMethod",
        "jws": "eyJhbGciOiJFZERTQSIsImI2NCI6ZmFsc2UsImNyaXQiOlsiYjY0Il19..DJBMvvFAIC00nSGB6Tn0XKbbF9XrsaJZREWvR2aONYTQQxnyXirtXnlewJMBBn2h9hfcGZrvnC1b6PgWmukzAg"
      }
    }
  }
}
```

## ✅ Identity Verification Endpoints

### POST `/api/v1/verify/identity`
Request identity verification using government sources.

**Request Body:**
```json
{
  "verification_type": "full_verification",
  "documents": [
    {
      "type": "passport",
      "number": "123456789",
      "expiry_date": "2030-06-15",
      "image_data": "base64_encoded_document_image"
    }
  ],
  "government_sources": [
    "hmrc",
    "dvla",
    "nhs"
  ],
  "biometric_data": {
    "fingerprint_template": "base64_encoded_template",
    "liveness_proof": "base64_encoded_liveness_data"
  }
}
```

**Response (202 Accepted):**
```json
{
  "success": true,
  "data": {
    "verification_id": "verify_abc123def456",
    "status": "processing",
    "estimated_completion": "2025-10-09T14:45:00Z",
    "steps": [
      {
        "step": "document_validation",
        "status": "in_progress",
        "description": "Validating document authenticity"
      },
      {
        "step": "government_verification",
        "status": "pending",
        "description": "Cross-referencing with government databases"
      },
      {
        "step": "biometric_matching",
        "status": "pending",
        "description": "Matching biometric data"
      },
      {
        "step": "fraud_check",
        "status": "pending",
        "description": "Running fraud detection algorithms"
      }
    ]
  }
}
```

### GET `/api/v1/verify/{verification_id}`
Check verification status.

**Response (200 OK):**
```json
{
  "success": true,
  "data": {
    "verification_id": "verify_abc123def456",
    "status": "completed",
    "result": "verified",
    "confidence_score": 0.95,
    "verification_level": 2,
    "steps": [
      {
        "step": "document_validation",
        "status": "completed",
        "result": "passed",
        "completed_at": "2025-10-09T14:42:00Z"
      },
      {
        "step": "government_verification",
        "status": "completed",
        "result": "verified",
        "sources": ["hmrc", "dvla", "nhs"],
        "completed_at": "2025-10-09T14:43:30Z"
      },
      {
        "step": "biometric_matching",
        "status": "completed",
        "result": "matched",
        "match_score": 0.97,
        "completed_at": "2025-10-09T14:44:00Z"
      },
      {
        "step": "fraud_check",
        "status": "completed",
        "result": "no_fraud",
        "risk_score": 0.12,
        "completed_at": "2025-10-09T14:44:30Z"
      }
    ],
    "completed_at": "2025-10-09T14:44:30Z",
    "next_actions": ["issue_credential"]
  }
}
```

## 🏛️ Government API Integration

### POST `/api/v1/gov/verify`
Verify identity against government databases.

**Request Body:**
```json
{
  "citizen_data": {
    "national_insurance_number": "AB123456C",
    "full_name": "John Smith",
    "date_of_birth": "1985-06-15",
    "address": {
      "line1": "123 Main Street",
      "city": "London",
      "postcode": "SW1A 1AA"
    }
  },
  "verification_sources": [
    "hmrc",
    "dvla", 
    "nhs",
    "dwp"
  ],
  "verification_level": "enhanced"
}
```

**Response (200 OK):**
```json
{
  "success": true,
  "data": {
    "verification_id": "gov_verify_789xyz",
    "overall_result": "verified",
    "confidence_score": 0.94,
    "source_results": {
      "hmrc": {
        "status": "verified",
        "data_matches": ["name", "ni_number", "address"],
        "employment_status": "employed",
        "tax_year": "2024-25"
      },
      "dvla": {
        "status": "verified", 
        "data_matches": ["name", "address"],
        "license_status": "valid",
        "license_categories": ["B"]
      },
      "nhs": {
        "status": "verified",
        "data_matches": ["name", "date_of_birth"],
        "registration_status": "active",
        "gp_registered": true
      },
      "dwp": {
        "status": "verified",
        "data_matches": ["name", "ni_number"],
        "benefit_claims": "none_active"
      }
    },
    "verification_timestamp": "2025-10-09T14:45:00Z"
  }
}
```

### GET `/api/v1/gov/status`
Check government API system status.

**Response (200 OK):**
```json
{
  "success": true,
  "data": {
    "overall_status": "operational",
    "api_status": {
      "hmrc": {
        "status": "operational",
        "response_time": 245,
        "uptime": 99.97,
        "last_check": "2025-10-09T14:45:00Z"
      },
      "dvla": {
        "status": "operational",
        "response_time": 189,
        "uptime": 99.95,
        "last_check": "2025-10-09T14:45:00Z"
      },
      "nhs": {
        "status": "degraded",
        "response_time": 1205,
        "uptime": 98.2,
        "last_check": "2025-10-09T14:45:00Z",
        "issues": ["Slow response times due to maintenance"]
      },
      "dwp": {
        "status": "operational", 
        "response_time": 334,
        "uptime": 99.91,
        "last_check": "2025-10-09T14:45:00Z"
      }
    }
  }
}
```

## 👥 Administrative Endpoints

### GET `/api/v1/admin/users`
List users (Admin only).

**Query Parameters:**
- `status` (optional): Filter by status
- `verification_level` (optional): Filter by verification level
- `created_after` (optional): ISO date string
- `limit` (optional): Results per page (max 100)
- `offset` (optional): Pagination offset

**Response (200 OK):**
```json
{
  "success": true,
  "data": {
    "users": [
      {
        "id": "550e8400-e29b-41d4-a716-446655440000",
        "email": "citizen@example.com", 
        "name": "John Smith",
        "status": "active",
        "verification_level": 2,
        "created_at": "2025-01-01T10:00:00Z",
        "last_login": "2025-10-09T14:30:00Z",
        "credential_count": 1
      }
    ],
    "pagination": {
      "total": 1250000,
      "limit": 50,
      "offset": 0,
      "has_more": true
    }
  }
}
```

### GET `/api/v1/admin/analytics`
System analytics and metrics.

**Response (200 OK):**
```json
{
  "success": true,
  "data": {
    "overview": {
      "total_users": 1250000,
      "active_users": 1189000,
      "verified_users": 1098000,
      "daily_registrations": 1547,
      "daily_verifications": 2103
    },
    "verification_metrics": {
      "success_rate": 94.2,
      "average_time_minutes": 8.5,
      "government_api_usage": {
        "hmrc": 45.2,
        "dvla": 38.7,
        "nhs": 52.1,
        "dwp": 28.9
      }
    },
    "fraud_detection": {
      "total_attempts": 15420,
      "fraud_detected": 127,
      "false_positive_rate": 2.1,
      "model_accuracy": 96.8
    },
    "system_performance": {
      "api_response_time_p95": 89,
      "uptime_percentage": 99.94,
      "error_rate": 0.23
    },
    "timestamp": "2025-10-09T14:45:00Z"
  }
}
```

## ❤️ Health Check Endpoints

### GET `/api/v1/health`
System health check.

**Response (200 OK):**
```json
{
  "success": true,
  "data": {
    "status": "healthy",
    "version": "1.0.0",
    "timestamp": "2025-10-09T14:45:00Z",
    "services": {
      "database": {
        "status": "healthy",
        "response_time": 12,
        "connections": {
          "active": 23,
          "max": 100
        }
      },
      "redis": {
        "status": "healthy",
        "response_time": 3,
        "memory_usage": "45%"
      },
      "kafka": {
        "status": "healthy",
        "topics": 5,
        "messages_per_second": 1247
      },
      "rust_core": {
        "status": "healthy",
        "response_time": 8,
        "crypto_operations_per_second": 5432
      },
      "government_apis": {
        "status": "degraded",
        "operational": 22,
        "degraded": 2,
        "offline": 1
      }
    },
    "uptime_seconds": 2547890
  }
}
```

### GET `/api/v1/health/detailed`
Detailed health information.

**Response (200 OK):**
```json
{
  "success": true,
  "data": {
    "status": "healthy",
    "components": {
      "go_gateway": {
        "status": "healthy",
        "version": "1.0.0",
        "memory_usage": "67%",
        "goroutines": 45,
        "requests_per_minute": 1250
      },
      "rust_core_engine": {
        "status": "healthy", 
        "version": "1.0.0",
        "memory_usage": "34%",
        "active_connections": 128,
        "crypto_operations_per_minute": 15420
      },
      "kotlin_connectors": {
        "status": "healthy",
        "version": "1.0.0",
        "jvm_memory_usage": "58%",
        "government_api_calls_per_minute": 890
      },
      "python_fraud_analytics": {
        "status": "healthy",
        "version": "1.0.0",
        "model_version": "2.1.0",
        "predictions_per_minute": 445
      }
    }
  }
}
```

## � Sync Endpoints

### WebSocket Connection `/api/v1/sync/ws`
Establish real-time WebSocket connection for live updates.

**Connection URL:**
```
wss://api.digital-identity.gov.uk/api/v1/sync/ws?token={jwt_token}
```

**Connection Message:**
```json
{
  "type": "subscribe",
  "channels": ["credential_updates", "verification_status", "government_feed"],
  "user_id": "550e8400-e29b-41d4-a716-446655440000"
}
```

**Incoming Messages:**
```json
{
  "type": "credential_update",
  "data": {
    "credential_id": "cred_123456789",
    "status": "updated",
    "changes": ["verification_level"],
    "timestamp": "2025-10-09T14:50:00Z"
  }
}
```

### POST `/api/v1/sync/events`
Publish sync event to Redis pub/sub.

**Request Body:**
```json
{
  "event_type": "user_verification_complete",
  "user_id": "550e8400-e29b-41d4-a716-446655440000",
  "data": {
    "verification_id": "verify_abc123",
    "result": "verified",
    "confidence_score": 0.95
  },
  "channels": ["fraud_analytics", "mobile_wallet"]
}
```

**Response (200 OK):**
```json
{
  "success": true,
  "data": {
    "event_id": "evt_987654321",
    "published_channels": 2,
    "timestamp": "2025-10-09T14:50:00Z"
  }
}
```

### GET `/api/v1/sync/status`
Check sync system status and connection health.

**Response (200 OK):**
```json
{
  "success": true,
  "data": {
    "redis_status": "connected",
    "active_connections": 1247,
    "messages_per_second": 89,
    "channels": {
      "credential_updates": 456,
      "verification_status": 234,
      "government_feed": 123
    },
    "last_sync": "2025-10-09T14:49:45Z"
  }
}
```

## �🔧 Error Handling

### Standard Error Response Format
```json
{
  "success": false,
  "error": {
    "code": "ERROR_CODE",
    "message": "Human-readable error message",
    "details": {
      "field": "Additional context",
      "suggestion": "Recommended action"
    },
    "request_id": "req_123456789",
    "timestamp": "2025-10-09T14:45:00Z"
  }
}
```

### HTTP Status Codes

| Status Code | Meaning | Usage |
|-------------|---------|-------|
| **200** | OK | Successful request |
| **201** | Created | Resource created successfully |
| **202** | Accepted | Request accepted for processing |
| **400** | Bad Request | Invalid request syntax or parameters |
| **401** | Unauthorized | Authentication required or failed |
| **403** | Forbidden | Insufficient permissions |
| **404** | Not Found | Resource not found |
| **409** | Conflict | Resource already exists |
| **422** | Unprocessable Entity | Validation failed |
| **429** | Too Many Requests | Rate limit exceeded |
| **500** | Internal Server Error | Unexpected server error |
| **502** | Bad Gateway | Upstream service error |
| **503** | Service Unavailable | Service temporarily unavailable |

### Common Error Codes

| Error Code | Description | HTTP Status |
|------------|-------------|-------------|
| `INVALID_CREDENTIALS` | Invalid username or password | 401 |
| `TOKEN_EXPIRED` | JWT token has expired | 401 |
| `INSUFFICIENT_PERMISSIONS` | User lacks required permissions | 403 |
| `USER_NOT_FOUND` | User account not found | 404 |
| `VALIDATION_FAILED` | Input validation failed | 422 |
| `RATE_LIMIT_EXCEEDED` | Too many requests | 429 |
| `GOVERNMENT_API_UNAVAILABLE` | External government API error | 502 |
| `VERIFICATION_IN_PROGRESS` | Identity verification already running | 409 |
| `CREDENTIAL_EXPIRED` | Digital credential has expired | 410 |

## 🔗 SDK and Integration Examples

### JavaScript/Node.js SDK Example
```javascript
const DigitalIdentityAPI = require('@uk-gov/digital-identity-api');

const client = new DigitalIdentityAPI({
  baseURL: 'https://api.digital-identity.gov.uk',
  apiKey: 'your-api-key',
  timeout: 30000
});

// Authenticate user
const authResult = await client.auth.login({
  email: 'citizen@example.com',
  password: 'password123'
});

// Get user profile
const profile = await client.users.getProfile(authResult.token);

// Request verification
const verification = await client.verify.requestVerification({
  token: authResult.token,
  documents: [{
    type: 'passport',
    number: '123456789'
  }],
  governmentSources: ['hmrc', 'dvla']
});
```

### Python SDK Example
```python
from uk_digital_identity import DigitalIdentityClient

client = DigitalIdentityClient(
    base_url='https://api.digital-identity.gov.uk',
    api_key='your-api-key'
)

# Authenticate
auth_result = client.auth.login(
    email='citizen@example.com',
    password='password123'
)

# Get credentials
credentials = client.credentials.list(
    token=auth_result['token'],
    status='active'
)

# Issue new credential
new_credential = client.credentials.issue(
    token=auth_result['token'],
    type='identity_credential',
    validity_period='5_years'
)
```

---

*This API reference provides comprehensive documentation for integrating with the UK Digital Identity Platform. For additional support or questions, contact the API support team.*