package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/lib/pq"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/redis/go-redis/v9"
	"github.com/spf13/viper"
	"go.uber.org/zap"
	"github.com/go-playground/validator/v10"
	"github.com/sony/gobreaker"
	"golang.org/x/time/rate"
	"golang.org/x/crypto/bcrypt"
)

type Config struct {
	Server struct {
		Port string `mapstructure:"port"`
		Host string `mapstructure:"host"`
	} `mapstructure:"server"`
	
	Database struct {
		URL             string        `mapstructure:"url"`
		MaxConnections  int           `mapstructure:"max_connections"`
		MaxIdleTime     time.Duration `mapstructure:"max_idle_time"`
		MaxLifetime     time.Duration `mapstructure:"max_lifetime"`
		ConnectTimeout  time.Duration `mapstructure:"connect_timeout"`
	} `mapstructure:"database"`
	
	Redis struct {
		Addr     string `mapstructure:"addr"`
		Password string `mapstructure:"password"`
		DB       int    `mapstructure:"db"`
	} `mapstructure:"redis"`
	
	Crypto struct {
		PrivateKeyPath string        `mapstructure:"private_key_path"`
		PublicKeyPath  string        `mapstructure:"public_key_path"`
		KeySize        int           `mapstructure:"key_size"`
		TokenExpiry    time.Duration `mapstructure:"token_expiry"`
	} `mapstructure:"crypto"`
	
	RateLimit struct {
		Requests int           `mapstructure:"requests"`
		Window   time.Duration `mapstructure:"window"`
		Burst    int           `mapstructure:"burst"`
	} `mapstructure:"rate_limit"`
}

type CredentialService struct {
	config         *Config
	logger         *zap.Logger
	db             *sql.DB
	redis          *redis.Client
	validator      *validator.Validate
	circuitBreaker *gobreaker.CircuitBreaker
	rateLimiter    *rate.Limiter
	metrics        *CredentialMetrics
	privateKey     *rsa.PrivateKey
	publicKey      *rsa.PublicKey
	startTime      time.Time
}

type CredentialMetrics struct {
	CredentialsIssued    prometheus.Counter
	CredentialsRevoked   prometheus.Counter
	CredentialsVerified  prometheus.Counter
	RequestDuration      prometheus.Histogram
	ActiveCredentials    prometheus.Gauge
	SigningOperations    prometheus.Counter
	VerificationFailed   prometheus.Counter
}

type DigitalCredential struct {
	ID              string                 `json:"id" db:"id"`
	Type            string                 `json:"type" db:"type" validate:"required,oneof=identity_card passport driving_license birth_certificate education_certificate employment_certificate"`
	HolderID        string                 `json:"holder_id" db:"holder_id" validate:"required"`
	IssuerID        string                 `json:"issuer_id" db:"issuer_id" validate:"required"`
	Status          string                 `json:"status" db:"status"`
	Level           string                 `json:"level" db:"level" validate:"required,oneof=basic standard enhanced"`
	Claims          map[string]interface{} `json:"claims" db:"claims"`
	Metadata        map[string]interface{} `json:"metadata" db:"metadata"`
	Signature       string                 `json:"signature" db:"signature"`
	IssuedAt        time.Time              `json:"issued_at" db:"issued_at"`
	ExpiresAt       time.Time              `json:"expires_at" db:"expires_at"`
	RevokedAt       *time.Time             `json:"revoked_at,omitempty" db:"revoked_at"`
	RevocationReason string                `json:"revocation_reason,omitempty" db:"revocation_reason"`
	CreatedAt       time.Time              `json:"created_at" db:"created_at"`
	UpdatedAt       time.Time              `json:"updated_at" db:"updated_at"`
	
	// Verification fields
	VerificationHash string    `json:"verification_hash,omitempty" db:"verification_hash"`
	BlockchainTxID   string    `json:"blockchain_tx_id,omitempty" db:"blockchain_tx_id"`
}

type CredentialRequest struct {
	Type           string                 `json:"type" validate:"required,oneof=identity_card passport driving_license birth_certificate education_certificate employment_certificate"`
	HolderID       string                 `json:"holder_id" validate:"required"`
	Level          string                 `json:"level" validate:"required,oneof=basic standard enhanced"`
	Claims         map[string]interface{} `json:"claims" validate:"required"`
	Metadata       map[string]interface{} `json:"metadata,omitempty"`
	ValidityPeriod time.Duration          `json:"validity_period" validate:"required"`
	
	// Supporting documents
	SupportingDocs []SupportingDocument `json:"supporting_documents,omitempty"`
}

type SupportingDocument struct {
	Type        string    `json:"type" validate:"required"`
	Reference   string    `json:"reference" validate:"required"`
	Hash        string    `json:"hash" validate:"required"`
	UploadedAt  time.Time `json:"uploaded_at"`
	VerifiedBy  string    `json:"verified_by,omitempty"`
	VerifiedAt  *time.Time `json:"verified_at,omitempty"`
}

type CredentialResponse struct {
	Credential      *DigitalCredential     `json:"credential"`
	VerifiableCredential *VerifiableCredential `json:"verifiable_credential"`
	QRCode          string                 `json:"qr_code"`
	DownloadURL     string                 `json:"download_url"`
	WalletImportURL string                 `json:"wallet_import_url"`
}

type VerifiableCredential struct {
	Context           []string               `json:"@context"`
	Type              []string               `json:"type"`
	Issuer            string                 `json:"issuer"`
	IssuanceDate      string                 `json:"issuanceDate"`
	ExpirationDate    string                 `json:"expirationDate"`
	CredentialSubject map[string]interface{} `json:"credentialSubject"`
	Proof             Proof                  `json:"proof"`
}

type Proof struct {
	Type               string    `json:"type"`
	Created            string    `json:"created"`
	ProofPurpose       string    `json:"proofPurpose"`
	VerificationMethod string    `json:"verificationMethod"`
	JWS                string    `json:"jws"`
}

type RevocationRequest struct {
	CredentialID string `json:"credential_id" validate:"required,uuid"`
	Reason       string `json:"reason" validate:"required,min=5,max=200"`
	RevokerID    string `json:"revoker_id" validate:"required"`
}

type VerificationRequest struct {
	CredentialID       string `json:"credential_id,omitempty"`
	CredentialData     string `json:"credential_data,omitempty"`
	VerificationMethod string `json:"verification_method" validate:"required,oneof=signature hash blockchain qr_code"`
}

type VerificationResult struct {
	Valid              bool                   `json:"valid"`
	CredentialID       string                 `json:"credential_id"`
	Status             string                 `json:"status"`
	IssuerTrusted      bool                   `json:"issuer_trusted"`
	SignatureValid     bool                   `json:"signature_valid"`
	NotExpired         bool                   `json:"not_expired"`
	NotRevoked         bool                   `json:"not_revoked"`
	VerificationDetails map[string]interface{} `json:"verification_details"`
	Warnings           []string               `json:"warnings"`
	VerifiedAt         time.Time              `json:"verified_at"`
}

type CredentialBatch struct {
	BatchID     string              `json:"batch_id"`
	Credentials []CredentialRequest `json:"credentials" validate:"required,min=1,max=100"`
	IssuerID    string              `json:"issuer_id" validate:"required"`
	BatchType   string              `json:"batch_type" validate:"required,oneof=bulk_identity bulk_education bulk_employment"`
}

type APIResponse struct {
	Success   bool        `json:"success"`
	Data      interface{} `json:"data,omitempty"`
	Error     string      `json:"error,omitempty"`
	RequestID string      `json:"request_id"`
	Timestamp time.Time   `json:"timestamp"`
}

func NewCredentialMetrics() *CredentialMetrics {
	return &CredentialMetrics{
		CredentialsIssued: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "credentials_issued_total",
			Help: "Total number of credentials issued",
		}),
		CredentialsRevoked: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "credentials_revoked_total",
			Help: "Total number of credentials revoked",
		}),
		CredentialsVerified: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "credentials_verified_total",
			Help: "Total number of credentials verified",
		}),
		RequestDuration: prometheus.NewHistogram(prometheus.HistogramOpts{
			Name:    "credential_request_duration_seconds",
			Help:    "Credential request duration in seconds",
			Buckets: prometheus.DefBuckets,
		}),
		ActiveCredentials: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "credentials_active_total",
			Help: "Number of active credentials",
		}),
		SigningOperations: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "credential_signing_operations_total",
			Help: "Total number of signing operations",
		}),
		VerificationFailed: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "credential_verification_failed_total",
			Help: "Total number of failed verifications",
		}),
	}
}

func (m *CredentialMetrics) Register() {
	prometheus.MustRegister(
		m.CredentialsIssued,
		m.CredentialsRevoked,
		m.CredentialsVerified,
		m.RequestDuration,
		m.ActiveCredentials,
		m.SigningOperations,
		m.VerificationFailed,
	)
}

func loadConfig() (*Config, error) {
	viper.SetConfigName("config")
	viper.SetConfigType("yaml")
	viper.AddConfigPath(".")
	viper.AddConfigPath("./config")
	
	// Set defaults
	viper.SetDefault("server.port", "8083")
	viper.SetDefault("server.host", "0.0.0.0")
	viper.SetDefault("database.max_connections", 25)
	viper.SetDefault("database.max_idle_time", "15m")
	viper.SetDefault("database.max_lifetime", "1h")
	viper.SetDefault("database.connect_timeout", "10s")
	viper.SetDefault("redis.addr", "localhost:6379")
	viper.SetDefault("redis.db", 3)
	viper.SetDefault("crypto.key_size", 2048)
	viper.SetDefault("crypto.token_expiry", "24h")
	viper.SetDefault("rate_limit.requests", 20)
	viper.SetDefault("rate_limit.window", "1m")
	viper.SetDefault("rate_limit.burst", 5)
	
	// Auto env
	viper.AutomaticEnv()
	viper.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
	
	if err := viper.ReadInConfig(); err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); !ok {
			return nil, fmt.Errorf("error reading config: %w", err)
		}
	}
	
	var config Config
	if err := viper.Unmarshal(&config); err != nil {
		return nil, fmt.Errorf("error unmarshaling config: %w", err)
	}
	
	return &config, nil
}

func NewCredentialService(config *Config, logger *zap.Logger) (*CredentialService, error) {
	// Initialize database
	db, err := sql.Open("postgres", config.Database.URL)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to database: %w", err)
	}
	
	db.SetMaxOpenConns(config.Database.MaxConnections)
	db.SetMaxIdleConns(config.Database.MaxConnections / 2)
	db.SetConnMaxIdleTime(config.Database.MaxIdleTime)
	db.SetConnMaxLifetime(config.Database.MaxLifetime)
	
	// Test database connection
	ctx, cancel := context.WithTimeout(context.Background(), config.Database.ConnectTimeout)
	defer cancel()
	
	if err := db.PingContext(ctx); err != nil {
		return nil, fmt.Errorf("failed to ping database: %w", err)
	}
	
	// Initialize Redis
	rdb := redis.NewClient(&redis.Options{
		Addr:     config.Redis.Addr,
		Password: config.Redis.Password,
		DB:       config.Redis.DB,
	})
	
	// Test Redis connection
	if err := rdb.Ping(context.Background()).Err(); err != nil {
		logger.Warn("Redis connection failed", zap.Error(err))
	}
	
	// Initialize RSA keys
	privateKey, publicKey, err := initializeKeys(config.Crypto.PrivateKeyPath, config.Crypto.PublicKeyPath, config.Crypto.KeySize)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize keys: %w", err)
	}
	
	// Initialize circuit breaker
	cb := gobreaker.NewCircuitBreaker(gobreaker.Settings{
		Name:        "credential-circuit-breaker",
		MaxRequests: 5,
		Interval:    60 * time.Second,
		Timeout:     60 * time.Second,
		ReadyToTrip: func(counts gobreaker.Counts) bool {
			return counts.ConsecutiveFailures >= 3
		},
	})
	
	// Initialize rate limiter
	rateLimiter := rate.NewLimiter(
		rate.Limit(config.RateLimit.Requests)/rate.Limit(config.RateLimit.Window.Seconds()),
		config.RateLimit.Burst,
	)
	
	// Initialize metrics
	metrics := NewCredentialMetrics()
	metrics.Register()
	
	return &CredentialService{
		config:         config,
		logger:         logger,
		db:             db,
		redis:          rdb,
		validator:      validator.New(),
		circuitBreaker: cb,
		rateLimiter:    rateLimiter,
		metrics:        metrics,
		privateKey:     privateKey,
		publicKey:      publicKey,
		startTime:      time.Now(),
	}, nil
}

func initializeKeys(privateKeyPath, publicKeyPath string, keySize int) (*rsa.PrivateKey, *rsa.PublicKey, error) {
	// Try to load existing keys
	if privateKeyPath != "" && publicKeyPath != "" {
		privateKey, err := loadPrivateKey(privateKeyPath)
		if err == nil {
			publicKey, err := loadPublicKey(publicKeyPath)
			if err == nil {
				return privateKey, publicKey, nil
			}
		}
	}
	
	// Generate new keys if loading failed
	privateKey, err := rsa.GenerateKey(rand.Reader, keySize)
	if err != nil {
		return nil, nil, err
	}
	
	publicKey := &privateKey.PublicKey
	
	// Save keys if paths are provided
	if privateKeyPath != "" {
		savePrivateKey(privateKeyPath, privateKey)
	}
	if publicKeyPath != "" {
		savePublicKey(publicKeyPath, publicKey)
	}
	
	return privateKey, publicKey, nil
}

func loadPrivateKey(path string) (*rsa.PrivateKey, error) {
	keyData, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	
	block, _ := pem.Decode(keyData)
	if block == nil {
		return nil, fmt.Errorf("invalid PEM data")
	}
	
	return x509.ParsePKCS1PrivateKey(block.Bytes)
}

func loadPublicKey(path string) (*rsa.PublicKey, error) {
	keyData, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	
	block, _ := pem.Decode(keyData)
	if block == nil {
		return nil, fmt.Errorf("invalid PEM data")
	}
	
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	
	return pub.(*rsa.PublicKey), nil
}

func savePrivateKey(path string, key *rsa.PrivateKey) error {
	keyBytes := x509.MarshalPKCS1PrivateKey(key)
	keyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: keyBytes,
	})
	
	return os.WriteFile(path, keyPEM, 0600)
}

func savePublicKey(path string, key *rsa.PublicKey) error {
	keyBytes, err := x509.MarshalPKIXPublicKey(key)
	if err != nil {
		return err
	}
	
	keyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: keyBytes,
	})
	
	return os.WriteFile(path, keyPEM, 0644)
}

func (cs *CredentialService) setupRouter() *gin.Engine {
	gin.SetMode(gin.ReleaseMode)
	r := gin.New()
	
	// Middleware
	r.Use(cs.loggingMiddleware())
	r.Use(cs.metricsMiddleware())
	r.Use(cs.rateLimitMiddleware())
	r.Use(gin.Recovery())
	
	// Health endpoints
	r.GET("/health", cs.healthCheck)
	r.GET("/ready", cs.readinessCheck)
	r.GET("/metrics", gin.WrapH(promhttp.Handler()))
	
	// Public key endpoint
	r.GET("/public-key", cs.getPublicKey)
	
	// Credential endpoints
	r.POST("/credentials", cs.issueCredential)
	r.POST("/credentials/batch", cs.issueBatchCredentials)
	r.GET("/credentials/:id", cs.getCredential)
	r.POST("/credentials/:id/revoke", cs.revokeCredential)
	r.POST("/credentials/verify", cs.verifyCredential)
	
	// Holder endpoints
	r.GET("/holders/:holder_id/credentials", cs.getHolderCredentials)
	r.GET("/holders/:holder_id/credentials/active", cs.getActiveCredentials)
	
	// Analytics endpoints
	r.GET("/analytics/statistics", cs.getCredentialStatistics)
	r.GET("/analytics/revocation-reasons", cs.getRevocationAnalytics)
	
	return r
}

func (cs *CredentialService) loggingMiddleware() gin.HandlerFunc {
	return gin.LoggerWithWriter(gin.DefaultWriter, "/health", "/ready", "/metrics")
}

func (cs *CredentialService) metricsMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		start := time.Now()
		
		defer func() {
			duration := time.Since(start)
			cs.metrics.RequestDuration.Observe(duration.Seconds())
		}()
		
		c.Next()
	}
}

func (cs *CredentialService) rateLimitMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		if !cs.rateLimiter.Allow() {
			cs.respondWithError(c, http.StatusTooManyRequests, "Rate limit exceeded")
			c.Abort()
			return
		}
		c.Next()
	}
}

func (cs *CredentialService) issueCredential(c *gin.Context) {
	var req CredentialRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		cs.respondWithError(c, http.StatusBadRequest, err.Error())
		return
	}
	
	if err := cs.validator.Struct(&req); err != nil {
		cs.respondWithError(c, http.StatusBadRequest, fmt.Sprintf("Validation error: %v", err))
		return
	}
	
	// Create credential
	credential := &DigitalCredential{
		ID:        uuid.New().String(),
		Type:      req.Type,
		HolderID:  req.HolderID,
		IssuerID:  "digital-identity-authority", // Should come from authentication
		Status:    "active",
		Level:     req.Level,
		Claims:    req.Claims,
		Metadata:  req.Metadata,
		IssuedAt:  time.Now(),
		ExpiresAt: time.Now().Add(req.ValidityPeriod),
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}
	
	// Generate verification hash
	credential.VerificationHash = cs.generateVerificationHash(credential)
	
	// Sign credential
	signature, err := cs.signCredential(credential)
	if err != nil {
		cs.logger.Error("Failed to sign credential", zap.Error(err))
		cs.respondWithError(c, http.StatusInternalServerError, "Failed to sign credential")
		return
	}
	
	credential.Signature = signature
	cs.metrics.SigningOperations.Inc()
	
	// Save to database
	if err := cs.saveCredential(credential); err != nil {
		cs.logger.Error("Failed to save credential", zap.Error(err))
		cs.respondWithError(c, http.StatusInternalServerError, "Failed to save credential")
		return
	}
	
	cs.metrics.CredentialsIssued.Inc()
	cs.metrics.ActiveCredentials.Inc()
	
	// Create verifiable credential
	vc := cs.createVerifiableCredential(credential)
	
	// Generate QR code data
	qrCode := cs.generateQRCode(credential)
	
	response := CredentialResponse{
		Credential:           credential,
		VerifiableCredential: vc,
		QRCode:              qrCode,
		DownloadURL:         fmt.Sprintf("/credentials/%s/download", credential.ID),
		WalletImportURL:     fmt.Sprintf("/credentials/%s/import", credential.ID),
	}
	
	cs.respondWithSuccess(c, response)
}

func (cs *CredentialService) issueBatchCredentials(c *gin.Context) {
	var batch CredentialBatch
	if err := c.ShouldBindJSON(&batch); err != nil {
		cs.respondWithError(c, http.StatusBadRequest, err.Error())
		return
	}
	
	if err := cs.validator.Struct(&batch); err != nil {
		cs.respondWithError(c, http.StatusBadRequest, fmt.Sprintf("Validation error: %v", err))
		return
	}
	
	results := make([]CredentialResponse, 0, len(batch.Credentials))
	
	// Process each credential in the batch
	for _, req := range batch.Credentials {
		credential := &DigitalCredential{
			ID:        uuid.New().String(),
			Type:      req.Type,
			HolderID:  req.HolderID,
			IssuerID:  batch.IssuerID,
			Status:    "active",
			Level:     req.Level,
			Claims:    req.Claims,
			Metadata:  req.Metadata,
			IssuedAt:  time.Now(),
			ExpiresAt: time.Now().Add(req.ValidityPeriod),
			CreatedAt: time.Now(),
			UpdatedAt: time.Now(),
		}
		
		credential.VerificationHash = cs.generateVerificationHash(credential)
		
		signature, err := cs.signCredential(credential)
		if err != nil {
			cs.logger.Error("Failed to sign batch credential", zap.Error(err))
			continue
		}
		
		credential.Signature = signature
		
		if err := cs.saveCredential(credential); err != nil {
			cs.logger.Error("Failed to save batch credential", zap.Error(err))
			continue
		}
		
		vc := cs.createVerifiableCredential(credential)
		qrCode := cs.generateQRCode(credential)
		
		results = append(results, CredentialResponse{
			Credential:           credential,
			VerifiableCredential: vc,
			QRCode:              qrCode,
			DownloadURL:         fmt.Sprintf("/credentials/%s/download", credential.ID),
			WalletImportURL:     fmt.Sprintf("/credentials/%s/import", credential.ID),
		})
		
		cs.metrics.CredentialsIssued.Inc()
		cs.metrics.ActiveCredentials.Inc()
	}
	
	response := map[string]interface{}{
		"batch_id":     batch.BatchID,
		"total":        len(batch.Credentials),
		"successful":   len(results),
		"failed":       len(batch.Credentials) - len(results),
		"credentials":  results,
		"issued_at":    time.Now(),
	}
	
	cs.respondWithSuccess(c, response)
}

func (cs *CredentialService) getCredential(c *gin.Context) {
	credentialID := c.Param("id")
	
	credential, err := cs.getCredentialByID(credentialID)
	if err != nil {
		cs.respondWithError(c, http.StatusNotFound, "Credential not found")
		return
	}
	
	cs.respondWithSuccess(c, credential)
}

func (cs *CredentialService) revokeCredential(c *gin.Context) {
	credentialID := c.Param("id")
	
	var req RevocationRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		cs.respondWithError(c, http.StatusBadRequest, err.Error())
		return
	}
	
	if err := cs.validator.Struct(&req); err != nil {
		cs.respondWithError(c, http.StatusBadRequest, fmt.Sprintf("Validation error: %v", err))
		return
	}
	
	// Revoke credential
	revokedAt := time.Now()
	if err := cs.revokeCredentialInDB(credentialID, req.Reason, req.RevokerID, revokedAt); err != nil {
		cs.logger.Error("Failed to revoke credential", zap.Error(err))
		cs.respondWithError(c, http.StatusInternalServerError, "Failed to revoke credential")
		return
	}
	
	cs.metrics.CredentialsRevoked.Inc()
	cs.metrics.ActiveCredentials.Dec()
	
	response := map[string]interface{}{
		"credential_id":      credentialID,
		"status":            "revoked",
		"revoked_at":        revokedAt,
		"revocation_reason": req.Reason,
		"revoked_by":        req.RevokerID,
	}
	
	cs.respondWithSuccess(c, response)
}

func (cs *CredentialService) verifyCredential(c *gin.Context) {
	var req VerificationRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		cs.respondWithError(c, http.StatusBadRequest, err.Error())
		return
	}
	
	if err := cs.validator.Struct(&req); err != nil {
		cs.respondWithError(c, http.StatusBadRequest, fmt.Sprintf("Validation error: %v", err))
		return
	}
	
	result := cs.performVerification(&req)
	
	if result.Valid {
		cs.metrics.CredentialsVerified.Inc()
	} else {
		cs.metrics.VerificationFailed.Inc()
	}
	
	cs.respondWithSuccess(c, result)
}

func (cs *CredentialService) getHolderCredentials(c *gin.Context) {
	holderID := c.Param("holder_id")
	
	credentials, err := cs.getCredentialsByHolderID(holderID)
	if err != nil {
		cs.logger.Error("Failed to get holder credentials", zap.Error(err))
		cs.respondWithError(c, http.StatusInternalServerError, "Failed to retrieve credentials")
		return
	}
	
	response := map[string]interface{}{
		"holder_id":    holderID,
		"total":        len(credentials),
		"credentials":  credentials,
		"retrieved_at": time.Now(),
	}
	
	cs.respondWithSuccess(c, response)
}

func (cs *CredentialService) getActiveCredentials(c *gin.Context) {
	holderID := c.Param("holder_id")
	
	credentials, err := cs.getActiveCredentialsByHolderID(holderID)
	if err != nil {
		cs.logger.Error("Failed to get active credentials", zap.Error(err))
		cs.respondWithError(c, http.StatusInternalServerError, "Failed to retrieve active credentials")
		return
	}
	
	response := map[string]interface{}{
		"holder_id":           holderID,
		"active_credentials":  len(credentials),
		"credentials":         credentials,
		"retrieved_at":        time.Now(),
	}
	
	cs.respondWithSuccess(c, response)
}

func (cs *CredentialService) getPublicKey(c *gin.Context) {
	// Export public key in PEM format
	keyBytes, err := x509.MarshalPKIXPublicKey(cs.publicKey)
	if err != nil {
		cs.respondWithError(c, http.StatusInternalServerError, "Failed to export public key")
		return
	}
	
	keyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: keyBytes,
	})
	
	response := map[string]interface{}{
		"public_key_pem": string(keyPEM),
		"key_id":         cs.generateKeyID(),
		"algorithm":      "RS256",
		"usage":          []string{"sig", "verify"},
	}
	
	cs.respondWithSuccess(c, response)
}

func (cs *CredentialService) getCredentialStatistics(c *gin.Context) {
	stats := cs.calculateCredentialStatistics()
	cs.respondWithSuccess(c, stats)
}

func (cs *CredentialService) getRevocationAnalytics(c *gin.Context) {
	analytics := cs.calculateRevocationAnalytics()
	cs.respondWithSuccess(c, analytics)
}

func (cs *CredentialService) healthCheck(c *gin.Context) {
	status := map[string]interface{}{
		"status":    "healthy",
		"version":   "1.0.0",
		"timestamp": time.Now(),
		"uptime":    time.Since(cs.startTime),
	}
	
	// Check database health
	if err := cs.db.Ping(); err != nil {
		status["status"] = "unhealthy"
		status["database"] = "disconnected"
	} else {
		status["database"] = "connected"
	}
	
	// Check Redis health
	if err := cs.redis.Ping(context.Background()).Err(); err != nil {
		status["redis"] = "disconnected"
	} else {
		status["redis"] = "connected"
	}
	
	// Check cryptographic keys
	if cs.privateKey != nil && cs.publicKey != nil {
		status["crypto"] = "ready"
	} else {
		status["crypto"] = "error"
		status["status"] = "unhealthy"
	}
	
	cs.respondWithSuccess(c, status)
}

func (cs *CredentialService) readinessCheck(c *gin.Context) {
	if err := cs.db.Ping(); err != nil {
		cs.respondWithError(c, http.StatusServiceUnavailable, "Database not ready")
		return
	}
	
	if cs.privateKey == nil || cs.publicKey == nil {
		cs.respondWithError(c, http.StatusServiceUnavailable, "Cryptographic keys not ready")
		return
	}
	
	cs.respondWithSuccess(c, map[string]string{"status": "ready"})
}

// Core credential operations
func (cs *CredentialService) signCredential(credential *DigitalCredential) (string, error) {
	// Create signing payload
	payload := map[string]interface{}{
		"id":                credential.ID,
		"type":             credential.Type,
		"holder_id":        credential.HolderID,
		"issuer_id":        credential.IssuerID,
		"level":            credential.Level,
		"claims":           credential.Claims,
		"issued_at":        credential.IssuedAt.Unix(),
		"expires_at":       credential.ExpiresAt.Unix(),
		"verification_hash": credential.VerificationHash,
	}
	
	payloadJSON, _ := json.Marshal(payload)
	
	// Create hash
	hash := sha256.Sum256(payloadJSON)
	
	// Sign with RSA private key
	signature, err := rsa.SignPKCS1v15(rand.Reader, cs.privateKey, crypto.SHA256, hash[:])
	if err != nil {
		return "", err
	}
	
	return base64.StdEncoding.EncodeToString(signature), nil
}

func (cs *CredentialService) verifySignature(credential *DigitalCredential, signature string) bool {
	// Decode signature
	sigBytes, err := base64.StdEncoding.DecodeString(signature)
	if err != nil {
		return false
	}
	
	// Recreate signing payload
	payload := map[string]interface{}{
		"id":                credential.ID,
		"type":             credential.Type,
		"holder_id":        credential.HolderID,
		"issuer_id":        credential.IssuerID,
		"level":            credential.Level,
		"claims":           credential.Claims,
		"issued_at":        credential.IssuedAt.Unix(),
		"expires_at":       credential.ExpiresAt.Unix(),
		"verification_hash": credential.VerificationHash,
	}
	
	payloadJSON, _ := json.Marshal(payload)
	hash := sha256.Sum256(payloadJSON)
	
	// Verify signature
	err = rsa.VerifyPKCS1v15(cs.publicKey, crypto.SHA256, hash[:], sigBytes)
	return err == nil
}

func (cs *CredentialService) generateVerificationHash(credential *DigitalCredential) string {
	data := fmt.Sprintf("%s:%s:%s:%d", credential.HolderID, credential.Type, credential.Level, credential.IssuedAt.Unix())
	hash := sha256.Sum256([]byte(data))
	return base64.StdEncoding.EncodeToString(hash[:])
}

func (cs *CredentialService) generateKeyID() string {
	keyBytes, _ := x509.MarshalPKIXPublicKey(cs.publicKey)
	hash := sha256.Sum256(keyBytes)
	return base64.StdEncoding.EncodeToString(hash[:8]) // First 8 bytes
}

func (cs *CredentialService) createVerifiableCredential(credential *DigitalCredential) *VerifiableCredential {
	return &VerifiableCredential{
		Context: []string{
			"https://www.w3.org/2018/credentials/v1",
			"https://digital-identity.gov.uk/contexts/v1",
		},
		Type: []string{
			"VerifiableCredential",
			credential.Type,
		},
		Issuer:            credential.IssuerID,
		IssuanceDate:      credential.IssuedAt.Format(time.RFC3339),
		ExpirationDate:    credential.ExpiresAt.Format(time.RFC3339),
		CredentialSubject: credential.Claims,
		Proof: Proof{
			Type:               "RsaSignature2018",
			Created:            credential.IssuedAt.Format(time.RFC3339),
			ProofPurpose:       "assertionMethod",
			VerificationMethod: fmt.Sprintf("https://digital-identity.gov.uk/keys/%s", cs.generateKeyID()),
			JWS:                credential.Signature,
		},
	}
}

func (cs *CredentialService) generateQRCode(credential *DigitalCredential) string {
	// Generate QR code data (URL or encoded credential)
	qrData := map[string]interface{}{
		"credential_id": credential.ID,
		"verification_url": fmt.Sprintf("https://digital-identity.gov.uk/verify/%s", credential.ID),
		"hash": credential.VerificationHash,
	}
	
	qrJSON, _ := json.Marshal(qrData)
	return base64.StdEncoding.EncodeToString(qrJSON)
}

func (cs *CredentialService) performVerification(req *VerificationRequest) *VerificationResult {
	result := &VerificationResult{
		VerificationDetails: make(map[string]interface{}),
		Warnings:           make([]string, 0),
		VerifiedAt:         time.Now(),
	}
	
	var credential *DigitalCredential
	var err error
	
	if req.CredentialID != "" {
		credential, err = cs.getCredentialByID(req.CredentialID)
		if err != nil {
			result.Valid = false
			result.Status = "not_found"
			return result
		}
		result.CredentialID = req.CredentialID
	} else if req.CredentialData != "" {
		// Decode and parse credential data
		// Implementation would depend on the format
		result.Valid = false
		result.Status = "unsupported_format"
		return result
	}
	
	// Verify signature
	result.SignatureValid = cs.verifySignature(credential, credential.Signature)
	if !result.SignatureValid {
		result.Warnings = append(result.Warnings, "Invalid signature")
	}
	
	// Check expiration
	result.NotExpired = time.Now().Before(credential.ExpiresAt)
	if !result.NotExpired {
		result.Warnings = append(result.Warnings, "Credential has expired")
	}
	
	// Check revocation status
	result.NotRevoked = credential.Status == "active"
	if !result.NotRevoked {
		result.Warnings = append(result.Warnings, "Credential has been revoked")
	}
	
	// Check issuer trust (simplified)
	result.IssuerTrusted = credential.IssuerID == "digital-identity-authority"
	if !result.IssuerTrusted {
		result.Warnings = append(result.Warnings, "Issuer is not trusted")
	}
	
	// Overall validity
	result.Valid = result.SignatureValid && result.NotExpired && result.NotRevoked && result.IssuerTrusted
	
	if result.Valid {
		result.Status = "valid"
	} else {
		result.Status = "invalid"
	}
	
	result.VerificationDetails = map[string]interface{}{
		"credential_type":  credential.Type,
		"credential_level": credential.Level,
		"issued_at":       credential.IssuedAt,
		"expires_at":      credential.ExpiresAt,
		"holder_id":       credential.HolderID,
		"issuer_id":       credential.IssuerID,
	}
	
	return result
}

// Database operations
func (cs *CredentialService) saveCredential(credential *DigitalCredential) error {
	query := `
		INSERT INTO credentials 
		(id, type, holder_id, issuer_id, status, level, claims, metadata, signature,
		 issued_at, expires_at, verification_hash, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)`
	
	claimsJSON, _ := json.Marshal(credential.Claims)
	metadataJSON, _ := json.Marshal(credential.Metadata)
	
	_, err := cs.db.Exec(query,
		credential.ID, credential.Type, credential.HolderID, credential.IssuerID,
		credential.Status, credential.Level, string(claimsJSON), string(metadataJSON),
		credential.Signature, credential.IssuedAt, credential.ExpiresAt,
		credential.VerificationHash, credential.CreatedAt, credential.UpdatedAt)
	
	return err
}

func (cs *CredentialService) getCredentialByID(credentialID string) (*DigitalCredential, error) {
	credential := &DigitalCredential{}
	
	query := `
		SELECT id, type, holder_id, issuer_id, status, level, claims, metadata, signature,
		       issued_at, expires_at, revoked_at, revocation_reason, verification_hash,
		       created_at, updated_at
		FROM credentials WHERE id = $1`
	
	var claimsJSON, metadataJSON string
	
	err := cs.db.QueryRow(query, credentialID).Scan(
		&credential.ID, &credential.Type, &credential.HolderID, &credential.IssuerID,
		&credential.Status, &credential.Level, &claimsJSON, &metadataJSON,
		&credential.Signature, &credential.IssuedAt, &credential.ExpiresAt,
		&credential.RevokedAt, &credential.RevocationReason, &credential.VerificationHash,
		&credential.CreatedAt, &credential.UpdatedAt)
	
	if err != nil {
		return nil, err
	}
	
	json.Unmarshal([]byte(claimsJSON), &credential.Claims)
	json.Unmarshal([]byte(metadataJSON), &credential.Metadata)
	
	return credential, nil
}

func (cs *CredentialService) revokeCredentialInDB(credentialID, reason, revokerID string, revokedAt time.Time) error {
	query := `
		UPDATE credentials 
		SET status = 'revoked', revoked_at = $2, revocation_reason = $3, updated_at = $4
		WHERE id = $1`
	
	_, err := cs.db.Exec(query, credentialID, revokedAt, reason, time.Now())
	return err
}

func (cs *CredentialService) getCredentialsByHolderID(holderID string) ([]DigitalCredential, error) {
	query := `
		SELECT id, type, holder_id, issuer_id, status, level, claims, metadata, signature,
		       issued_at, expires_at, revoked_at, revocation_reason, verification_hash,
		       created_at, updated_at
		FROM credentials WHERE holder_id = $1 ORDER BY created_at DESC`
	
	rows, err := cs.db.Query(query, holderID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	
	var credentials []DigitalCredential
	
	for rows.Next() {
		credential := DigitalCredential{}
		var claimsJSON, metadataJSON string
		
		err := rows.Scan(
			&credential.ID, &credential.Type, &credential.HolderID, &credential.IssuerID,
			&credential.Status, &credential.Level, &claimsJSON, &metadataJSON,
			&credential.Signature, &credential.IssuedAt, &credential.ExpiresAt,
			&credential.RevokedAt, &credential.RevocationReason, &credential.VerificationHash,
			&credential.CreatedAt, &credential.UpdatedAt)
		
		if err != nil {
			continue
		}
		
		json.Unmarshal([]byte(claimsJSON), &credential.Claims)
		json.Unmarshal([]byte(metadataJSON), &credential.Metadata)
		
		credentials = append(credentials, credential)
	}
	
	return credentials, nil
}

func (cs *CredentialService) getActiveCredentialsByHolderID(holderID string) ([]DigitalCredential, error) {
	query := `
		SELECT id, type, holder_id, issuer_id, status, level, claims, metadata, signature,
		       issued_at, expires_at, verification_hash, created_at, updated_at
		FROM credentials 
		WHERE holder_id = $1 AND status = 'active' AND expires_at > NOW()
		ORDER BY created_at DESC`
	
	rows, err := cs.db.Query(query, holderID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	
	var credentials []DigitalCredential
	
	for rows.Next() {
		credential := DigitalCredential{}
		var claimsJSON, metadataJSON string
		
		err := rows.Scan(
			&credential.ID, &credential.Type, &credential.HolderID, &credential.IssuerID,
			&credential.Status, &credential.Level, &claimsJSON, &metadataJSON,
			&credential.Signature, &credential.IssuedAt, &credential.ExpiresAt,
			&credential.VerificationHash, &credential.CreatedAt, &credential.UpdatedAt)
		
		if err != nil {
			continue
		}
		
		json.Unmarshal([]byte(claimsJSON), &credential.Claims)
		json.Unmarshal([]byte(metadataJSON), &credential.Metadata)
		
		credentials = append(credentials, credential)
	}
	
	return credentials, nil
}

func (cs *CredentialService) calculateCredentialStatistics() map[string]interface{} {
	var totalCredentials, activeCredentials, revokedCredentials, expiredCredentials int
	
	// Get total credentials
	cs.db.QueryRow("SELECT COUNT(*) FROM credentials").Scan(&totalCredentials)
	
	// Get active credentials
	cs.db.QueryRow("SELECT COUNT(*) FROM credentials WHERE status = 'active' AND expires_at > NOW()").Scan(&activeCredentials)
	
	// Get revoked credentials
	cs.db.QueryRow("SELECT COUNT(*) FROM credentials WHERE status = 'revoked'").Scan(&revokedCredentials)
	
	// Get expired credentials
	cs.db.QueryRow("SELECT COUNT(*) FROM credentials WHERE expires_at <= NOW()").Scan(&expiredCredentials)
	
	return map[string]interface{}{
		"total_credentials":   totalCredentials,
		"active_credentials":  activeCredentials,
		"revoked_credentials": revokedCredentials,
		"expired_credentials": expiredCredentials,
		"utilization_rate":    float64(activeCredentials) / float64(totalCredentials),
		"timestamp":          time.Now(),
	}
}

func (cs *CredentialService) calculateRevocationAnalytics() map[string]interface{} {
	// Get revocation reasons
	rows, err := cs.db.Query(`
		SELECT revocation_reason, COUNT(*) 
		FROM credentials 
		WHERE status = 'revoked' AND revocation_reason IS NOT NULL
		GROUP BY revocation_reason
		ORDER BY COUNT(*) DESC`)
	
	reasonStats := make(map[string]int)
	
	if err == nil {
		defer rows.Close()
		for rows.Next() {
			var reason string
			var count int
			if rows.Scan(&reason, &count) == nil {
				reasonStats[reason] = count
			}
		}
	}
	
	return map[string]interface{}{
		"revocation_reasons": reasonStats,
		"timestamp":         time.Now(),
	}
}

func (cs *CredentialService) respondWithSuccess(c *gin.Context, data interface{}) {
	response := APIResponse{
		Success:   true,
		Data:      data,
		RequestID: uuid.New().String(),
		Timestamp: time.Now(),
	}
	c.JSON(http.StatusOK, response)
}

func (cs *CredentialService) respondWithError(c *gin.Context, code int, message string) {
	response := APIResponse{
		Success:   false,
		Error:     message,
		RequestID: uuid.New().String(),
		Timestamp: time.Now(),
	}
	c.JSON(code, response)
}

func (cs *CredentialService) Start() error {
	router := cs.setupRouter()
	
	server := &http.Server{
		Addr:    cs.config.Server.Host + ":" + cs.config.Server.Port,
		Handler: router,
	}
	
	cs.logger.Info("Starting credential service",
		zap.String("addr", server.Addr),
	)
	
	// Graceful shutdown
	go func() {
		sigChan := make(chan os.Signal, 1)
		signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
		<-sigChan
		
		cs.logger.Info("Shutting down credential service...")
		
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		
		if err := server.Shutdown(ctx); err != nil {
			cs.logger.Error("Server shutdown error", zap.Error(err))
		}
		
		cs.db.Close()
		cs.redis.Close()
	}()
	
	return server.ListenAndServe()
}

func main() {
	// Initialize logger
	logger, _ := zap.NewProduction()
	defer logger.Sync()
	
	// Load configuration
	config, err := loadConfig()
	if err != nil {
		logger.Fatal("Failed to load config", zap.Error(err))
	}
	
	// Create and start service
	service, err := NewCredentialService(config, logger)
	if err != nil {
		logger.Fatal("Failed to create credential service", zap.Error(err))
	}
	
	if err := service.Start(); err != nil && err != http.ErrServerClosed {
		logger.Fatal("Credential service failed", zap.Error(err))
	}
}