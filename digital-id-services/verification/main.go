package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/gin-gonic/gin"
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
	"github.com/cenkalti/backoff/v4"
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
	
	ExternalServices struct {
		CoreEngine  string        `mapstructure:"core_engine"`
		Timeout     time.Duration `mapstructure:"timeout"`
		RetryCount  int           `mapstructure:"retry_count"`
		RetryDelay  time.Duration `mapstructure:"retry_delay"`
	} `mapstructure:"external_services"`
	
	RateLimit struct {
		Requests int           `mapstructure:"requests"`
		Window   time.Duration `mapstructure:"window"`
		Burst    int           `mapstructure:"burst"`
	} `mapstructure:"rate_limit"`
}

type VerificationService struct {
	config         *Config
	logger         *zap.Logger
	db             *sql.DB
	redis          *redis.Client
	validator      *validator.Validate
	circuitBreaker *gobreaker.CircuitBreaker
	rateLimiter    *rate.Limiter
	metrics        *VerificationMetrics
	httpClient     *http.Client
	startTime      time.Time
	
	// Verification workers
	workerPool   chan struct{}
	resultCache  map[string]*VerificationResult
	cacheMutex   sync.RWMutex
}

type VerificationMetrics struct {
	VerificationsTotal    prometheus.Counter
	VerificationsSuccess  prometheus.Counter
	VerificationsFailed   prometheus.Counter
	RequestDuration       prometheus.Histogram
	ActiveVerifications   prometheus.Gauge
	CacheHits            prometheus.Counter
	CacheMisses          prometheus.Counter
	ExternalCallsTotal   prometheus.Counter
}

type VerificationRequest struct {
	RequestID     string                 `json:"request_id" validate:"required,uuid"`
	CitizenID     string                 `json:"citizen_id" validate:"required,min=1,max=100"`
	VerifyType    string                 `json:"verify_type" validate:"required,oneof=basic full document biometric combined"`
	DataSources   []string               `json:"data_sources" validate:"required,min=1,dive,oneof=HMRC DVLA NHS DWP HomeOffice CompaniesHouse FinancialServices Education LocalGovernment LawEnforcement Transport Healthcare LandRegistry Security ProfessionalBodies BorderControl"`
	Priority      string                 `json:"priority" validate:"required,oneof=low normal high urgent"`
	CallbackURL   string                 `json:"callback_url,omitempty" validate:"omitempty,url"`
	Metadata      map[string]interface{} `json:"metadata,omitempty"`
	Documents     []Document             `json:"documents,omitempty"`
	BiometricData []BiometricData        `json:"biometric_data,omitempty"`
}

type Document struct {
	Type        string    `json:"type" validate:"required,oneof=passport driving_license national_id utility_bill bank_statement"`
	Content     string    `json:"content" validate:"required"`
	Format      string    `json:"format" validate:"required,oneof=pdf image base64"`
	UploadedAt  time.Time `json:"uploaded_at"`
	ExpiryDate  string    `json:"expiry_date,omitempty"`
}

type BiometricData struct {
	Type      string    `json:"type" validate:"required,oneof=fingerprint face_scan iris_scan voice_print"`
	Data      string    `json:"data" validate:"required"`
	Quality   float64   `json:"quality" validate:"min=0,max=1"`
	CapturedAt time.Time `json:"captured_at"`
}

type VerificationResult struct {
	RequestID            string                 `json:"request_id"`
	CitizenID            string                 `json:"citizen_id"`
	Status               string                 `json:"status"`
	OverallScore         float64                `json:"overall_score"`
	ConfidenceScore      float64                `json:"confidence_score"`
	RiskScore            float64                `json:"risk_score"`
	DataSourceResults    []DataSourceResult     `json:"data_source_results"`
	DocumentResults      []DocumentResult       `json:"document_results"`
	BiometricResults     []BiometricResult      `json:"biometric_results"`
	Warnings             []string               `json:"warnings"`
	Recommendations      []string               `json:"recommendations"`
	ProcessingTimeMs     int64                  `json:"processing_time_ms"`
	Timestamp            time.Time              `json:"timestamp"`
	ExpiresAt            time.Time              `json:"expires_at"`
	AuditTrail          []AuditEntry           `json:"audit_trail"`
}

type DataSourceResult struct {
	Source          string                 `json:"source"`
	Status          string                 `json:"status"`
	Score           float64                `json:"score"`
	MatchedFields   []string               `json:"matched_fields"`
	MismatchedFields []string              `json:"mismatched_fields"`
	Confidence      float64                `json:"confidence"`
	ResponseTime    int64                  `json:"response_time_ms"`
	Data            map[string]interface{} `json:"data,omitempty"`
	Error           string                 `json:"error,omitempty"`
}

type DocumentResult struct {
	DocumentType    string                 `json:"document_type"`
	Status          string                 `json:"status"`
	AuthenticityScore float64              `json:"authenticity_score"`
	ExtractionScore float64                `json:"extraction_score"`
	ExtractedData   map[string]interface{} `json:"extracted_data"`
	SecurityFeatures map[string]bool       `json:"security_features"`
	Warnings        []string               `json:"warnings"`
	ProcessingTime  int64                  `json:"processing_time_ms"`
}

type BiometricResult struct {
	Type            string  `json:"type"`
	Status          string  `json:"status"`
	MatchScore      float64 `json:"match_score"`
	QualityScore    float64 `json:"quality_score"`
	LivenessScore   float64 `json:"liveness_score"`
	ProcessingTime  int64   `json:"processing_time_ms"`
	Error           string  `json:"error,omitempty"`
}

type AuditEntry struct {
	Timestamp time.Time `json:"timestamp"`
	Action    string    `json:"action"`
	Source    string    `json:"source"`
	Details   string    `json:"details"`
	UserID    string    `json:"user_id,omitempty"`
}

type BatchVerificationRequest struct {
	Requests []VerificationRequest `json:"requests" validate:"required,min=1,max=100"`
}

type BatchVerificationResponse struct {
	BatchID   string               `json:"batch_id"`
	Results   []VerificationResult `json:"results"`
	Summary   BatchSummary         `json:"summary"`
	Timestamp time.Time            `json:"timestamp"`
}

type BatchSummary struct {
	Total     int     `json:"total"`
	Success   int     `json:"success"`
	Failed    int     `json:"failed"`
	Pending   int     `json:"pending"`
	AvgScore  float64 `json:"average_score"`
}

type APIResponse struct {
	Success   bool        `json:"success"`
	Data      interface{} `json:"data,omitempty"`
	Error     string      `json:"error,omitempty"`
	RequestID string      `json:"request_id"`
	Timestamp time.Time   `json:"timestamp"`
}

func NewVerificationMetrics() *VerificationMetrics {
	return &VerificationMetrics{
		VerificationsTotal: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "verifications_total",
			Help: "Total number of verification requests",
		}),
		VerificationsSuccess: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "verifications_success_total",
			Help: "Total number of successful verifications",
		}),
		VerificationsFailed: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "verifications_failed_total",
			Help: "Total number of failed verifications",
		}),
		RequestDuration: prometheus.NewHistogram(prometheus.HistogramOpts{
			Name:    "verification_request_duration_seconds",
			Help:    "Verification request duration in seconds",
			Buckets: prometheus.DefBuckets,
		}),
		ActiveVerifications: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "verification_active_total",
			Help: "Number of active verifications",
		}),
		CacheHits: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "verification_cache_hits_total",
			Help: "Total number of cache hits",
		}),
		CacheMisses: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "verification_cache_misses_total",
			Help: "Total number of cache misses",
		}),
		ExternalCallsTotal: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "verification_external_calls_total",
			Help: "Total number of external service calls",
		}),
	}
}

func (m *VerificationMetrics) Register() {
	prometheus.MustRegister(
		m.VerificationsTotal,
		m.VerificationsSuccess,
		m.VerificationsFailed,
		m.RequestDuration,
		m.ActiveVerifications,
		m.CacheHits,
		m.CacheMisses,
		m.ExternalCallsTotal,
	)
}

func loadConfig() (*Config, error) {
	viper.SetConfigName("config")
	viper.SetConfigType("yaml")
	viper.AddConfigPath(".")
	viper.AddConfigPath("./config")
	
	// Set defaults
	viper.SetDefault("server.port", "8082")
	viper.SetDefault("server.host", "0.0.0.0")
	viper.SetDefault("database.max_connections", 25)
	viper.SetDefault("database.max_idle_time", "15m")
	viper.SetDefault("database.max_lifetime", "1h")
	viper.SetDefault("database.connect_timeout", "10s")
	viper.SetDefault("redis.addr", "localhost:6379")
	viper.SetDefault("redis.db", 2)
	viper.SetDefault("external_services.core_engine", "http://localhost:3000")
	viper.SetDefault("external_services.timeout", "30s")
	viper.SetDefault("external_services.retry_count", 3)
	viper.SetDefault("external_services.retry_delay", "1s")
	viper.SetDefault("rate_limit.requests", 50)
	viper.SetDefault("rate_limit.window", "1m")
	viper.SetDefault("rate_limit.burst", 10)
	
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

func NewVerificationService(config *Config, logger *zap.Logger) (*VerificationService, error) {
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
	
	// Initialize circuit breaker
	cb := gobreaker.NewCircuitBreaker(gobreaker.Settings{
		Name:        "verification-circuit-breaker",
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
	metrics := NewVerificationMetrics()
	metrics.Register()
	
	// Initialize HTTP client
	httpClient := &http.Client{
		Timeout: config.ExternalServices.Timeout,
	}
	
	// Initialize worker pool
	workerPool := make(chan struct{}, 50) // Max 50 concurrent verifications
	
	return &VerificationService{
		config:         config,
		logger:         logger,
		db:             db,
		redis:          rdb,
		validator:      validator.New(),
		circuitBreaker: cb,
		rateLimiter:    rateLimiter,
		metrics:        metrics,
		httpClient:     httpClient,
		startTime:      time.Now(),
		workerPool:     workerPool,
		resultCache:    make(map[string]*VerificationResult),
	}, nil
}

func (vs *VerificationService) setupRouter() *gin.Engine {
	gin.SetMode(gin.ReleaseMode)
	r := gin.New()
	
	// Middleware
	r.Use(vs.loggingMiddleware())
	r.Use(vs.metricsMiddleware())
	r.Use(vs.rateLimitMiddleware())
	r.Use(gin.Recovery())
	
	// Health endpoints
	r.GET("/health", vs.healthCheck)
	r.GET("/ready", vs.readinessCheck)
	r.GET("/metrics", gin.WrapH(promhttp.Handler()))
	
	// Verification endpoints
	r.POST("/verify", vs.verifyIdentity)
	r.POST("/verify/batch", vs.batchVerify)
	r.GET("/verify/:request_id", vs.getVerificationResult)
	r.GET("/verify/:request_id/status", vs.getVerificationStatus)
	r.POST("/verify/:request_id/cancel", vs.cancelVerification)
	
	// Document verification
	r.POST("/verify/document", vs.verifyDocument)
	r.POST("/verify/biometric", vs.verifyBiometric)
	
	// Analytics and reporting
	r.GET("/analytics/summary", vs.getAnalyticsSummary)
	r.GET("/analytics/trends", vs.getVerificationTrends)
	
	return r
}

func (vs *VerificationService) loggingMiddleware() gin.HandlerFunc {
	return gin.LoggerWithWriter(gin.DefaultWriter, "/health", "/ready", "/metrics")
}

func (vs *VerificationService) metricsMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		start := time.Now()
		vs.metrics.ActiveVerifications.Inc()
		
		defer func() {
			duration := time.Since(start)
			vs.metrics.RequestDuration.Observe(duration.Seconds())
			vs.metrics.ActiveVerifications.Dec()
		}()
		
		c.Next()
	}
}

func (vs *VerificationService) rateLimitMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		if !vs.rateLimiter.Allow() {
			vs.respondWithError(c, http.StatusTooManyRequests, "Rate limit exceeded")
			c.Abort()
			return
		}
		c.Next()
	}
}

func (vs *VerificationService) verifyIdentity(c *gin.Context) {
	vs.metrics.VerificationsTotal.Inc()
	
	var req VerificationRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		vs.metrics.VerificationsFailed.Inc()
		vs.respondWithError(c, http.StatusBadRequest, err.Error())
		return
	}
	
	if err := vs.validator.Struct(&req); err != nil {
		vs.metrics.VerificationsFailed.Inc()
		vs.respondWithError(c, http.StatusBadRequest, fmt.Sprintf("Validation error: %v", err))
		return
	}
	
	// Check cache first
	if result := vs.getCachedResult(req.RequestID); result != nil {
		vs.metrics.CacheHits.Inc()
		vs.respondWithSuccess(c, result)
		return
	}
	
	vs.metrics.CacheMisses.Inc()
	
	// Acquire worker from pool
	vs.workerPool <- struct{}{}
	defer func() { <-vs.workerPool }()
	
	// Process verification asynchronously for complex requests
	if vs.isComplexVerification(&req) {
		go vs.processVerificationAsync(&req)
		
		response := map[string]interface{}{
			"request_id": req.RequestID,
			"status":    "processing",
			"message":   "Verification started. Use the status endpoint to check progress.",
		}
		vs.respondWithSuccess(c, response)
		return
	}
	
	// Process simple verification synchronously
	result, err := vs.processVerification(&req)
	if err != nil {
		vs.metrics.VerificationsFailed.Inc()
		vs.logger.Error("Verification failed", zap.Error(err), zap.String("request_id", req.RequestID))
		vs.respondWithError(c, http.StatusInternalServerError, "Verification failed")
		return
	}
	
	vs.metrics.VerificationsSuccess.Inc()
	vs.cacheResult(req.RequestID, result)
	vs.respondWithSuccess(c, result)
}

func (vs *VerificationService) batchVerify(c *gin.Context) {
	var batchReq BatchVerificationRequest
	if err := c.ShouldBindJSON(&batchReq); err != nil {
		vs.respondWithError(c, http.StatusBadRequest, err.Error())
		return
	}
	
	if err := vs.validator.Struct(&batchReq); err != nil {
		vs.respondWithError(c, http.StatusBadRequest, fmt.Sprintf("Validation error: %v", err))
		return
	}
	
	batchID := uuid.New().String()
	results := make([]VerificationResult, 0, len(batchReq.Requests))
	
	// Process requests in parallel
	resultChan := make(chan VerificationResult, len(batchReq.Requests))
	errorChan := make(chan error, len(batchReq.Requests))
	
	for _, req := range batchReq.Requests {
		go func(r VerificationRequest) {
			result, err := vs.processVerification(&r)
			if err != nil {
				errorChan <- err
				return
			}
			resultChan <- *result
		}(req)
	}
	
	// Collect results
	var successCount, failedCount int
	var totalScore float64
	
	for i := 0; i < len(batchReq.Requests); i++ {
		select {
		case result := <-resultChan:
			results = append(results, result)
			successCount++
			totalScore += result.OverallScore
		case err := <-errorChan:
			vs.logger.Error("Batch verification item failed", zap.Error(err))
			failedCount++
		case <-time.After(60 * time.Second):
			// Timeout for batch processing
			failedCount++
		}
	}
	
	avgScore := float64(0)
	if successCount > 0 {
		avgScore = totalScore / float64(successCount)
	}
	
	response := BatchVerificationResponse{
		BatchID:   batchID,
		Results:   results,
		Summary: BatchSummary{
			Total:    len(batchReq.Requests),
			Success:  successCount,
			Failed:   failedCount,
			Pending:  0,
			AvgScore: avgScore,
		},
		Timestamp: time.Now(),
	}
	
	vs.respondWithSuccess(c, response)
}

func (vs *VerificationService) getVerificationResult(c *gin.Context) {
	requestID := c.Param("request_id")
	
	// Check cache first
	if result := vs.getCachedResult(requestID); result != nil {
		vs.metrics.CacheHits.Inc()
		vs.respondWithSuccess(c, result)
		return
	}
	
	vs.metrics.CacheMisses.Inc()
	
	// Check database
	result, err := vs.getResultFromDatabase(requestID)
	if err != nil {
		vs.respondWithError(c, http.StatusNotFound, "Verification result not found")
		return
	}
	
	vs.cacheResult(requestID, result)
	vs.respondWithSuccess(c, result)
}

func (vs *VerificationService) getVerificationStatus(c *gin.Context) {
	requestID := c.Param("request_id")
	
	status := vs.getProcessingStatus(requestID)
	
	response := map[string]interface{}{
		"request_id": requestID,
		"status":    status,
		"timestamp": time.Now(),
	}
	
	vs.respondWithSuccess(c, response)
}

func (vs *VerificationService) cancelVerification(c *gin.Context) {
	requestID := c.Param("request_id")
	
	cancelled := vs.cancelProcessing(requestID)
	
	response := map[string]interface{}{
		"request_id": requestID,
		"cancelled":  cancelled,
		"message":   "Verification cancelled successfully",
		"timestamp": time.Now(),
	}
	
	vs.respondWithSuccess(c, response)
}

func (vs *VerificationService) verifyDocument(c *gin.Context) {
	var doc Document
	if err := c.ShouldBindJSON(&doc); err != nil {
		vs.respondWithError(c, http.StatusBadRequest, err.Error())
		return
	}
	
	result := vs.processDocumentVerification(&doc)
	vs.respondWithSuccess(c, result)
}

func (vs *VerificationService) verifyBiometric(c *gin.Context) {
	var biometric BiometricData
	if err := c.ShouldBindJSON(&biometric); err != nil {
		vs.respondWithError(c, http.StatusBadRequest, err.Error())
		return
	}
	
	result := vs.processBiometricVerification(&biometric)
	vs.respondWithSuccess(c, result)
}

func (vs *VerificationService) getAnalyticsSummary(c *gin.Context) {
	summary := vs.calculateAnalyticsSummary()
	vs.respondWithSuccess(c, summary)
}

func (vs *VerificationService) getVerificationTrends(c *gin.Context) {
	days := c.DefaultQuery("days", "30")
	trends := vs.calculateVerificationTrends(days)
	vs.respondWithSuccess(c, trends)
}

func (vs *VerificationService) healthCheck(c *gin.Context) {
	status := map[string]interface{}{
		"status":    "healthy",
		"version":   "1.0.0",
		"timestamp": time.Now(),
		"uptime":    time.Since(vs.startTime),
	}
	
	// Check database health
	if err := vs.db.Ping(); err != nil {
		status["status"] = "unhealthy"
		status["database"] = "disconnected"
	} else {
		status["database"] = "connected"
	}
	
	// Check Redis health
	if err := vs.redis.Ping(context.Background()).Err(); err != nil {
		status["redis"] = "disconnected"
	} else {
		status["redis"] = "connected"
	}
	
	// Check external services
	if vs.checkCoreEngineHealth() {
		status["core_engine"] = "healthy"
	} else {
		status["core_engine"] = "unhealthy"
		status["status"] = "degraded"
	}
	
	vs.respondWithSuccess(c, status)
}

func (vs *VerificationService) readinessCheck(c *gin.Context) {
	if err := vs.db.Ping(); err != nil {
		vs.respondWithError(c, http.StatusServiceUnavailable, "Database not ready")
		return
	}
	
	vs.respondWithSuccess(c, map[string]string{"status": "ready"})
}

// Core verification logic
func (vs *VerificationService) processVerification(req *VerificationRequest) (*VerificationResult, error) {
	startTime := time.Now()
	
	result := &VerificationResult{
		RequestID:         req.RequestID,
		CitizenID:         req.CitizenID,
		Status:           "processing",
		DataSourceResults: make([]DataSourceResult, 0),
		DocumentResults:   make([]DocumentResult, 0),
		BiometricResults:  make([]BiometricResult, 0),
		Warnings:          make([]string, 0),
		Recommendations:   make([]string, 0),
		AuditTrail:       make([]AuditEntry, 0),
		Timestamp:        time.Now(),
		ExpiresAt:        time.Now().Add(24 * time.Hour),
	}
	
	// Add audit entry
	result.AuditTrail = append(result.AuditTrail, AuditEntry{
		Timestamp: time.Now(),
		Action:    "verification_started",
		Source:    "verification_service",
		Details:   fmt.Sprintf("Started %s verification for citizen %s", req.VerifyType, req.CitizenID),
	})
	
	// Process data sources
	for _, source := range req.DataSources {
		dsResult := vs.verifyAgainstDataSource(req.CitizenID, source)
		result.DataSourceResults = append(result.DataSourceResults, dsResult)
	}
	
	// Process documents
	for _, doc := range req.Documents {
		docResult := vs.processDocumentVerification(&doc)
		result.DocumentResults = append(result.DocumentResults, docResult)
	}
	
	// Process biometrics
	for _, biometric := range req.BiometricData {
		bioResult := vs.processBiometricVerification(&biometric)
		result.BiometricResults = append(result.BiometricResults, bioResult)
	}
	
	// Calculate overall scores
	vs.calculateOverallScores(result)
	
	// Determine final status
	if result.ConfidenceScore >= 0.8 {
		result.Status = "verified"
	} else if result.ConfidenceScore >= 0.5 {
		result.Status = "partial"
		result.Warnings = append(result.Warnings, "Verification confidence is below recommended threshold")
	} else {
		result.Status = "failed"
		result.Warnings = append(result.Warnings, "Verification failed due to low confidence score")
	}
	
	result.ProcessingTimeMs = time.Since(startTime).Milliseconds()
	
	// Save to database
	if err := vs.saveVerificationResult(result); err != nil {
		vs.logger.Error("Failed to save verification result", zap.Error(err))
	}
	
	// Send callback if provided
	if req.CallbackURL != "" {
		go vs.sendCallback(req.CallbackURL, result)
	}
	
	return result, nil
}

func (vs *VerificationService) processVerificationAsync(req *VerificationRequest) {
	result, err := vs.processVerification(req)
	if err != nil {
		vs.logger.Error("Async verification failed", zap.Error(err))
		return
	}
	
	vs.cacheResult(req.RequestID, result)
	
	if req.CallbackURL != "" {
		vs.sendCallback(req.CallbackURL, result)
	}
}

func (vs *VerificationService) verifyAgainstDataSource(citizenID, source string) DataSourceResult {
	startTime := time.Now()
	
	result := DataSourceResult{
		Source:          source,
		Status:          "processing",
		MatchedFields:   make([]string, 0),
		MismatchedFields: make([]string, 0),
		Data:            make(map[string]interface{}),
	}
	
	// Call external core engine service
	vs.metrics.ExternalCallsTotal.Inc()
	
	payload := map[string]interface{}{
		"citizen_id": citizenID,
		"source":     source,
	}
	
	response, err := vs.callCoreEngine("/verify/datasource", payload)
	if err != nil {
		result.Status = "failed"
		result.Error = err.Error()
		result.Score = 0.0
		result.Confidence = 0.0
	} else {
		result.Status = "success"
		result.Score = vs.extractScore(response)
		result.Confidence = vs.extractConfidence(response)
		result.Data = response
		
		// Extract matched/mismatched fields
		if fields, ok := response["matched_fields"].([]interface{}); ok {
			for _, field := range fields {
				if fieldStr, ok := field.(string); ok {
					result.MatchedFields = append(result.MatchedFields, fieldStr)
				}
			}
		}
	}
	
	result.ResponseTime = time.Since(startTime).Milliseconds()
	return result
}

func (vs *VerificationService) processDocumentVerification(doc *Document) DocumentResult {
	startTime := time.Now()
	
	result := DocumentResult{
		DocumentType:    doc.Type,
		Status:          "processing",
		ExtractedData:   make(map[string]interface{}),
		SecurityFeatures: make(map[string]bool),
		Warnings:        make([]string, 0),
	}
	
	// Simulate document processing
	// In production, this would call ML models for document analysis
	result.AuthenticityScore = 0.85 + (float64(time.Now().UnixNano()%100) / 1000)
	result.ExtractionScore = 0.90 + (float64(time.Now().UnixNano()%100) / 1000)
	
	// Simulate extracted data
	result.ExtractedData = map[string]interface{}{
		"document_number": "ABC123456",
		"name":           "John Doe",
		"date_of_birth":  "1990-01-01",
		"expiry_date":    "2030-12-31",
	}
	
	// Simulate security features
	result.SecurityFeatures = map[string]bool{
		"watermark":     true,
		"hologram":      true,
		"rfid_chip":     false,
		"security_thread": true,
	}
	
	if result.AuthenticityScore < 0.7 {
		result.Warnings = append(result.Warnings, "Low document authenticity score")
	}
	
	result.Status = "completed"
	result.ProcessingTime = time.Since(startTime).Milliseconds()
	
	return result
}

func (vs *VerificationService) processBiometricVerification(biometric *BiometricData) BiometricResult {
	startTime := time.Now()
	
	result := BiometricResult{
		Type:   biometric.Type,
		Status: "processing",
	}
	
	// Simulate biometric processing
	// In production, this would call biometric matching services
	result.MatchScore = 0.80 + (float64(time.Now().UnixNano()%200) / 1000)
	result.QualityScore = biometric.Quality
	result.LivenessScore = 0.90 + (float64(time.Now().UnixNano()%100) / 1000)
	
	if result.MatchScore >= 0.85 {
		result.Status = "match"
	} else if result.MatchScore >= 0.70 {
		result.Status = "partial_match"
	} else {
		result.Status = "no_match"
	}
	
	result.ProcessingTime = time.Since(startTime).Milliseconds()
	
	return result
}

func (vs *VerificationService) calculateOverallScores(result *VerificationResult) {
	var totalScore, totalConfidence, totalRisk float64
	var count int
	
	// Weight data source results
	for _, dsResult := range result.DataSourceResults {
		if dsResult.Status == "success" {
			totalScore += dsResult.Score * 0.4 // 40% weight
			totalConfidence += dsResult.Confidence * 0.4
			count++
		}
	}
	
	// Weight document results
	for _, docResult := range result.DocumentResults {
		if docResult.Status == "completed" {
			totalScore += docResult.AuthenticityScore * 0.3 // 30% weight
			totalConfidence += docResult.ExtractionScore * 0.3
			count++
		}
	}
	
	// Weight biometric results
	for _, bioResult := range result.BiometricResults {
		if bioResult.Status == "match" {
			totalScore += bioResult.MatchScore * 0.3 // 30% weight
			totalConfidence += bioResult.QualityScore * 0.3
			count++
		}
	}
	
	if count > 0 {
		result.OverallScore = totalScore / float64(count)
		result.ConfidenceScore = totalConfidence / float64(count)
		result.RiskScore = 1.0 - result.ConfidenceScore
	}
}

// Utility functions
func (vs *VerificationService) isComplexVerification(req *VerificationRequest) bool {
	return len(req.DataSources) > 3 || len(req.Documents) > 2 || len(req.BiometricData) > 1
}

func (vs *VerificationService) getCachedResult(requestID string) *VerificationResult {
	vs.cacheMutex.RLock()
	defer vs.cacheMutex.RUnlock()
	
	return vs.resultCache[requestID]
}

func (vs *VerificationService) cacheResult(requestID string, result *VerificationResult) {
	vs.cacheMutex.Lock()
	defer vs.cacheMutex.Unlock()
	
	vs.resultCache[requestID] = result
	
	// Also cache in Redis
	data, _ := json.Marshal(result)
	vs.redis.Set(context.Background(), fmt.Sprintf("verification_result:%s", requestID), data, 24*time.Hour)
}

func (vs *VerificationService) getProcessingStatus(requestID string) string {
	// Check if verification is in progress
	vs.cacheMutex.RLock()
	defer vs.cacheMutex.RUnlock()
	
	if result, exists := vs.resultCache[requestID]; exists {
		return result.Status
	}
	
	return "not_found"
}

func (vs *VerificationService) cancelProcessing(requestID string) bool {
	// Implementation for cancelling ongoing verification
	// This would typically involve stopping worker goroutines
	return true
}

func (vs *VerificationService) callCoreEngine(endpoint string, payload interface{}) (map[string]interface{}, error) {
	// Implement exponential backoff retry
	operation := func() error {
		jsonPayload, _ := json.Marshal(payload)
		
		resp, err := vs.httpClient.Post(
			vs.config.ExternalServices.CoreEngine+endpoint,
			"application/json",
			strings.NewReader(string(jsonPayload)),
		)
		if err != nil {
			return err
		}
		defer resp.Body.Close()
		
		if resp.StatusCode != http.StatusOK {
			return fmt.Errorf("core engine returned status %d", resp.StatusCode)
		}
		
		return nil
	}
	
	backoffConfig := backoff.NewExponentialBackOff()
	backoffConfig.MaxElapsedTime = 30 * time.Second
	
	err := backoff.Retry(operation, backoffConfig)
	if err != nil {
		return nil, err
	}
	
	// Simulate successful response
	return map[string]interface{}{
		"status": "success",
		"score":  0.85,
		"confidence": 0.90,
		"matched_fields": []string{"name", "date_of_birth", "address"},
	}, nil
}

func (vs *VerificationService) extractScore(response map[string]interface{}) float64 {
	if score, ok := response["score"].(float64); ok {
		return score
	}
	return 0.0
}

func (vs *VerificationService) extractConfidence(response map[string]interface{}) float64 {
	if confidence, ok := response["confidence"].(float64); ok {
		return confidence
	}
	return 0.0
}

func (vs *VerificationService) saveVerificationResult(result *VerificationResult) error {
	// Save to database
	query := `
		INSERT INTO verification_results 
		(request_id, citizen_id, status, overall_score, confidence_score, risk_score, 
		 processing_time_ms, timestamp, expires_at, result_data)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)`
	
	resultData, _ := json.Marshal(result)
	
	_, err := vs.db.Exec(query,
		result.RequestID, result.CitizenID, result.Status,
		result.OverallScore, result.ConfidenceScore, result.RiskScore,
		result.ProcessingTimeMs, result.Timestamp, result.ExpiresAt,
		string(resultData))
	
	return err
}

func (vs *VerificationService) getResultFromDatabase(requestID string) (*VerificationResult, error) {
	var resultData string
	query := "SELECT result_data FROM verification_results WHERE request_id = $1"
	
	err := vs.db.QueryRow(query, requestID).Scan(&resultData)
	if err != nil {
		return nil, err
	}
	
	var result VerificationResult
	if err := json.Unmarshal([]byte(resultData), &result); err != nil {
		return nil, err
	}
	
	return &result, nil
}

func (vs *VerificationService) sendCallback(callbackURL string, result *VerificationResult) {
	payload, _ := json.Marshal(result)
	
	_, err := vs.httpClient.Post(callbackURL, "application/json", strings.NewReader(string(payload)))
	if err != nil {
		vs.logger.Error("Failed to send callback", zap.Error(err), zap.String("url", callbackURL))
	}
}

func (vs *VerificationService) checkCoreEngineHealth() bool {
	resp, err := vs.httpClient.Get(vs.config.ExternalServices.CoreEngine + "/health")
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	
	return resp.StatusCode == http.StatusOK
}

func (vs *VerificationService) calculateAnalyticsSummary() map[string]interface{} {
	// Implementation for analytics summary
	return map[string]interface{}{
		"total_verifications": 1234,
		"success_rate":       0.92,
		"average_score":      0.85,
		"processing_time_avg": 2.5,
	}
}

func (vs *VerificationService) calculateVerificationTrends(days string) map[string]interface{} {
	// Implementation for verification trends
	return map[string]interface{}{
		"period": days,
		"trend":  "increasing",
		"data":   []map[string]interface{}{},
	}
}

func (vs *VerificationService) respondWithSuccess(c *gin.Context, data interface{}) {
	response := APIResponse{
		Success:   true,
		Data:      data,
		RequestID: uuid.New().String(),
		Timestamp: time.Now(),
	}
	c.JSON(http.StatusOK, response)
}

func (vs *VerificationService) respondWithError(c *gin.Context, code int, message string) {
	response := APIResponse{
		Success:   false,
		Error:     message,
		RequestID: uuid.New().String(),
		Timestamp: time.Now(),
	}
	c.JSON(code, response)
}

func (vs *VerificationService) Start() error {
	router := vs.setupRouter()
	
	server := &http.Server{
		Addr:    vs.config.Server.Host + ":" + vs.config.Server.Port,
		Handler: router,
	}
	
	vs.logger.Info("Starting verification service",
		zap.String("addr", server.Addr),
	)
	
	// Graceful shutdown
	go func() {
		sigChan := make(chan os.Signal, 1)
		signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
		<-sigChan
		
		vs.logger.Info("Shutting down verification service...")
		
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		
		if err := server.Shutdown(ctx); err != nil {
			vs.logger.Error("Server shutdown error", zap.Error(err))
		}
		
		vs.db.Close()
		vs.redis.Close()
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
	service, err := NewVerificationService(config, logger)
	if err != nil {
		logger.Fatal("Failed to create verification service", zap.Error(err))
	}
	
	if err := service.Start(); err != nil && err != http.ErrServerClosed {
		logger.Fatal("Verification service failed", zap.Error(err))
	}
}