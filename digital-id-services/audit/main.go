package main

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strconv"
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
	
	Audit struct {
		RetentionDays   int  `mapstructure:"retention_days"`
		BatchSize       int  `mapstructure:"batch_size"`
		EnableGDPR      bool `mapstructure:"enable_gdpr"`
		EnableEncryption bool `mapstructure:"enable_encryption"`
	} `mapstructure:"audit"`
	
	RateLimit struct {
		Requests int           `mapstructure:"requests"`
		Window   time.Duration `mapstructure:"window"`
		Burst    int           `mapstructure:"burst"`
	} `mapstructure:"rate_limit"`
}

type AuditService struct {
	config         *Config
	logger         *zap.Logger
	db             *sql.DB
	redis          *redis.Client
	validator      *validator.Validate
	circuitBreaker *gobreaker.CircuitBreaker
	rateLimiter    *rate.Limiter
	metrics        *AuditMetrics
	startTime      time.Time
}

type AuditMetrics struct {
	EventsLogged     prometheus.Counter
	EventsQueried    prometheus.Counter
	ComplianceChecks prometheus.Counter
	RequestDuration  prometheus.Histogram
	ActiveSessions   prometheus.Gauge
	DataExports      prometheus.Counter
	GDPRRequests     prometheus.Counter
	SecurityAlerts   prometheus.Counter
}

type AuditEvent struct {
	ID            string                 `json:"id" db:"id"`
	EventType     string                 `json:"event_type" db:"event_type"`
	Category      string                 `json:"category" db:"category"`
	Severity      string                 `json:"severity" db:"severity"`
	Source        string                 `json:"source" db:"source"`
	ActorID       string                 `json:"actor_id" db:"actor_id"`
	ActorType     string                 `json:"actor_type" db:"actor_type"`
	SubjectID     string                 `json:"subject_id" db:"subject_id"`
	SubjectType   string                 `json:"subject_type" db:"subject_type"`
	Action        string                 `json:"action" db:"action"`
	Resource      string                 `json:"resource" db:"resource"`
	Outcome       string                 `json:"outcome" db:"outcome"`
	IPAddress     string                 `json:"ip_address" db:"ip_address"`
	UserAgent     string                 `json:"user_agent" db:"user_agent"`
	SessionID     string                 `json:"session_id" db:"session_id"`
	RequestID     string                 `json:"request_id" db:"request_id"`
	Details       map[string]interface{} `json:"details" db:"details"`
	Metadata      map[string]interface{} `json:"metadata" db:"metadata"`
	Timestamp     time.Time              `json:"timestamp" db:"timestamp"`
	ProcessedAt   time.Time              `json:"processed_at" db:"processed_at"`
	
	// GDPR and compliance fields
	DataCategory     string `json:"data_category,omitempty" db:"data_category"`
	LegalBasis       string `json:"legal_basis,omitempty" db:"legal_basis"`
	ConsentID        string `json:"consent_id,omitempty" db:"consent_id"`
	RetentionPeriod  int    `json:"retention_period,omitempty" db:"retention_period"`
	EncryptionStatus string `json:"encryption_status,omitempty" db:"encryption_status"`
	
	// Integrity fields
	Hash      string `json:"hash" db:"hash"`
	PrevHash  string `json:"prev_hash" db:"prev_hash"`
	ChainID   string `json:"chain_id" db:"chain_id"`
}

type AuditQuery struct {
	EventTypes   []string  `json:"event_types,omitempty"`
	Categories   []string  `json:"categories,omitempty"`
	Severities   []string  `json:"severities,omitempty"`
	Sources      []string  `json:"sources,omitempty"`
	ActorIDs     []string  `json:"actor_ids,omitempty"`
	SubjectIDs   []string  `json:"subject_ids,omitempty"`
	Actions      []string  `json:"actions,omitempty"`
	Resources    []string  `json:"resources,omitempty"`
	Outcomes     []string  `json:"outcomes,omitempty"`
	StartTime    time.Time `json:"start_time,omitempty"`
	EndTime      time.Time `json:"end_time,omitempty"`
	IPAddress    string    `json:"ip_address,omitempty"`
	SessionID    string    `json:"session_id,omitempty"`
	RequestID    string    `json:"request_id,omitempty"`
	Limit        int       `json:"limit,omitempty"`
	Offset       int       `json:"offset,omitempty"`
	OrderBy      string    `json:"order_by,omitempty"`
	OrderDir     string    `json:"order_dir,omitempty"`
}

type ComplianceReport struct {
	ReportID      string                 `json:"report_id"`
	ReportType    string                 `json:"report_type"`
	Period        string                 `json:"period"`
	StartDate     time.Time              `json:"start_date"`
	EndDate       time.Time              `json:"end_date"`
	TotalEvents   int                    `json:"total_events"`
	EventsByType  map[string]int         `json:"events_by_type"`
	Violations    []ComplianceViolation  `json:"violations"`
	Recommendations []string            `json:"recommendations"`
	GeneratedAt   time.Time              `json:"generated_at"`
	GeneratedBy   string                 `json:"generated_by"`
	Summary       map[string]interface{} `json:"summary"`
}

type ComplianceViolation struct {
	ID          string                 `json:"id"`
	Type        string                 `json:"type"`
	Severity    string                 `json:"severity"`
	Description string                 `json:"description"`
	EventID     string                 `json:"event_id"`
	Details     map[string]interface{} `json:"details"`
	DetectedAt  time.Time              `json:"detected_at"`
	Status      string                 `json:"status"`
}

type GDPRRequest struct {
	RequestID     string    `json:"request_id"`
	RequestType   string    `json:"request_type" validate:"required,oneof=access rectification erasure portability restriction objection"`
	SubjectID     string    `json:"subject_id" validate:"required"`
	RequesterID   string    `json:"requester_id" validate:"required"`
	Reason        string    `json:"reason,omitempty"`
	Scope         []string  `json:"scope,omitempty"`
	Status        string    `json:"status"`
	RequestedAt   time.Time `json:"requested_at"`
	ProcessedAt   *time.Time `json:"processed_at,omitempty"`
	CompletedAt   *time.Time `json:"completed_at,omitempty"`
	ExpiresAt     time.Time `json:"expires_at"`
}

type SecurityAlert struct {
	ID          string                 `json:"id"`
	AlertType   string                 `json:"alert_type"`
	Severity    string                 `json:"severity"`
	Title       string                 `json:"title"`
	Description string                 `json:"description"`
	Source      string                 `json:"source"`
	EventIDs    []string               `json:"event_ids"`
	Indicators  map[string]interface{} `json:"indicators"`
	Response    map[string]interface{} `json:"response"`
	DetectedAt  time.Time              `json:"detected_at"`
	Status      string                 `json:"status"`
	AssignedTo  string                 `json:"assigned_to,omitempty"`
	ResolvedAt  *time.Time             `json:"resolved_at,omitempty"`
}

type APIResponse struct {
	Success   bool        `json:"success"`
	Data      interface{} `json:"data,omitempty"`
	Error     string      `json:"error,omitempty"`
	RequestID string      `json:"request_id"`
	Timestamp time.Time   `json:"timestamp"`
}

func NewAuditMetrics() *AuditMetrics {
	return &AuditMetrics{
		EventsLogged: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "audit_events_logged_total",
			Help: "Total number of audit events logged",
		}),
		EventsQueried: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "audit_events_queried_total",
			Help: "Total number of audit events queried",
		}),
		ComplianceChecks: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "compliance_checks_total",
			Help: "Total number of compliance checks performed",
		}),
		RequestDuration: prometheus.NewHistogram(prometheus.HistogramOpts{
			Name:    "audit_request_duration_seconds",
			Help:    "Audit request duration in seconds",
			Buckets: prometheus.DefBuckets,
		}),
		ActiveSessions: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "audit_active_sessions",
			Help: "Number of active audit sessions",
		}),
		DataExports: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "audit_data_exports_total",
			Help: "Total number of audit data exports",
		}),
		GDPRRequests: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "gdpr_requests_total",
			Help: "Total number of GDPR requests processed",
		}),
		SecurityAlerts: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "security_alerts_total",
			Help: "Total number of security alerts generated",
		}),
	}
}

func (m *AuditMetrics) Register() {
	prometheus.MustRegister(
		m.EventsLogged,
		m.EventsQueried,
		m.ComplianceChecks,
		m.RequestDuration,
		m.ActiveSessions,
		m.DataExports,
		m.GDPRRequests,
		m.SecurityAlerts,
	)
}

func loadConfig() (*Config, error) {
	viper.SetConfigName("config")
	viper.SetConfigType("yaml")
	viper.AddConfigPath(".")
	viper.AddConfigPath("./config")
	
	// Set defaults
	viper.SetDefault("server.port", "8084")
	viper.SetDefault("server.host", "0.0.0.0")
	viper.SetDefault("database.max_connections", 25)
	viper.SetDefault("database.max_idle_time", "15m")
	viper.SetDefault("database.max_lifetime", "1h")
	viper.SetDefault("database.connect_timeout", "10s")
	viper.SetDefault("redis.addr", "localhost:6379")
	viper.SetDefault("redis.db", 4)
	viper.SetDefault("audit.retention_days", 2555) // 7 years
	viper.SetDefault("audit.batch_size", 1000)
	viper.SetDefault("audit.enable_gdpr", true)
	viper.SetDefault("audit.enable_encryption", true)
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

func NewAuditService(config *Config, logger *zap.Logger) (*AuditService, error) {
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
		Name:        "audit-circuit-breaker",
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
	metrics := NewAuditMetrics()
	metrics.Register()
	
	return &AuditService{
		config:         config,
		logger:         logger,
		db:             db,
		redis:          rdb,
		validator:      validator.New(),
		circuitBreaker: cb,
		rateLimiter:    rateLimiter,
		metrics:        metrics,
		startTime:      time.Now(),
	}, nil
}

func (as *AuditService) setupRouter() *gin.Engine {
	gin.SetMode(gin.ReleaseMode)
	r := gin.New()
	
	// Middleware
	r.Use(as.loggingMiddleware())
	r.Use(as.metricsMiddleware())
	r.Use(as.rateLimitMiddleware())
	r.Use(gin.Recovery())
	
	// Health endpoints
	r.GET("/health", as.healthCheck)
	r.GET("/ready", as.readinessCheck)
	r.GET("/metrics", gin.WrapH(promhttp.Handler()))
	
	// Audit event endpoints
	r.POST("/events", as.logEvent)
	r.POST("/events/batch", as.logBatchEvents)
	r.GET("/events", as.queryEvents)
	r.GET("/events/:id", as.getEvent)
	
	// Search and analytics endpoints
	r.POST("/search", as.searchEvents)
	r.GET("/analytics/summary", as.getAnalyticsSummary)
	r.GET("/analytics/timeline", as.getEventTimeline)
	r.GET("/analytics/patterns", as.detectPatterns)
	
	// Compliance endpoints
	r.POST("/compliance/report", as.generateComplianceReport)
	r.GET("/compliance/reports", as.getComplianceReports)
	r.GET("/compliance/violations", as.getComplianceViolations)
	r.POST("/compliance/check", as.performComplianceCheck)
	
	// GDPR endpoints
	r.POST("/gdpr/request", as.createGDPRRequest)
	r.GET("/gdpr/requests", as.getGDPRRequests)
	r.POST("/gdpr/requests/:id/process", as.processGDPRRequest)
	r.GET("/gdpr/export/:subject_id", as.exportPersonalData)
	
	// Security endpoints
	r.GET("/security/alerts", as.getSecurityAlerts)
	r.POST("/security/alerts", as.createSecurityAlert)
	r.POST("/security/alerts/:id/resolve", as.resolveSecurityAlert)
	
	// Data management endpoints
	r.POST("/data/archive", as.archiveOldData)
	r.POST("/data/purge", as.purgeExpiredData)
	r.GET("/data/integrity", as.checkDataIntegrity)
	
	return r
}

func (as *AuditService) loggingMiddleware() gin.HandlerFunc {
	return gin.LoggerWithWriter(gin.DefaultWriter, "/health", "/ready", "/metrics")
}

func (as *AuditService) metricsMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		start := time.Now()
		
		defer func() {
			duration := time.Since(start)
			as.metrics.RequestDuration.Observe(duration.Seconds())
		}()
		
		c.Next()
	}
}

func (as *AuditService) rateLimitMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		if !as.rateLimiter.Allow() {
			as.respondWithError(c, http.StatusTooManyRequests, "Rate limit exceeded")
			c.Abort()
			return
		}
		c.Next()
	}
}

func (as *AuditService) logEvent(c *gin.Context) {
	var event AuditEvent
	if err := c.ShouldBindJSON(&event); err != nil {
		as.respondWithError(c, http.StatusBadRequest, err.Error())
		return
	}
	
	// Set defaults and generate IDs
	event.ID = uuid.New().String()
	event.Timestamp = time.Now()
	event.ProcessedAt = time.Now()
	
	// Calculate hash for integrity
	event.Hash = as.calculateEventHash(&event)
	
	// Get previous hash for chain
	prevHash, err := as.getLastEventHash()
	if err == nil {
		event.PrevHash = prevHash
	}
	
	// Save event
	if err := as.saveAuditEvent(&event); err != nil {
		as.logger.Error("Failed to save audit event", zap.Error(err))
		as.respondWithError(c, http.StatusInternalServerError, "Failed to save audit event")
		return
	}
	
	as.metrics.EventsLogged.Inc()
	
	// Check for security patterns
	go as.checkSecurityPatterns(&event)
	
	as.respondWithSuccess(c, map[string]interface{}{
		"event_id": event.ID,
		"hash":     event.Hash,
		"logged_at": event.ProcessedAt,
	})
}

func (as *AuditService) logBatchEvents(c *gin.Context) {
	var events []AuditEvent
	if err := c.ShouldBindJSON(&events); err != nil {
		as.respondWithError(c, http.StatusBadRequest, err.Error())
		return
	}
	
	if len(events) == 0 || len(events) > as.config.Audit.BatchSize {
		as.respondWithError(c, http.StatusBadRequest, fmt.Sprintf("Batch size must be between 1 and %d", as.config.Audit.BatchSize))
		return
	}
	
	var savedEvents []string
	
	// Process each event in batch
	for i := range events {
		events[i].ID = uuid.New().String()
		events[i].Timestamp = time.Now()
		events[i].ProcessedAt = time.Now()
		events[i].Hash = as.calculateEventHash(&events[i])
		
		if i > 0 {
			events[i].PrevHash = events[i-1].Hash
		} else {
			prevHash, _ := as.getLastEventHash()
			events[i].PrevHash = prevHash
		}
		
		if err := as.saveAuditEvent(&events[i]); err != nil {
			as.logger.Error("Failed to save batch event", zap.Error(err), zap.String("event_id", events[i].ID))
			continue
		}
		
		savedEvents = append(savedEvents, events[i].ID)
		as.metrics.EventsLogged.Inc()
	}
	
	response := map[string]interface{}{
		"total_events":   len(events),
		"saved_events":   len(savedEvents),
		"failed_events":  len(events) - len(savedEvents),
		"event_ids":      savedEvents,
		"processed_at":   time.Now(),
	}
	
	as.respondWithSuccess(c, response)
}

func (as *AuditService) queryEvents(c *gin.Context) {
	// Parse query parameters
	query := AuditQuery{
		Limit:    100, // Default limit
		Offset:   0,
		OrderBy:  "timestamp",
		OrderDir: "DESC",
	}
	
	if limit := c.Query("limit"); limit != "" {
		if l, err := strconv.Atoi(limit); err == nil && l > 0 && l <= 1000 {
			query.Limit = l
		}
	}
	
	if offset := c.Query("offset"); offset != "" {
		if o, err := strconv.Atoi(offset); err == nil && o >= 0 {
			query.Offset = o
		}
	}
	
	if eventType := c.Query("event_type"); eventType != "" {
		query.EventTypes = strings.Split(eventType, ",")
	}
	
	if category := c.Query("category"); category != "" {
		query.Categories = strings.Split(category, ",")
	}
	
	if actorID := c.Query("actor_id"); actorID != "" {
		query.ActorIDs = []string{actorID}
	}
	
	if subjectID := c.Query("subject_id"); subjectID != "" {
		query.SubjectIDs = []string{subjectID}
	}
	
	if startTime := c.Query("start_time"); startTime != "" {
		if t, err := time.Parse(time.RFC3339, startTime); err == nil {
			query.StartTime = t
		}
	}
	
	if endTime := c.Query("end_time"); endTime != "" {
		if t, err := time.Parse(time.RFC3339, endTime); err == nil {
			query.EndTime = t
		}
	}
	
	// Execute query
	events, total, err := as.executeEventQuery(&query)
	if err != nil {
		as.logger.Error("Failed to query events", zap.Error(err))
		as.respondWithError(c, http.StatusInternalServerError, "Failed to query events")
		return
	}
	
	as.metrics.EventsQueried.Inc()
	
	response := map[string]interface{}{
		"events":      events,
		"total":       total,
		"limit":       query.Limit,
		"offset":      query.Offset,
		"returned":    len(events),
		"queried_at":  time.Now(),
	}
	
	as.respondWithSuccess(c, response)
}

func (as *AuditService) searchEvents(c *gin.Context) {
	var query AuditQuery
	if err := c.ShouldBindJSON(&query); err != nil {
		as.respondWithError(c, http.StatusBadRequest, err.Error())
		return
	}
	
	// Set defaults
	if query.Limit == 0 {
		query.Limit = 100
	}
	if query.OrderBy == "" {
		query.OrderBy = "timestamp"
	}
	if query.OrderDir == "" {
		query.OrderDir = "DESC"
	}
	
	events, total, err := as.executeEventQuery(&query)
	if err != nil {
		as.logger.Error("Failed to search events", zap.Error(err))
		as.respondWithError(c, http.StatusInternalServerError, "Failed to search events")
		return
	}
	
	as.metrics.EventsQueried.Inc()
	
	response := map[string]interface{}{
		"events":     events,
		"total":      total,
		"query":      query,
		"searched_at": time.Now(),
	}
	
	as.respondWithSuccess(c, response)
}

func (as *AuditService) getEvent(c *gin.Context) {
	eventID := c.Param("id")
	
	event, err := as.getAuditEventByID(eventID)
	if err != nil {
		as.respondWithError(c, http.StatusNotFound, "Event not found")
		return
	}
	
	as.respondWithSuccess(c, event)
}

func (as *AuditService) generateComplianceReport(c *gin.Context) {
	type reportRequest struct {
		ReportType string    `json:"report_type" validate:"required,oneof=gdpr sox pci hipaa iso27001 custom"`
		StartDate  time.Time `json:"start_date" validate:"required"`
		EndDate    time.Time `json:"end_date" validate:"required"`
		Scope      []string  `json:"scope,omitempty"`
	}
	
	var req reportRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		as.respondWithError(c, http.StatusBadRequest, err.Error())
		return
	}
	
	if err := as.validator.Struct(&req); err != nil {
		as.respondWithError(c, http.StatusBadRequest, fmt.Sprintf("Validation error: %v", err))
		return
	}
	
	report, err := as.createComplianceReport(req.ReportType, req.StartDate, req.EndDate, req.Scope)
	if err != nil {
		as.logger.Error("Failed to generate compliance report", zap.Error(err))
		as.respondWithError(c, http.StatusInternalServerError, "Failed to generate compliance report")
		return
	}
	
	as.metrics.ComplianceChecks.Inc()
	
	as.respondWithSuccess(c, report)
}

func (as *AuditService) createGDPRRequest(c *gin.Context) {
	var req GDPRRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		as.respondWithError(c, http.StatusBadRequest, err.Error())
		return
	}
	
	if err := as.validator.Struct(&req); err != nil {
		as.respondWithError(c, http.StatusBadRequest, fmt.Sprintf("Validation error: %v", err))
		return
	}
	
	// Set defaults
	req.RequestID = uuid.New().String()
	req.Status = "pending"
	req.RequestedAt = time.Now()
	req.ExpiresAt = time.Now().AddDate(0, 1, 0) // 30 days
	
	if err := as.saveGDPRRequest(&req); err != nil {
		as.logger.Error("Failed to save GDPR request", zap.Error(err))
		as.respondWithError(c, http.StatusInternalServerError, "Failed to save GDPR request")
		return
	}
	
	as.metrics.GDPRRequests.Inc()
	
	// Log the GDPR request as an audit event
	go as.logGDPRRequestEvent(&req)
	
	as.respondWithSuccess(c, req)
}

func (as *AuditService) getAnalyticsSummary(c *gin.Context) {
	startTime := c.Query("start_time")
	endTime := c.Query("end_time")
	
	var start, end time.Time
	var err error
	
	if startTime != "" {
		start, err = time.Parse(time.RFC3339, startTime)
		if err != nil {
			as.respondWithError(c, http.StatusBadRequest, "Invalid start_time format")
			return
		}
	} else {
		start = time.Now().AddDate(0, 0, -30) // Default: last 30 days
	}
	
	if endTime != "" {
		end, err = time.Parse(time.RFC3339, endTime)
		if err != nil {
			as.respondWithError(c, http.StatusBadRequest, "Invalid end_time format")
			return
		}
	} else {
		end = time.Now()
	}
	
	summary := as.calculateAnalyticsSummary(start, end)
	as.respondWithSuccess(c, summary)
}

func (as *AuditService) createSecurityAlert(c *gin.Context) {
	var alert SecurityAlert
	if err := c.ShouldBindJSON(&alert); err != nil {
		as.respondWithError(c, http.StatusBadRequest, err.Error())
		return
	}
	
	alert.ID = uuid.New().String()
	alert.DetectedAt = time.Now()
	alert.Status = "open"
	
	if err := as.saveSecurityAlert(&alert); err != nil {
		as.logger.Error("Failed to save security alert", zap.Error(err))
		as.respondWithError(c, http.StatusInternalServerError, "Failed to save security alert")
		return
	}
	
	as.metrics.SecurityAlerts.Inc()
	
	as.respondWithSuccess(c, alert)
}

func (as *AuditService) healthCheck(c *gin.Context) {
	status := map[string]interface{}{
		"status":    "healthy",
		"version":   "1.0.0",
		"timestamp": time.Now(),
		"uptime":    time.Since(as.startTime),
	}
	
	// Check database health
	if err := as.db.Ping(); err != nil {
		status["status"] = "unhealthy"
		status["database"] = "disconnected"
	} else {
		status["database"] = "connected"
	}
	
	// Check Redis health
	if err := as.redis.Ping(context.Background()).Err(); err != nil {
		status["redis"] = "disconnected"
	} else {
		status["redis"] = "connected"
	}
	
	as.respondWithSuccess(c, status)
}

func (as *AuditService) readinessCheck(c *gin.Context) {
	if err := as.db.Ping(); err != nil {
		as.respondWithError(c, http.StatusServiceUnavailable, "Database not ready")
		return
	}
	
	as.respondWithSuccess(c, map[string]string{"status": "ready"})
}

// Core audit operations
func (as *AuditService) calculateEventHash(event *AuditEvent) string {
	data := fmt.Sprintf("%s:%s:%s:%s:%s:%s:%d",
		event.EventType, event.ActorID, event.SubjectID, event.Action,
		event.Resource, event.Outcome, event.Timestamp.Unix())
	
	hash := sha256.Sum256([]byte(data))
	return hex.EncodeToString(hash[:])
}

func (as *AuditService) getLastEventHash() (string, error) {
	var hash string
	err := as.db.QueryRow("SELECT hash FROM audit_events ORDER BY timestamp DESC LIMIT 1").Scan(&hash)
	return hash, err
}

func (as *AuditService) saveAuditEvent(event *AuditEvent) error {
	query := `
		INSERT INTO audit_events 
		(id, event_type, category, severity, source, actor_id, actor_type, subject_id, 
		 subject_type, action, resource, outcome, ip_address, user_agent, session_id, 
		 request_id, details, metadata, timestamp, processed_at, data_category, 
		 legal_basis, consent_id, retention_period, encryption_status, hash, prev_hash, chain_id)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20, $21, $22, $23, $24, $25, $26, $27, $28)`
	
	detailsJSON, _ := json.Marshal(event.Details)
	metadataJSON, _ := json.Marshal(event.Metadata)
	
	_, err := as.db.Exec(query,
		event.ID, event.EventType, event.Category, event.Severity, event.Source,
		event.ActorID, event.ActorType, event.SubjectID, event.SubjectType,
		event.Action, event.Resource, event.Outcome, event.IPAddress, event.UserAgent,
		event.SessionID, event.RequestID, string(detailsJSON), string(metadataJSON),
		event.Timestamp, event.ProcessedAt, event.DataCategory, event.LegalBasis,
		event.ConsentID, event.RetentionPeriod, event.EncryptionStatus,
		event.Hash, event.PrevHash, event.ChainID)
	
	return err
}

func (as *AuditService) getAuditEventByID(eventID string) (*AuditEvent, error) {
	event := &AuditEvent{}
	
	query := `
		SELECT id, event_type, category, severity, source, actor_id, actor_type, 
		       subject_id, subject_type, action, resource, outcome, ip_address, 
		       user_agent, session_id, request_id, details, metadata, timestamp, 
		       processed_at, data_category, legal_basis, consent_id, retention_period, 
		       encryption_status, hash, prev_hash, chain_id
		FROM audit_events WHERE id = $1`
	
	var detailsJSON, metadataJSON string
	
	err := as.db.QueryRow(query, eventID).Scan(
		&event.ID, &event.EventType, &event.Category, &event.Severity, &event.Source,
		&event.ActorID, &event.ActorType, &event.SubjectID, &event.SubjectType,
		&event.Action, &event.Resource, &event.Outcome, &event.IPAddress, &event.UserAgent,
		&event.SessionID, &event.RequestID, &detailsJSON, &metadataJSON,
		&event.Timestamp, &event.ProcessedAt, &event.DataCategory, &event.LegalBasis,
		&event.ConsentID, &event.RetentionPeriod, &event.EncryptionStatus,
		&event.Hash, &event.PrevHash, &event.ChainID)
	
	if err != nil {
		return nil, err
	}
	
	json.Unmarshal([]byte(detailsJSON), &event.Details)
	json.Unmarshal([]byte(metadataJSON), &event.Metadata)
	
	return event, nil
}

func (as *AuditService) executeEventQuery(query *AuditQuery) ([]AuditEvent, int, error) {
	// Build SQL query
	sqlQuery := "SELECT COUNT(*) FROM audit_events WHERE 1=1"
	args := make([]interface{}, 0)
	argCount := 0
	
	// Add where clauses
	if len(query.EventTypes) > 0 {
		argCount++
		sqlQuery += fmt.Sprintf(" AND event_type = ANY($%d)", argCount)
		args = append(args, pq.Array(query.EventTypes))
	}
	
	if len(query.Categories) > 0 {
		argCount++
		sqlQuery += fmt.Sprintf(" AND category = ANY($%d)", argCount)
		args = append(args, pq.Array(query.Categories))
	}
	
	if len(query.ActorIDs) > 0 {
		argCount++
		sqlQuery += fmt.Sprintf(" AND actor_id = ANY($%d)", argCount)
		args = append(args, pq.Array(query.ActorIDs))
	}
	
	if !query.StartTime.IsZero() {
		argCount++
		sqlQuery += fmt.Sprintf(" AND timestamp >= $%d", argCount)
		args = append(args, query.StartTime)
	}
	
	if !query.EndTime.IsZero() {
		argCount++
		sqlQuery += fmt.Sprintf(" AND timestamp <= $%d", argCount)
		args = append(args, query.EndTime)
	}
	
	// Get total count
	var total int
	err := as.db.QueryRow(sqlQuery, args...).Scan(&total)
	if err != nil {
		return nil, 0, err
	}
	
	// Build main query
	mainQuery := strings.Replace(sqlQuery, "SELECT COUNT(*)", 
		`SELECT id, event_type, category, severity, source, actor_id, actor_type, 
		        subject_id, subject_type, action, resource, outcome, ip_address, 
		        user_agent, session_id, request_id, details, metadata, timestamp, 
		        processed_at, data_category, legal_basis, consent_id, retention_period, 
		        encryption_status, hash, prev_hash, chain_id`, 1)
	
	mainQuery += fmt.Sprintf(" ORDER BY %s %s LIMIT $%d OFFSET $%d", 
		query.OrderBy, query.OrderDir, argCount+1, argCount+2)
	args = append(args, query.Limit, query.Offset)
	
	// Execute main query
	rows, err := as.db.Query(mainQuery, args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	
	var events []AuditEvent
	
	for rows.Next() {
		event := AuditEvent{}
		var detailsJSON, metadataJSON string
		
		err := rows.Scan(
			&event.ID, &event.EventType, &event.Category, &event.Severity, &event.Source,
			&event.ActorID, &event.ActorType, &event.SubjectID, &event.SubjectType,
			&event.Action, &event.Resource, &event.Outcome, &event.IPAddress, &event.UserAgent,
			&event.SessionID, &event.RequestID, &detailsJSON, &metadataJSON,
			&event.Timestamp, &event.ProcessedAt, &event.DataCategory, &event.LegalBasis,
			&event.ConsentID, &event.RetentionPeriod, &event.EncryptionStatus,
			&event.Hash, &event.PrevHash, &event.ChainID)
		
		if err != nil {
			continue
		}
		
		json.Unmarshal([]byte(detailsJSON), &event.Details)
		json.Unmarshal([]byte(metadataJSON), &event.Metadata)
		
		events = append(events, event)
	}
	
	return events, total, nil
}

func (as *AuditService) createComplianceReport(reportType string, startDate, endDate time.Time, scope []string) (*ComplianceReport, error) {
	report := &ComplianceReport{
		ReportID:    uuid.New().String(),
		ReportType:  reportType,
		Period:      fmt.Sprintf("%s to %s", startDate.Format("2006-01-02"), endDate.Format("2006-01-02")),
		StartDate:   startDate,
		EndDate:     endDate,
		GeneratedAt: time.Now(),
		GeneratedBy: "audit-service",
		Summary:     make(map[string]interface{}),
	}
	
	// Get event statistics
	var totalEvents int
	as.db.QueryRow("SELECT COUNT(*) FROM audit_events WHERE timestamp BETWEEN $1 AND $2", 
		startDate, endDate).Scan(&totalEvents)
	
	report.TotalEvents = totalEvents
	
	// Get events by type
	report.EventsByType = make(map[string]int)
	rows, err := as.db.Query(`
		SELECT event_type, COUNT(*) 
		FROM audit_events 
		WHERE timestamp BETWEEN $1 AND $2 
		GROUP BY event_type`, startDate, endDate)
	
	if err == nil {
		defer rows.Close()
		for rows.Next() {
			var eventType string
			var count int
			if rows.Scan(&eventType, &count) == nil {
				report.EventsByType[eventType] = count
			}
		}
	}
	
	// Check for compliance violations based on report type
	report.Violations = as.detectComplianceViolations(reportType, startDate, endDate)
	
	// Generate recommendations
	report.Recommendations = as.generateComplianceRecommendations(report)
	
	return report, nil
}

func (as *AuditService) detectComplianceViolations(reportType string, startDate, endDate time.Time) []ComplianceViolation {
	violations := make([]ComplianceViolation, 0)
	
	switch reportType {
	case "gdpr":
		// Check for GDPR violations
		violations = append(violations, as.checkGDPRViolations(startDate, endDate)...)
	case "sox":
		// Check for SOX violations
		violations = append(violations, as.checkSOXViolations(startDate, endDate)...)
	case "pci":
		// Check for PCI violations
		violations = append(violations, as.checkPCIViolations(startDate, endDate)...)
	}
	
	return violations
}

func (as *AuditService) checkGDPRViolations(startDate, endDate time.Time) []ComplianceViolation {
	violations := make([]ComplianceViolation, 0)
	
	// Check for data access without consent
	rows, err := as.db.Query(`
		SELECT id, details FROM audit_events 
		WHERE timestamp BETWEEN $1 AND $2 
		AND action = 'data_access' 
		AND (consent_id IS NULL OR consent_id = '')`, 
		startDate, endDate)
	
	if err == nil {
		defer rows.Close()
		for rows.Next() {
			var eventID, detailsJSON string
			if rows.Scan(&eventID, &detailsJSON) == nil {
				violation := ComplianceViolation{
					ID:          uuid.New().String(),
					Type:        "gdpr_consent_missing",
					Severity:    "high",
					Description: "Data access without valid consent",
					EventID:     eventID,
					DetectedAt:  time.Now(),
					Status:      "open",
				}
				violations = append(violations, violation)
			}
		}
	}
	
	return violations
}

func (as *AuditService) checkSOXViolations(startDate, endDate time.Time) []ComplianceViolation {
	// Implementation for SOX compliance checks
	return make([]ComplianceViolation, 0)
}

func (as *AuditService) checkPCIViolations(startDate, endDate time.Time) []ComplianceViolation {
	// Implementation for PCI compliance checks
	return make([]ComplianceViolation, 0)
}

func (as *AuditService) generateComplianceRecommendations(report *ComplianceReport) []string {
	recommendations := make([]string, 0)
	
	if len(report.Violations) > 0 {
		recommendations = append(recommendations, "Address identified compliance violations immediately")
	}
	
	if report.TotalEvents < 100 {
		recommendations = append(recommendations, "Consider increasing audit event coverage")
	}
	
	recommendations = append(recommendations, "Regularly review and update audit policies")
	recommendations = append(recommendations, "Implement automated compliance monitoring")
	
	return recommendations
}

func (as *AuditService) saveGDPRRequest(req *GDPRRequest) error {
	query := `
		INSERT INTO gdpr_requests 
		(request_id, request_type, subject_id, requester_id, reason, scope, status, 
		 requested_at, expires_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`
	
	scopeJSON, _ := json.Marshal(req.Scope)
	
	_, err := as.db.Exec(query, req.RequestID, req.RequestType, req.SubjectID,
		req.RequesterID, req.Reason, string(scopeJSON), req.Status,
		req.RequestedAt, req.ExpiresAt)
	
	return err
}

func (as *AuditService) logGDPRRequestEvent(req *GDPRRequest) {
	event := &AuditEvent{
		ID:           uuid.New().String(),
		EventType:    "gdpr_request",
		Category:     "compliance",
		Severity:     "medium",
		Source:       "audit-service",
		ActorID:      req.RequesterID,
		ActorType:    "user",
		SubjectID:    req.SubjectID,
		SubjectType:  "data_subject",
		Action:       "gdpr_request_created",
		Resource:     "personal_data",
		Outcome:      "success",
		Details: map[string]interface{}{
			"request_id":   req.RequestID,
			"request_type": req.RequestType,
			"reason":       req.Reason,
		},
		Timestamp:    time.Now(),
		ProcessedAt:  time.Now(),
		DataCategory: "personal_data",
		LegalBasis:   "gdpr_article_15",
	}
	
	event.Hash = as.calculateEventHash(event)
	as.saveAuditEvent(event)
}

func (as *AuditService) saveSecurityAlert(alert *SecurityAlert) error {
	query := `
		INSERT INTO security_alerts 
		(id, alert_type, severity, title, description, source, event_ids, 
		 indicators, response, detected_at, status, assigned_to)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)`
	
	eventIDsJSON, _ := json.Marshal(alert.EventIDs)
	indicatorsJSON, _ := json.Marshal(alert.Indicators)
	responseJSON, _ := json.Marshal(alert.Response)
	
	_, err := as.db.Exec(query, alert.ID, alert.AlertType, alert.Severity,
		alert.Title, alert.Description, alert.Source, string(eventIDsJSON),
		string(indicatorsJSON), string(responseJSON), alert.DetectedAt,
		alert.Status, alert.AssignedTo)
	
	return err
}

func (as *AuditService) checkSecurityPatterns(event *AuditEvent) {
	// Check for suspicious patterns
	if event.Outcome == "failure" && event.Action == "authentication" {
		// Check for multiple failed logins
		var failedAttempts int
		as.db.QueryRow(`
			SELECT COUNT(*) FROM audit_events 
			WHERE actor_id = $1 AND action = 'authentication' AND outcome = 'failure' 
			AND timestamp > NOW() - INTERVAL '15 minutes'`, event.ActorID).Scan(&failedAttempts)
		
		if failedAttempts >= 5 {
			alert := &SecurityAlert{
				ID:          uuid.New().String(),
				AlertType:   "brute_force",
				Severity:    "high",
				Title:       "Multiple Failed Authentication Attempts",
				Description: fmt.Sprintf("User %s has %d failed login attempts in 15 minutes", event.ActorID, failedAttempts),
				Source:      "audit-service",
				EventIDs:    []string{event.ID},
				Indicators: map[string]interface{}{
					"failed_attempts": failedAttempts,
					"time_window":     "15_minutes",
					"actor_id":        event.ActorID,
				},
				DetectedAt: time.Now(),
				Status:     "open",
			}
			as.saveSecurityAlert(alert)
		}
	}
}

func (as *AuditService) calculateAnalyticsSummary(startTime, endTime time.Time) map[string]interface{} {
	summary := make(map[string]interface{})
	
	// Total events
	var totalEvents int
	as.db.QueryRow("SELECT COUNT(*) FROM audit_events WHERE timestamp BETWEEN $1 AND $2", 
		startTime, endTime).Scan(&totalEvents)
	summary["total_events"] = totalEvents
	
	// Events by category
	categoryMap := make(map[string]int)
	rows, err := as.db.Query(`
		SELECT category, COUNT(*) FROM audit_events 
		WHERE timestamp BETWEEN $1 AND $2 
		GROUP BY category`, startTime, endTime)
	
	if err == nil {
		defer rows.Close()
		for rows.Next() {
			var category string
			var count int
			if rows.Scan(&category, &count) == nil {
				categoryMap[category] = count
			}
		}
	}
	summary["events_by_category"] = categoryMap
	
	// Events by severity
	severityMap := make(map[string]int)
	rows2, err := as.db.Query(`
		SELECT severity, COUNT(*) FROM audit_events 
		WHERE timestamp BETWEEN $1 AND $2 
		GROUP BY severity`, startTime, endTime)
	
	if err == nil {
		defer rows2.Close()
		for rows2.Next() {
			var severity string
			var count int
			if rows2.Scan(&severity, &count) == nil {
				severityMap[severity] = count
			}
		}
	}
	summary["events_by_severity"] = severityMap
	
	// Unique actors
	var uniqueActors int
	as.db.QueryRow("SELECT COUNT(DISTINCT actor_id) FROM audit_events WHERE timestamp BETWEEN $1 AND $2", 
		startTime, endTime).Scan(&uniqueActors)
	summary["unique_actors"] = uniqueActors
	
	summary["period"] = map[string]interface{}{
		"start": startTime,
		"end":   endTime,
	}
	summary["generated_at"] = time.Now()
	
	return summary
}

func (as *AuditService) respondWithSuccess(c *gin.Context, data interface{}) {
	response := APIResponse{
		Success:   true,
		Data:      data,
		RequestID: uuid.New().String(),
		Timestamp: time.Now(),
	}
	c.JSON(http.StatusOK, response)
}

func (as *AuditService) respondWithError(c *gin.Context, code int, message string) {
	response := APIResponse{
		Success:   false,
		Error:     message,
		RequestID: uuid.New().String(),
		Timestamp: time.Now(),
	}
	c.JSON(code, response)
}

// Placeholder implementations for additional endpoints
func (as *AuditService) getEventTimeline(c *gin.Context) {
	as.respondWithSuccess(c, map[string]interface{}{
		"message": "Event timeline endpoint - implementation pending",
	})
}

func (as *AuditService) detectPatterns(c *gin.Context) {
	as.respondWithSuccess(c, map[string]interface{}{
		"message": "Pattern detection endpoint - implementation pending",
	})
}

func (as *AuditService) getComplianceReports(c *gin.Context) {
	as.respondWithSuccess(c, map[string]interface{}{
		"message": "Compliance reports endpoint - implementation pending",
	})
}

func (as *AuditService) getComplianceViolations(c *gin.Context) {
	as.respondWithSuccess(c, map[string]interface{}{
		"message": "Compliance violations endpoint - implementation pending",
	})
}

func (as *AuditService) performComplianceCheck(c *gin.Context) {
	as.respondWithSuccess(c, map[string]interface{}{
		"message": "Compliance check endpoint - implementation pending",
	})
}

func (as *AuditService) getGDPRRequests(c *gin.Context) {
	as.respondWithSuccess(c, map[string]interface{}{
		"message": "GDPR requests endpoint - implementation pending",
	})
}

func (as *AuditService) processGDPRRequest(c *gin.Context) {
	as.respondWithSuccess(c, map[string]interface{}{
		"message": "Process GDPR request endpoint - implementation pending",
	})
}

func (as *AuditService) exportPersonalData(c *gin.Context) {
	as.respondWithSuccess(c, map[string]interface{}{
		"message": "Export personal data endpoint - implementation pending",
	})
}

func (as *AuditService) getSecurityAlerts(c *gin.Context) {
	as.respondWithSuccess(c, map[string]interface{}{
		"message": "Security alerts endpoint - implementation pending",
	})
}

func (as *AuditService) resolveSecurityAlert(c *gin.Context) {
	as.respondWithSuccess(c, map[string]interface{}{
		"message": "Resolve security alert endpoint - implementation pending",
	})
}

func (as *AuditService) archiveOldData(c *gin.Context) {
	as.respondWithSuccess(c, map[string]interface{}{
		"message": "Archive old data endpoint - implementation pending",
	})
}

func (as *AuditService) purgeExpiredData(c *gin.Context) {
	as.respondWithSuccess(c, map[string]interface{}{
		"message": "Purge expired data endpoint - implementation pending",
	})
}

func (as *AuditService) checkDataIntegrity(c *gin.Context) {
	as.respondWithSuccess(c, map[string]interface{}{
		"message": "Data integrity check endpoint - implementation pending",
	})
}

func (as *AuditService) Start() error {
	router := as.setupRouter()
	
	server := &http.Server{
		Addr:    as.config.Server.Host + ":" + as.config.Server.Port,
		Handler: router,
	}
	
	as.logger.Info("Starting audit service",
		zap.String("addr", server.Addr),
	)
	
	// Graceful shutdown
	go func() {
		sigChan := make(chan os.Signal, 1)
		signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
		<-sigChan
		
		as.logger.Info("Shutting down audit service...")
		
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		
		if err := server.Shutdown(ctx); err != nil {
			as.logger.Error("Server shutdown error", zap.Error(err))
		}
		
		as.db.Close()
		as.redis.Close()
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
	service, err := NewAuditService(config, logger)
	if err != nil {
		logger.Fatal("Failed to create audit service", zap.Error(err))
	}
	
	if err := service.Start(); err != nil && err != http.ErrServerClosed {
		logger.Fatal("Audit service failed", zap.Error(err))
	}
}