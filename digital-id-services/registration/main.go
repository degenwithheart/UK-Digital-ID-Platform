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
	"golang.org/x/crypto/bcrypt"
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
	
	JWT struct {
		Secret string `mapstructure:"secret"`
	} `mapstructure:"jwt"`
	
	RateLimit struct {
		Requests int           `mapstructure:"requests"`
		Window   time.Duration `mapstructure:"window"`
		Burst    int           `mapstructure:"burst"`
	} `mapstructure:"rate_limit"`
}

type RegistrationService struct {
	config         *Config
	logger         *zap.Logger
	db             *sql.DB
	redis          *redis.Client
	validator      *validator.Validate
	circuitBreaker *gobreaker.CircuitBreaker
	rateLimiter    *rate.Limiter
	metrics        *RegistrationMetrics
	startTime      time.Time
}

type RegistrationMetrics struct {
	RegistrationsTotal    prometheus.Counter
	RegistrationsSuccess  prometheus.Counter
	RegistrationsFailed   prometheus.Counter
	VerificationsSent     prometheus.Counter
	RequestDuration       prometheus.Histogram
	ActiveSessions        prometheus.Gauge
}

type User struct {
	ID                string    `json:"id" db:"id"`
	Email             string    `json:"email" db:"email" validate:"required,email"`
	FirstName         string    `json:"first_name" db:"first_name" validate:"required,min=2,max=50"`
	LastName          string    `json:"last_name" db:"last_name" validate:"required,min=2,max=50"`
	DateOfBirth       string    `json:"date_of_birth" db:"date_of_birth" validate:"required"`
	PhoneNumber       string    `json:"phone_number" db:"phone_number" validate:"required,min=10,max=15"`
	NationalInsurance string    `json:"national_insurance" db:"national_insurance" validate:"required,len=9"`
	Address           Address   `json:"address" validate:"required"`
	PasswordHash      string    `json:"-" db:"password_hash"`
	EmailVerified     bool      `json:"email_verified" db:"email_verified"`
	PhoneVerified     bool      `json:"phone_verified" db:"phone_verified"`
	Status            string    `json:"status" db:"status"`
	CreatedAt         time.Time `json:"created_at" db:"created_at"`
	UpdatedAt         time.Time `json:"updated_at" db:"updated_at"`
}

type Address struct {
	Street   string `json:"street" validate:"required,min=5,max=100"`
	City     string `json:"city" validate:"required,min=2,max=50"`
	County   string `json:"county" validate:"required,min=2,max=50"`
	Postcode string `json:"postcode" validate:"required,min=5,max=10"`
	Country  string `json:"country" validate:"required,len=2"`
}

type RegistrationRequest struct {
	Email             string  `json:"email" validate:"required,email"`
	Password          string  `json:"password" validate:"required,min=8,max=128"`
	ConfirmPassword   string  `json:"confirm_password" validate:"required,eqfield=Password"`
	FirstName         string  `json:"first_name" validate:"required,min=2,max=50"`
	LastName          string  `json:"last_name" validate:"required,min=2,max=50"`
	DateOfBirth       string  `json:"date_of_birth" validate:"required"`
	PhoneNumber       string  `json:"phone_number" validate:"required,min=10,max=15"`
	NationalInsurance string  `json:"national_insurance" validate:"required,len=9"`
	Address           Address `json:"address" validate:"required"`
	AcceptTerms       bool    `json:"accept_terms" validate:"required"`
	AcceptPrivacy     bool    `json:"accept_privacy" validate:"required"`
}

type VerificationRequest struct {
	UserID string `json:"user_id" validate:"required,uuid"`
	Type   string `json:"type" validate:"required,oneof=email phone"`
	Code   string `json:"code,omitempty"`
}

type APIResponse struct {
	Success   bool        `json:"success"`
	Data      interface{} `json:"data,omitempty"`
	Error     string      `json:"error,omitempty"`
	RequestID string      `json:"request_id"`
	Timestamp time.Time   `json:"timestamp"`
}

func NewRegistrationMetrics() *RegistrationMetrics {
	return &RegistrationMetrics{
		RegistrationsTotal: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "registrations_total",
			Help: "Total number of registration attempts",
		}),
		RegistrationsSuccess: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "registrations_success_total",
			Help: "Total number of successful registrations",
		}),
		RegistrationsFailed: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "registrations_failed_total",
			Help: "Total number of failed registrations",
		}),
		VerificationsSent: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "verifications_sent_total",
			Help: "Total number of verification messages sent",
		}),
		RequestDuration: prometheus.NewHistogram(prometheus.HistogramOpts{
			Name:    "registration_request_duration_seconds",
			Help:    "Registration request duration in seconds",
			Buckets: prometheus.DefBuckets,
		}),
		ActiveSessions: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "registration_active_sessions",
			Help: "Number of active registration sessions",
		}),
	}
}

func (m *RegistrationMetrics) Register() {
	prometheus.MustRegister(
		m.RegistrationsTotal,
		m.RegistrationsSuccess,
		m.RegistrationsFailed,
		m.VerificationsSent,
		m.RequestDuration,
		m.ActiveSessions,
	)
}

func loadConfig() (*Config, error) {
	viper.SetConfigName("config")
	viper.SetConfigType("yaml")
	viper.AddConfigPath(".")
	viper.AddConfigPath("./config")
	
	// Set defaults
	viper.SetDefault("server.port", "8081")
	viper.SetDefault("server.host", "0.0.0.0")
	viper.SetDefault("database.max_connections", 25)
	viper.SetDefault("database.max_idle_time", "15m")
	viper.SetDefault("database.max_lifetime", "1h")
	viper.SetDefault("database.connect_timeout", "10s")
	viper.SetDefault("redis.addr", "localhost:6379")
	viper.SetDefault("redis.db", 1)
	viper.SetDefault("jwt.secret", "registration-service-secret")
	viper.SetDefault("rate_limit.requests", 10)
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

func NewRegistrationService(config *Config, logger *zap.Logger) (*RegistrationService, error) {
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
		Name:        "registration-circuit-breaker",
		MaxRequests: 3,
		Interval:    60 * time.Second,
		Timeout:     60 * time.Second,
		ReadyToTrip: func(counts gobreaker.Counts) bool {
			return counts.ConsecutiveFailures >= 5
		},
	})
	
	// Initialize rate limiter
	rateLimiter := rate.NewLimiter(
		rate.Limit(config.RateLimit.Requests)/rate.Limit(config.RateLimit.Window.Seconds()),
		config.RateLimit.Burst,
	)
	
	// Initialize metrics
	metrics := NewRegistrationMetrics()
	metrics.Register()
	
	return &RegistrationService{
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

func (rs *RegistrationService) setupRouter() *gin.Engine {
	gin.SetMode(gin.ReleaseMode)
	r := gin.New()
	
	// Middleware
	r.Use(rs.loggingMiddleware())
	r.Use(rs.metricsMiddleware())
	r.Use(rs.rateLimitMiddleware())
	r.Use(gin.Recovery())
	
	// Health endpoints
	r.GET("/health", rs.healthCheck)
	r.GET("/ready", rs.readinessCheck)
	r.GET("/metrics", gin.WrapH(promhttp.Handler()))
	
	// Registration endpoints
	r.POST("/register", rs.registerUser)
	r.POST("/verify", rs.verifyUser)
	r.POST("/resend-verification", rs.resendVerification)
	
	// User management endpoints (require authentication)
	auth := r.Group("/")
	auth.Use(rs.authMiddleware())
	{
		auth.GET("/register/:id", rs.getUser)
		auth.PUT("/register/:id", rs.updateUser)
		auth.DELETE("/register/:id", rs.deleteUser)
		auth.GET("/register/:id/status", rs.getUserStatus)
	}
	
	return r
}

func (rs *RegistrationService) loggingMiddleware() gin.HandlerFunc {
	return gin.LoggerWithWriter(gin.DefaultWriter, "/health", "/ready", "/metrics")
}

func (rs *RegistrationService) metricsMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		start := time.Now()
		rs.metrics.ActiveSessions.Inc()
		
		defer func() {
			duration := time.Since(start)
			rs.metrics.RequestDuration.Observe(duration.Seconds())
			rs.metrics.ActiveSessions.Dec()
		}()
		
		c.Next()
	}
}

func (rs *RegistrationService) rateLimitMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		if !rs.rateLimiter.Allow() {
			rs.respondWithError(c, http.StatusTooManyRequests, "Rate limit exceeded")
			c.Abort()
			return
		}
		c.Next()
	}
}

func (rs *RegistrationService) authMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		authHeader := c.GetHeader("Authorization")
		if authHeader == "" {
			rs.respondWithError(c, http.StatusUnauthorized, "Authorization header required")
			c.Abort()
			return
		}
		
		tokenString := strings.TrimPrefix(authHeader, "Bearer ")
		if tokenString == authHeader {
			rs.respondWithError(c, http.StatusUnauthorized, "Invalid authorization format")
			c.Abort()
			return
		}
		
		// Parse JWT token (simplified - use proper JWT validation)
		token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("unexpected signing method")
			}
			return []byte(rs.config.JWT.Secret), nil
		})
		
		if err != nil || !token.Valid {
			rs.respondWithError(c, http.StatusUnauthorized, "Invalid token")
			c.Abort()
			return
		}
		
		c.Next()
	}
}

func (rs *RegistrationService) registerUser(c *gin.Context) {
	rs.metrics.RegistrationsTotal.Inc()
	
	var req RegistrationRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		rs.metrics.RegistrationsFailed.Inc()
		rs.respondWithError(c, http.StatusBadRequest, err.Error())
		return
	}
	
	// Validate request
	if err := rs.validator.Struct(&req); err != nil {
		rs.metrics.RegistrationsFailed.Inc()
		rs.respondWithError(c, http.StatusBadRequest, fmt.Sprintf("Validation error: %v", err))
		return
	}
	
	// Check if user already exists
	exists, err := rs.userExists(req.Email)
	if err != nil {
		rs.metrics.RegistrationsFailed.Inc()
		rs.logger.Error("Failed to check user existence", zap.Error(err))
		rs.respondWithError(c, http.StatusInternalServerError, "Internal server error")
		return
	}
	
	if exists {
		rs.metrics.RegistrationsFailed.Inc()
		rs.respondWithError(c, http.StatusConflict, "User already exists")
		return
	}
	
	// Hash password
	passwordHash, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		rs.metrics.RegistrationsFailed.Inc()
		rs.logger.Error("Failed to hash password", zap.Error(err))
		rs.respondWithError(c, http.StatusInternalServerError, "Internal server error")
		return
	}
	
	// Create user
	user := &User{
		ID:                uuid.New().String(),
		Email:             req.Email,
		FirstName:         req.FirstName,
		LastName:          req.LastName,
		DateOfBirth:       req.DateOfBirth,
		PhoneNumber:       req.PhoneNumber,
		NationalInsurance: req.NationalInsurance,
		Address:           req.Address,
		PasswordHash:      string(passwordHash),
		Status:           "pending_verification",
		CreatedAt:        time.Now(),
		UpdatedAt:        time.Now(),
	}
	
	// Save to database
	if err := rs.createUser(user); err != nil {
		rs.metrics.RegistrationsFailed.Inc()
		rs.logger.Error("Failed to create user", zap.Error(err))
		rs.respondWithError(c, http.StatusInternalServerError, "Failed to create user")
		return
	}
	
	// Send verification emails/SMS
	go rs.sendVerificationMessages(user)
	
	rs.metrics.RegistrationsSuccess.Inc()
	
	// Return user without sensitive data
	response := map[string]interface{}{
		"user_id": user.ID,
		"email":   user.Email,
		"status":  user.Status,
		"message": "Registration successful. Please check your email and phone for verification codes.",
	}
	
	rs.respondWithSuccess(c, response)
}

func (rs *RegistrationService) verifyUser(c *gin.Context) {
	var req VerificationRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		rs.respondWithError(c, http.StatusBadRequest, err.Error())
		return
	}
	
	if err := rs.validator.Struct(&req); err != nil {
		rs.respondWithError(c, http.StatusBadRequest, fmt.Sprintf("Validation error: %v", err))
		return
	}
	
	// Verify the code from Redis
	storedCode, err := rs.redis.Get(context.Background(), rs.getVerificationKey(req.UserID, req.Type)).Result()
	if err != nil {
		rs.respondWithError(c, http.StatusBadRequest, "Invalid or expired verification code")
		return
	}
	
	if storedCode != req.Code {
		rs.respondWithError(c, http.StatusBadRequest, "Invalid verification code")
		return
	}
	
	// Update user verification status
	if err := rs.updateVerificationStatus(req.UserID, req.Type); err != nil {
		rs.logger.Error("Failed to update verification status", zap.Error(err))
		rs.respondWithError(c, http.StatusInternalServerError, "Failed to update verification status")
		return
	}
	
	// Remove verification code from Redis
	rs.redis.Del(context.Background(), rs.getVerificationKey(req.UserID, req.Type))
	
	rs.respondWithSuccess(c, map[string]interface{}{
		"message": fmt.Sprintf("%s verification successful", req.Type),
	})
}

func (rs *RegistrationService) resendVerification(c *gin.Context) {
	var req struct {
		UserID string `json:"user_id" validate:"required,uuid"`
		Type   string `json:"type" validate:"required,oneof=email phone"`
	}
	
	if err := c.ShouldBindJSON(&req); err != nil {
		rs.respondWithError(c, http.StatusBadRequest, err.Error())
		return
	}
	
	if err := rs.validator.Struct(&req); err != nil {
		rs.respondWithError(c, http.StatusBadRequest, fmt.Sprintf("Validation error: %v", err))
		return
	}
	
	user, err := rs.getUserByID(req.UserID)
	if err != nil {
		rs.respondWithError(c, http.StatusNotFound, "User not found")
		return
	}
	
	// Send verification message
	if req.Type == "email" {
		go rs.sendEmailVerification(user)
	} else {
		go rs.sendSMSVerification(user)
	}
	
	rs.respondWithSuccess(c, map[string]interface{}{
		"message": fmt.Sprintf("%s verification code resent", req.Type),
	})
}

func (rs *RegistrationService) getUser(c *gin.Context) {
	userID := c.Param("id")
	
	user, err := rs.getUserByID(userID)
	if err != nil {
		rs.respondWithError(c, http.StatusNotFound, "User not found")
		return
	}
	
	// Remove sensitive data
	user.PasswordHash = ""
	
	rs.respondWithSuccess(c, user)
}

func (rs *RegistrationService) updateUser(c *gin.Context) {
	userID := c.Param("id")
	
	var updates map[string]interface{}
	if err := c.ShouldBindJSON(&updates); err != nil {
		rs.respondWithError(c, http.StatusBadRequest, err.Error())
		return
	}
	
	// Remove sensitive fields from updates
	delete(updates, "id")
	delete(updates, "password_hash")
	delete(updates, "created_at")
	
	if err := rs.updateUserFields(userID, updates); err != nil {
		rs.logger.Error("Failed to update user", zap.Error(err))
		rs.respondWithError(c, http.StatusInternalServerError, "Failed to update user")
		return
	}
	
	rs.respondWithSuccess(c, map[string]interface{}{
		"message": "User updated successfully",
	})
}

func (rs *RegistrationService) deleteUser(c *gin.Context) {
	userID := c.Param("id")
	
	if err := rs.deleteUserByID(userID); err != nil {
		rs.logger.Error("Failed to delete user", zap.Error(err))
		rs.respondWithError(c, http.StatusInternalServerError, "Failed to delete user")
		return
	}
	
	rs.respondWithSuccess(c, map[string]interface{}{
		"message": "User deleted successfully",
	})
}

func (rs *RegistrationService) getUserStatus(c *gin.Context) {
	userID := c.Param("id")
	
	status, err := rs.getUserVerificationStatus(userID)
	if err != nil {
		rs.respondWithError(c, http.StatusNotFound, "User not found")
		return
	}
	
	rs.respondWithSuccess(c, status)
}

func (rs *RegistrationService) healthCheck(c *gin.Context) {
	status := map[string]interface{}{
		"status":    "healthy",
		"version":   "1.0.0",
		"timestamp": time.Now(),
		"uptime":    time.Since(rs.startTime),
	}
	
	// Check database health
	if err := rs.db.Ping(); err != nil {
		status["status"] = "unhealthy"
		status["database"] = "disconnected"
	} else {
		status["database"] = "connected"
	}
	
	// Check Redis health
	if err := rs.redis.Ping(context.Background()).Err(); err != nil {
		status["redis"] = "disconnected"
	} else {
		status["redis"] = "connected"
	}
	
	rs.respondWithSuccess(c, status)
}

func (rs *RegistrationService) readinessCheck(c *gin.Context) {
	if err := rs.db.Ping(); err != nil {
		rs.respondWithError(c, http.StatusServiceUnavailable, "Database not ready")
		return
	}
	
	rs.respondWithSuccess(c, map[string]string{"status": "ready"})
}

// Database operations
func (rs *RegistrationService) userExists(email string) (bool, error) {
	var count int
	err := rs.db.QueryRow("SELECT COUNT(*) FROM users WHERE email = $1", email).Scan(&count)
	return count > 0, err
}

func (rs *RegistrationService) createUser(user *User) error {
	query := `
		INSERT INTO users (id, email, first_name, last_name, date_of_birth, phone_number, 
		                  national_insurance, address_street, address_city, address_county, 
		                  address_postcode, address_country, password_hash, status, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16)`
	
	_, err := rs.db.Exec(query,
		user.ID, user.Email, user.FirstName, user.LastName, user.DateOfBirth,
		user.PhoneNumber, user.NationalInsurance, user.Address.Street,
		user.Address.City, user.Address.County, user.Address.Postcode,
		user.Address.Country, user.PasswordHash, user.Status,
		user.CreatedAt, user.UpdatedAt)
	
	return err
}

func (rs *RegistrationService) getUserByID(userID string) (*User, error) {
	user := &User{}
	query := `
		SELECT id, email, first_name, last_name, date_of_birth, phone_number, 
		       national_insurance, address_street, address_city, address_county, 
		       address_postcode, address_country, email_verified, phone_verified, 
		       status, created_at, updated_at
		FROM users WHERE id = $1`
	
	var addressStreet, addressCity, addressCounty, addressPostcode, addressCountry string
	err := rs.db.QueryRow(query, userID).Scan(
		&user.ID, &user.Email, &user.FirstName, &user.LastName, &user.DateOfBirth,
		&user.PhoneNumber, &user.NationalInsurance, &addressStreet, &addressCity,
		&addressCounty, &addressPostcode, &addressCountry, &user.EmailVerified,
		&user.PhoneVerified, &user.Status, &user.CreatedAt, &user.UpdatedAt)
	
	if err != nil {
		return nil, err
	}
	
	user.Address = Address{
		Street:   addressStreet,
		City:     addressCity,
		County:   addressCounty,
		Postcode: addressPostcode,
		Country:  addressCountry,
	}
	
	return user, nil
}

func (rs *RegistrationService) updateVerificationStatus(userID, verificationType string) error {
	var query string
	
	switch verificationType {
	case "email":
		query = "UPDATE users SET email_verified = true, updated_at = $2 WHERE id = $1"
	case "phone":
		query = "UPDATE users SET phone_verified = true, updated_at = $2 WHERE id = $1"
	default:
		return fmt.Errorf("invalid verification type: %s", verificationType)
	}
	
	_, err := rs.db.Exec(query, userID, time.Now())
	return err
}

func (rs *RegistrationService) updateUserFields(userID string, updates map[string]interface{}) error {
	// Build dynamic update query
	setParts := make([]string, 0, len(updates))
	args := make([]interface{}, 0, len(updates)+2)
	argIndex := 1
	
	for field, value := range updates {
		setParts = append(setParts, fmt.Sprintf("%s = $%d", field, argIndex))
		args = append(args, value)
		argIndex++
	}
	
	if len(setParts) == 0 {
		return fmt.Errorf("no fields to update")
	}
	
	// Add updated_at
	setParts = append(setParts, fmt.Sprintf("updated_at = $%d", argIndex))
	args = append(args, time.Now())
	argIndex++
	
	// Add user ID
	args = append(args, userID)
	
	query := fmt.Sprintf("UPDATE users SET %s WHERE id = $%d", strings.Join(setParts, ", "), argIndex)
	
	_, err := rs.db.Exec(query, args...)
	return err
}

func (rs *RegistrationService) deleteUserByID(userID string) error {
	_, err := rs.db.Exec("DELETE FROM users WHERE id = $1", userID)
	return err
}

func (rs *RegistrationService) getUserVerificationStatus(userID string) (map[string]interface{}, error) {
	var emailVerified, phoneVerified bool
	var status string
	
	query := "SELECT email_verified, phone_verified, status FROM users WHERE id = $1"
	err := rs.db.QueryRow(query, userID).Scan(&emailVerified, &phoneVerified, &status)
	if err != nil {
		return nil, err
	}
	
	return map[string]interface{}{
		"user_id":        userID,
		"email_verified": emailVerified,
		"phone_verified": phoneVerified,
		"status":         status,
		"fully_verified": emailVerified && phoneVerified,
	}, nil
}

// Verification message functions
func (rs *RegistrationService) sendVerificationMessages(user *User) {
	rs.sendEmailVerification(user)
	rs.sendSMSVerification(user)
}

func (rs *RegistrationService) sendEmailVerification(user *User) {
	code := rs.generateVerificationCode()
	key := rs.getVerificationKey(user.ID, "email")
	
	// Store code in Redis with 10 minute expiration
	rs.redis.Set(context.Background(), key, code, 10*time.Minute)
	
	// TODO: Send actual email
	rs.logger.Info("Email verification code generated",
		zap.String("user_id", user.ID),
		zap.String("email", user.Email),
		zap.String("code", code),
	)
	
	rs.metrics.VerificationsSent.Inc()
}

func (rs *RegistrationService) sendSMSVerification(user *User) {
	code := rs.generateVerificationCode()
	key := rs.getVerificationKey(user.ID, "phone")
	
	// Store code in Redis with 10 minute expiration
	rs.redis.Set(context.Background(), key, code, 10*time.Minute)
	
	// TODO: Send actual SMS
	rs.logger.Info("SMS verification code generated",
		zap.String("user_id", user.ID),
		zap.String("phone", user.PhoneNumber),
		zap.String("code", code),
	)
	
	rs.metrics.VerificationsSent.Inc()
}

func (rs *RegistrationService) generateVerificationCode() string {
	return fmt.Sprintf("%06d", time.Now().UnixNano()%1000000)
}

func (rs *RegistrationService) getVerificationKey(userID, verificationType string) string {
	return fmt.Sprintf("verification:%s:%s", userID, verificationType)
}

func (rs *RegistrationService) respondWithSuccess(c *gin.Context, data interface{}) {
	response := APIResponse{
		Success:   true,
		Data:      data,
		RequestID: uuid.New().String(),
		Timestamp: time.Now(),
	}
	c.JSON(http.StatusOK, response)
}

func (rs *RegistrationService) respondWithError(c *gin.Context, code int, message string) {
	response := APIResponse{
		Success:   false,
		Error:     message,
		RequestID: uuid.New().String(),
		Timestamp: time.Now(),
	}
	c.JSON(code, response)
}

func (rs *RegistrationService) Start() error {
	router := rs.setupRouter()
	
	server := &http.Server{
		Addr:    rs.config.Server.Host + ":" + rs.config.Server.Port,
		Handler: router,
	}
	
	rs.logger.Info("Starting registration service",
		zap.String("addr", server.Addr),
	)
	
	// Graceful shutdown
	go func() {
		sigChan := make(chan os.Signal, 1)
		signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
		<-sigChan
		
		rs.logger.Info("Shutting down registration service...")
		
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		
		if err := server.Shutdown(ctx); err != nil {
			rs.logger.Error("Server shutdown error", zap.Error(err))
		}
		
		rs.db.Close()
		rs.redis.Close()
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
	service, err := NewRegistrationService(config, logger)
	if err != nil {
		logger.Fatal("Failed to create registration service", zap.Error(err))
	}
	
	if err := service.Start(); err != nil && err != http.ErrServerClosed {
		logger.Fatal("Registration service failed", zap.Error(err))
	}
}