package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/redis/go-redis/v9"
	"github.com/rs/cors"
	"github.com/sirupsen/logrus"
	"github.com/sony/gobreaker"
	"golang.org/x/time/rate"
	"go.uber.org/zap"
	"github.com/spf13/viper"
	"github.com/gorilla/websocket"
)

type Config struct {
	Server struct {
		Port            string        `mapstructure:"port"`
		Host            string        `mapstructure:"host"`
		ReadTimeout     time.Duration `mapstructure:"read_timeout"`
		WriteTimeout    time.Duration `mapstructure:"write_timeout"`
		IdleTimeout     time.Duration `mapstructure:"idle_timeout"`
		MaxHeaderBytes  int           `mapstructure:"max_header_bytes"`
	} `mapstructure:"server"`
	
	Redis struct {
		Addr         string        `mapstructure:"addr"`
		Password     string        `mapstructure:"password"`
		DB           int           `mapstructure:"db"`
		PoolSize     int           `mapstructure:"pool_size"`
		DialTimeout  time.Duration `mapstructure:"dial_timeout"`
		ReadTimeout  time.Duration `mapstructure:"read_timeout"`
		WriteTimeout time.Duration `mapstructure:"write_timeout"`
	} `mapstructure:"redis"`
	
	JWT struct {
		Secret     string        `mapstructure:"secret"`
		Expiration time.Duration `mapstructure:"expiration"`
		Issuer     string        `mapstructure:"issuer"`
	} `mapstructure:"jwt"`
	
	RateLimit struct {
		Requests int           `mapstructure:"requests"`
		Window   time.Duration `mapstructure:"window"`
		Burst    int           `mapstructure:"burst"`
	} `mapstructure:"rate_limit"`
	
	Services struct {
		CoreEngine     string `mapstructure:"core_engine"`
		Registration   string `mapstructure:"registration"`
		Verification   string `mapstructure:"verification"`
		Credential     string `mapstructure:"credential"`
		Audit         string `mapstructure:"audit"`
	} `mapstructure:"services"`
	
	CircuitBreaker struct {
		MaxRequests     uint32        `mapstructure:"max_requests"`
		Interval        time.Duration `mapstructure:"interval"`
		Timeout         time.Duration `mapstructure:"timeout"`
		FailureThreshold uint32       `mapstructure:"failure_threshold"`
	} `mapstructure:"circuit_breaker"`
}

type Gateway struct {
	config         *Config
	logger         *zap.Logger
	redis          *redis.Client
	router         *gin.Engine
	circuitBreaker *gobreaker.CircuitBreaker
	rateLimiter    *rate.Limiter
	metrics        *GatewayMetrics
	upgrader       websocket.Upgrader
	clients        map[string]*websocket.Conn
	clientsMu      sync.RWMutex
	startTime      time.Time
}

type GatewayMetrics struct {
	RequestsTotal     prometheus.Counter
	RequestDuration   prometheus.Histogram
	ActiveConnections prometheus.Gauge
	ErrorsTotal       prometheus.Counter
	CircuitBreakerState prometheus.Gauge
	RateLimitHits     prometheus.Counter
}

type JWTClaims struct {
	UserID   string `json:"user_id"`
	Role     string `json:"role"`
	Scope    string `json:"scope"`
	jwt.RegisteredClaims
}

type APIResponse struct {
	Success   bool        `json:"success"`
	Data      interface{} `json:"data,omitempty"`
	Error     string      `json:"error,omitempty"`
	RequestID string      `json:"request_id"`
	Timestamp time.Time   `json:"timestamp"`
}

type HealthCheck struct {
	Status     string            `json:"status"`
	Version    string            `json:"version"`
	Uptime     time.Duration     `json:"uptime"`
	Services   map[string]string `json:"services"`
	Timestamp  time.Time         `json:"timestamp"`
}

func NewGatewayMetrics() *GatewayMetrics {
	return &GatewayMetrics{
		RequestsTotal: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "gateway_requests_total",
			Help: "Total number of gateway requests",
		}),
		RequestDuration: prometheus.NewHistogram(prometheus.HistogramOpts{
			Name:    "gateway_request_duration_seconds",
			Help:    "Gateway request duration in seconds",
			Buckets: prometheus.DefBuckets,
		}),
		ActiveConnections: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "gateway_active_connections",
			Help: "Number of active gateway connections",
		}),
		ErrorsTotal: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "gateway_errors_total",
			Help: "Total number of gateway errors",
		}),
		CircuitBreakerState: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "gateway_circuit_breaker_state",
			Help: "Circuit breaker state (0=closed, 1=half-open, 2=open)",
		}),
		RateLimitHits: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "gateway_rate_limit_hits_total",
			Help: "Total number of rate limit hits",
		}),
	}
}

func (m *GatewayMetrics) Register() {
	prometheus.MustRegister(
		m.RequestsTotal,
		m.RequestDuration,
		m.ActiveConnections,
		m.ErrorsTotal,
		m.CircuitBreakerState,
		m.RateLimitHits,
	)
}

func loadConfig() (*Config, error) {
	viper.SetConfigName("config")
	viper.SetConfigType("yaml")
	viper.AddConfigPath(".")
	viper.AddConfigPath("./config")
	
	// Set defaults
	viper.SetDefault("server.port", "8080")
	viper.SetDefault("server.host", "0.0.0.0")
	viper.SetDefault("server.read_timeout", "30s")
	viper.SetDefault("server.write_timeout", "30s")
	viper.SetDefault("server.idle_timeout", "120s")
	viper.SetDefault("server.max_header_bytes", 1048576)
	
	viper.SetDefault("redis.addr", "localhost:6379")
	viper.SetDefault("redis.db", 0)
	viper.SetDefault("redis.pool_size", 10)
	
	viper.SetDefault("jwt.secret", "your-jwt-secret-key")
	viper.SetDefault("jwt.expiration", "24h")
	viper.SetDefault("jwt.issuer", "digital-id-gateway")
	
	viper.SetDefault("rate_limit.requests", 100)
	viper.SetDefault("rate_limit.window", "1m")
	viper.SetDefault("rate_limit.burst", 10)
	
	viper.SetDefault("services.core_engine", "http://localhost:3000")
	viper.SetDefault("services.registration", "http://localhost:8081")
	viper.SetDefault("services.verification", "http://localhost:8082")
	viper.SetDefault("services.credential", "http://localhost:8083")
	viper.SetDefault("services.audit", "http://localhost:8084")
	
	// Circuit breaker defaults
	viper.SetDefault("circuit_breaker.max_requests", 3)
	viper.SetDefault("circuit_breaker.interval", "60s")
	viper.SetDefault("circuit_breaker.timeout", "60s")
	viper.SetDefault("circuit_breaker.failure_threshold", 5)
	
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

func NewGateway(config *Config, logger *zap.Logger) (*Gateway, error) {
	// Initialize Redis
	rdb := redis.NewClient(&redis.Options{
		Addr:         config.Redis.Addr,
		Password:     config.Redis.Password,
		DB:           config.Redis.DB,
		PoolSize:     config.Redis.PoolSize,
		DialTimeout:  config.Redis.DialTimeout,
		ReadTimeout:  config.Redis.ReadTimeout,
		WriteTimeout: config.Redis.WriteTimeout,
	})
	
	// Test Redis connection
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := rdb.Ping(ctx).Err(); err != nil {
		logger.Warn("Redis connection failed, continuing without cache", zap.Error(err))
	}
	
	// Initialize circuit breaker
	cb := gobreaker.NewCircuitBreaker(gobreaker.Settings{
		Name:        "gateway-circuit-breaker",
		MaxRequests: config.CircuitBreaker.MaxRequests,
		Interval:    config.CircuitBreaker.Interval,
		Timeout:     config.CircuitBreaker.Timeout,
		ReadyToTrip: func(counts gobreaker.Counts) bool {
			return counts.ConsecutiveFailures >= config.CircuitBreaker.FailureThreshold
		},
		OnStateChange: func(name string, from, to gobreaker.State) {
			logger.Info("Circuit breaker state changed",
				zap.String("name", name),
				zap.String("from", from.String()),
				zap.String("to", to.String()),
			)
		},
	})
	
	// Initialize rate limiter
	rateLimiter := rate.NewLimiter(
		rate.Limit(config.RateLimit.Requests)/rate.Limit(config.RateLimit.Window.Seconds()),
		config.RateLimit.Burst,
	)
	
	// Initialize metrics
	metrics := NewGatewayMetrics()
	metrics.Register()
	
	// Initialize WebSocket upgrader
	upgrader := websocket.Upgrader{
		CheckOrigin: func(r *http.Request) bool {
			return true // Configure properly for production
		},
	}
	
	return &Gateway{
		config:         config,
		logger:         logger,
		redis:          rdb,
		circuitBreaker: cb,
		rateLimiter:    rateLimiter,
		metrics:        metrics,
		upgrader:       upgrader,
		clients:        make(map[string]*websocket.Conn),
		startTime:      time.Now(),
	}, nil
}

func (g *Gateway) setupRouter() {
	gin.SetMode(gin.ReleaseMode)
	r := gin.New()
	
	// Middleware
	r.Use(g.loggingMiddleware())
	r.Use(g.corsMiddleware())
	r.Use(g.metricsMiddleware())
	r.Use(g.rateLimitMiddleware())
	r.Use(gin.Recovery())
	
	// Health endpoints
	r.GET("/health", g.healthCheck)
	r.GET("/ready", g.readinessCheck)
	r.GET("/metrics", gin.WrapH(promhttp.Handler()))
	
	// WebSocket endpoint
	r.GET("/ws", g.handleWebSocket)
	
	// API routes with JWT middleware
	api := r.Group("/api/v1")
	api.Use(g.jwtMiddleware())
	{
		// Identity verification routes
		api.POST("/verify", g.proxyToService("core_engine", "/verify"))
		api.POST("/verify/batch", g.proxyToService("core_engine", "/verify/batch"))
		api.GET("/verify/:id/status", g.proxyToService("core_engine", "/verify/%s/status"))
		api.POST("/verify/:id/cancel", g.proxyToService("core_engine", "/verify/%s/cancel"))
		
		// Registration routes
		api.POST("/register", g.proxyToService("registration", "/register"))
		api.GET("/register/:id", g.proxyToService("registration", "/register/%s"))
		api.PUT("/register/:id", g.proxyToService("registration", "/register/%s"))
		api.DELETE("/register/:id", g.proxyToService("registration", "/register/%s"))
		
		// Credential routes
		api.POST("/credentials", g.proxyToService("credential", "/credentials"))
		api.GET("/credentials/:id", g.proxyToService("credential", "/credentials/%s"))
		api.POST("/credentials/:id/revoke", g.proxyToService("credential", "/credentials/%s/revoke"))
		
		// Audit routes
		api.GET("/audit/logs", g.proxyToService("audit", "/audit/logs"))
		api.GET("/audit/reports", g.proxyToService("audit", "/audit/reports"))
	}
	
	// Public routes (no JWT required)
	public := r.Group("/public")
	{
		public.POST("/auth/login", g.login)
		public.POST("/auth/refresh", g.refreshToken)
		public.GET("/status", g.systemStatus)
	}
	
	g.router = r
}

func (g *Gateway) loggingMiddleware() gin.HandlerFunc {
	return gin.LoggerWithWriter(gin.DefaultWriter, "/health", "/ready", "/metrics")
}

func (g *Gateway) corsMiddleware() gin.HandlerFunc {
	c := cors.New(cors.Options{
		AllowedOrigins:   []string{"*"}, // Configure for production
		AllowedMethods:   []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
		AllowedHeaders:   []string{"*"},
		ExposedHeaders:   []string{"Content-Length", "Authorization"},
		AllowCredentials: true,
		MaxAge:           12 * time.Hour,
	})
	
	return func(ctx *gin.Context) {
		c.HandlerFunc(ctx.Writer, ctx.Request)
		ctx.Next()
	}
}

func (g *Gateway) metricsMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		start := time.Now()
		
		g.metrics.RequestsTotal.Inc()
		g.metrics.ActiveConnections.Inc()
		
		defer func() {
			duration := time.Since(start)
			g.metrics.RequestDuration.Observe(duration.Seconds())
			g.metrics.ActiveConnections.Dec()
		}()
		
		c.Next()
		
		if c.Writer.Status() >= 400 {
			g.metrics.ErrorsTotal.Inc()
		}
	}
}

func (g *Gateway) rateLimitMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		if !g.rateLimiter.Allow() {
			g.metrics.RateLimitHits.Inc()
			g.respondWithError(c, http.StatusTooManyRequests, "Rate limit exceeded")
			c.Abort()
			return
		}
		c.Next()
	}
}

func (g *Gateway) jwtMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		authHeader := c.GetHeader("Authorization")
		if authHeader == "" {
			g.respondWithError(c, http.StatusUnauthorized, "Authorization header required")
			c.Abort()
			return
		}
		
		tokenString := strings.TrimPrefix(authHeader, "Bearer ")
		if tokenString == authHeader {
			g.respondWithError(c, http.StatusUnauthorized, "Invalid authorization format")
			c.Abort()
			return
		}
		
		claims := &JWTClaims{}
		token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
			}
			return []byte(g.config.JWT.Secret), nil
		})
		
		if err != nil || !token.Valid {
			g.respondWithError(c, http.StatusUnauthorized, "Invalid token")
			c.Abort()
			return
		}
		
		c.Set("user_id", claims.UserID)
		c.Set("role", claims.Role)
		c.Set("scope", claims.Scope)
		c.Next()
	}
}

func (g *Gateway) proxyToService(serviceName, path string) gin.HandlerFunc {
	return func(c *gin.Context) {
		serviceURL := g.getServiceURL(serviceName)
		if serviceURL == "" {
			g.respondWithError(c, http.StatusServiceUnavailable, "Service not available")
			return
		}
		
		// Format path with URL parameters
		if strings.Contains(path, "%s") {
			id := c.Param("id")
			path = fmt.Sprintf(path, id)
		}
		
		fullURL := serviceURL + path
		
		// Execute request through circuit breaker
		result, err := g.circuitBreaker.Execute(func() (interface{}, error) {
			return g.forwardRequest(c, fullURL)
		})
		
		if err != nil {
			g.logger.Error("Service request failed",
				zap.String("service", serviceName),
				zap.String("url", fullURL),
				zap.Error(err),
			)
			g.respondWithError(c, http.StatusBadGateway, "Service unavailable")
			return
		}
		
		response := result.(map[string]interface{})
		g.respondWithSuccess(c, response)
	}
}

func (g *Gateway) forwardRequest(c *gin.Context, url string) (map[string]interface{}, error) {
	client := &http.Client{
		Timeout: 30 * time.Second,
	}
	
	// Create request
	req, err := http.NewRequest(c.Request.Method, url, c.Request.Body)
	if err != nil {
		return nil, err
	}
	
	// Copy headers
	for key, values := range c.Request.Header {
		for _, value := range values {
			req.Header.Add(key, value)
		}
	}
	
	// Forward query parameters
	req.URL.RawQuery = c.Request.URL.RawQuery
	
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	
	var result map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}
	
	c.Status(resp.StatusCode)
	return result, nil
}

func (g *Gateway) getServiceURL(serviceName string) string {
	switch serviceName {
	case "core_engine":
		return g.config.Services.CoreEngine
	case "registration":
		return g.config.Services.Registration
	case "verification":
		return g.config.Services.Verification
	case "credential":
		return g.config.Services.Credential
	case "audit":
		return g.config.Services.Audit
	default:
		return ""
	}
}

func (g *Gateway) healthCheck(c *gin.Context) {
	health := HealthCheck{
		Status:    "healthy",
		Version:   "1.0.0",
		Uptime:    time.Since(g.startTime),
		Services:  make(map[string]string),
		Timestamp: time.Now(),
	}
	
	// Check service health
	services := map[string]string{
		"core_engine":  g.config.Services.CoreEngine,
		"registration": g.config.Services.Registration,
		"verification": g.config.Services.Verification,
		"credential":   g.config.Services.Credential,
		"audit":       g.config.Services.Audit,
	}
	
	for name, url := range services {
		status := "healthy"
		if !g.checkServiceHealth(url) {
			status = "unhealthy"
			health.Status = "degraded"
		}
		health.Services[name] = status
	}
	
	g.respondWithSuccess(c, health)
}

func (g *Gateway) readinessCheck(c *gin.Context) {
	// Check critical dependencies
	if g.redis.Ping(context.Background()).Err() != nil {
		g.respondWithError(c, http.StatusServiceUnavailable, "Redis not ready")
		return
	}
	
	g.respondWithSuccess(c, map[string]string{"status": "ready"})
}

func (g *Gateway) checkServiceHealth(url string) bool {
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Get(url + "/health")
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	
	return resp.StatusCode == http.StatusOK
}

func (g *Gateway) login(c *gin.Context) {
	var loginReq struct {
		Username string `json:"username" binding:"required"`
		Password string `json:"password" binding:"required"`
	}
	
	if err := c.ShouldBindJSON(&loginReq); err != nil {
		g.respondWithError(c, http.StatusBadRequest, err.Error())
		return
	}
	
	// TODO: Implement actual authentication
	// For now, create a token for demo purposes
	claims := &JWTClaims{
		UserID: uuid.New().String(),
		Role:   "user",
		Scope:  "read:write",
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    g.config.JWT.Issuer,
			Subject:   loginReq.Username,
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(g.config.JWT.Expiration)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		},
	}
	
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString([]byte(g.config.JWT.Secret))
	if err != nil {
		g.respondWithError(c, http.StatusInternalServerError, "Failed to generate token")
		return
	}
	
	g.respondWithSuccess(c, map[string]interface{}{
		"token":      tokenString,
		"expires_at": claims.ExpiresAt.Time,
		"user_id":    claims.UserID,
	})
}

func (g *Gateway) refreshToken(c *gin.Context) {
	// Implementation for token refresh
	g.respondWithError(c, http.StatusNotImplemented, "Token refresh not implemented")
}

func (g *Gateway) systemStatus(c *gin.Context) {
	status := map[string]interface{}{
		"gateway":   "operational",
		"version":   "1.0.0",
		"timestamp": time.Now(),
		"uptime":    time.Since(g.startTime),
	}
	
	g.respondWithSuccess(c, status)
}

func (g *Gateway) handleWebSocket(c *gin.Context) {
	conn, err := g.upgrader.Upgrade(c.Writer, c.Request, nil)
	if err != nil {
		g.logger.Error("WebSocket upgrade failed", zap.Error(err))
		return
	}
	defer conn.Close()
	
	clientID := uuid.New().String()
	g.clientsMu.Lock()
	g.clients[clientID] = conn
	g.clientsMu.Unlock()
	
	defer func() {
		g.clientsMu.Lock()
		delete(g.clients, clientID)
		g.clientsMu.Unlock()
	}()
	
	for {
		_, message, err := conn.ReadMessage()
		if err != nil {
			g.logger.Error("WebSocket read error", zap.Error(err))
			break
		}
		
		g.logger.Info("WebSocket message received",
			zap.String("client_id", clientID),
			zap.String("message", string(message)),
		)
		
		// Echo message back for now
		if err := conn.WriteMessage(websocket.TextMessage, message); err != nil {
			g.logger.Error("WebSocket write error", zap.Error(err))
			break
		}
	}
}

func (g *Gateway) respondWithSuccess(c *gin.Context, data interface{}) {
	response := APIResponse{
		Success:   true,
		Data:      data,
		RequestID: uuid.New().String(),
		Timestamp: time.Now(),
	}
	c.JSON(http.StatusOK, response)
}

func (g *Gateway) respondWithError(c *gin.Context, code int, message string) {
	response := APIResponse{
		Success:   false,
		Error:     message,
		RequestID: uuid.New().String(),
		Timestamp: time.Now(),
	}
	c.JSON(code, response)
}

func (g *Gateway) Start() error {
	g.setupRouter()
	
	server := &http.Server{
		Addr:           g.config.Server.Host + ":" + g.config.Server.Port,
		Handler:        g.router,
		ReadTimeout:    g.config.Server.ReadTimeout,
		WriteTimeout:   g.config.Server.WriteTimeout,
		IdleTimeout:    g.config.Server.IdleTimeout,
		MaxHeaderBytes: g.config.Server.MaxHeaderBytes,
	}
	
	g.logger.Info("Starting gateway server",
		zap.String("addr", server.Addr),
	)
	
	// Graceful shutdown
	go func() {
		sigChan := make(chan os.Signal, 1)
		signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
		<-sigChan
		
		g.logger.Info("Shutting down gateway server...")
		
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		
		if err := server.Shutdown(ctx); err != nil {
			g.logger.Error("Server shutdown error", zap.Error(err))
		}
		
		g.redis.Close()
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
	
	// Create and start gateway
	gateway, err := NewGateway(config, logger)
	if err != nil {
		logger.Fatal("Failed to create gateway", zap.Error(err))
	}
	
	if err := gateway.Start(); err != nil && err != http.ErrServerClosed {
		logger.Fatal("Gateway server failed", zap.Error(err))
	}
}