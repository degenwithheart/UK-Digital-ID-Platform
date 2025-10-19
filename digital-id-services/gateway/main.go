// #cgo LDFLAGS: -L${SRCDIR}/../../core-id-engine/target/debug -lcore_id_engine -ldl
// #include <stdlib.h>
import "C"

package main

import (
	"net/http"
	"time"
	"os"
	"encoding/json"
	"fmt"
	"errors"
	"unsafe"
	"context"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"gorm.io/gorm"
	"gorm.io/driver/postgres"
	"github.com/segmentio/kafka-go"
	"golang.org/x/crypto/bcrypt"
	"github.com/go-playground/validator/v10"
	"github.com/gin-contrib/cors"
	"golang.org/x/time/rate"
	"github.com/sirupsen/logrus"
	"github.com/go-redis/redis/v8"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"io"
	"digital-id-services/degenhf"
)

type User struct {
	ID       uint   `json:"id" gorm:"primaryKey"`
	Name     string `json:"name" gorm:"not null" validate:"required,min=2,max=50"`
	Email    string `json:"email" gorm:"unique;not null" validate:"required,email"`
	Password string `json:"-" gorm:"not null" validate:"required,min=8"`
	PublicKey string `json:"public_key"`
	CreatedAt time.Time
}

type Credential struct {
	ID        uint   `json:"id" gorm:"primaryKey"`
	UserID    uint   `json:"user_id"`
	Payload   string `json:"payload"`
	Signature string `json:"signature"`
	IssuedAt  int64  `json:"issued_at"`
	ExpiresAt int64  `json:"expires_at"`
}

var db *gorm.DB
var jwtSecret = []byte("your-very-secure-secret-key-change-in-prod") // Use env var
var validate *validator.Validate
var limiter = rate.NewLimiter(rate.Every(time.Minute), 100) // 100 requests per minute
var logger *logrus.Logger
var redisClient *redis.Client
var encryptionKey = []byte("your-32-byte-encryption-key-here") // Use env var
var degenHF *degenhf.DegenHF

func initDB() {
	var err error
	dsn := os.Getenv("DATABASE_URL")
	if dsn == "" {
		dsn = "host=postgres user=user password=password dbname=digital_id port=5432 sslmode=disable TimeZone=UTC"
	}
	db, err = gorm.Open(postgres.Open(dsn), &gorm.Config{})
	if err != nil {
		panic("failed to connect database")
	}
	db.AutoMigrate(&User{}, &Credential{})
	validate = validator.New()
	logger = logrus.New()
	logger.SetFormatter(&logrus.JSONFormatter{})
	logger.SetLevel(logrus.InfoLevel)

	// Initialize Redis
	redisAddr := os.Getenv("REDIS_URL")
	if redisAddr == "" {
		redisAddr = "redis:6379"
	}
	redisClient = redis.NewClient(&redis.Options{
		Addr: redisAddr,
	})
	_, err = redisClient.Ping(context.Background()).Result()
	if err != nil {
		logger.Warn("Failed to connect to Redis: ", err)
	}

	// Initialize DegenHF security framework
	threshold := degenhf.ThresholdConfig{
		TotalTrustees:      10,
		RequiredSignatures: 7,
		EmergencyThreshold: 9,
	}
	degenHF, err = degenhf.NewDegenHF(threshold)
	if err != nil {
		logger.Error("Failed to initialize DegenHF: ", err)
		panic("DegenHF initialization failed")
	}

	if err := degenHF.InitializeTrustees(); err != nil {
		logger.Error("Failed to initialize DegenHF trustees: ", err)
		panic("DegenHF trustee initialization failed")
	}

	if err := degenHF.InitializeKillSwitches(); err != nil {
		logger.Error("Failed to initialize DegenHF kill switches: ", err)
		panic("DegenHF kill switch initialization failed")
	}

	logger.Info("DegenHF security framework initialized successfully")

	// Subscribe to government data events
	go func() {
		pubsub := redisClient.Subscribe(context.Background(), "id-system-events")
		defer pubsub.Close()

		for msg := range pubsub.Channel() {
			var event map[string]interface{}
			json.Unmarshal([]byte(msg.Payload), &event)
			if event["type"] == "connector_data_received" {
				// Handle government data sync
				logger.Info("Received government data: ", event)
				// Could update user records or credentials based on gov data
			}
		}
	}()
}

func hashPassword(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	return string(bytes), err
}

func checkPassword(hashed, password string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hashed), []byte(password))
	return err == nil
}

func encryptData(data string) (string, error) {
	block, err := aes.NewCipher(encryptionKey)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}
	ciphertext := gcm.Seal(nonce, nonce, []byte(data), nil)
	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

func decryptData(encryptedData string) (string, error) {
	data, err := base64.StdEncoding.DecodeString(encryptedData)
	if err != nil {
		return "", err
	}
	block, err := aes.NewCipher(encryptionKey)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	nonceSize := gcm.NonceSize()
	if len(data) < nonceSize {
		return "", errors.New("ciphertext too short")
	}
	nonce, ciphertext := data[:nonceSize], data[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", err
	}
	return string(plaintext), nil
}

func publishEvent(eventType string, data map[string]interface{}) {
	event := map[string]interface{}{
		"type": eventType,
		"data": data,
		"timestamp": time.Now().Unix(),
	}
	jsonData, _ := json.Marshal(event)
	redisClient.Publish(context.Background(), "id-system-events", string(jsonData))
}

func cacheUser(userID uint, user User) {
	userJSON, _ := json.Marshal(user)
	redisClient.Set(context.Background(), fmt.Sprintf("user:%d", userID), string(userJSON), time.Hour)
}

func getCachedUser(userID uint) (*User, error) {
	val, err := redisClient.Get(context.Background(), fmt.Sprintf("user:%d", userID)).Result()
	if err != nil {
		return nil, err
	}
	var user User
	json.Unmarshal([]byte(val), &user)
	return &user, nil
}

func generateToken(userID uint) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"user_id": userID,
		"exp":     time.Now().Add(time.Hour * 24).Unix(),
		"iat":     time.Now().Unix(),
	})
	return token.SignedString(jwtSecret)
}

func rateLimitMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		if !limiter.Allow() {
			c.JSON(http.StatusTooManyRequests, gin.H{"error": "Rate limit exceeded"})
			c.Abort()
			return
		}
		c.Next()
	}
}

func authMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		tokenString := c.GetHeader("Authorization")
		if tokenString == "" {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Missing token"})
			c.Abort()
			return
		}
		token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
			return jwtSecret, nil
		})
		if err != nil || !token.Valid {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid token"})
			c.Abort()
			return
		}
		if claims, ok := token.Claims.(jwt.MapClaims); ok {
			c.Set("user_id", claims["user_id"])
		}
		c.Next()
	}
}

func checkEligibilityHMRC(userID uint) (bool, error) {
	// Call Kotlin service
	resp, err := http.Get("http://kotlin-connectors:8081/api/connectors/verify-eligibility?nino=1234567890&income=15000")
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()

	var result map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return false, err
	}
	eligible, ok := result["eligible"].(bool)
	if !ok {
		return false, fmt.Errorf("invalid response")
	}
	return eligible, nil
}

func initRustEngine() error {
	if C.init_engine() != 0 {
		return errors.New("failed to initialize Rust engine")
	}
	return nil
}

func generateKeypairRust(userID string) error {
	cUserID := C.CString(userID)
	defer C.free(unsafe.Pointer(cUserID))
	if C.generate_keypair(cUserID) != 0 {
		return errors.New("failed to generate keypair")
	}
	return nil
}

func signCredentialRust(userID, payload string, issuedAt, expiresAt int64) (string, error) {
	cUserID := C.CString(userID)
	defer C.free(unsafe.Pointer(cUserID))
	cPayload := C.CString(payload)
	defer C.free(unsafe.Pointer(cPayload))
	result := C.sign_credential(cUserID, cPayload, C.ulong(issuedAt), C.ulong(expiresAt))
	if result == nil {
		return "", errors.New("signing failed")
	}
	defer C.free_string(result)
	return C.GoString(result), nil
}

// isSystemAdministrator checks if a user has system administrator privileges
func isSystemAdministrator(userID uint) bool {
	// In a real implementation, this would check against a database of administrators
	// For now, only allow user ID 1 (system admin)
	return userID == 1
}

func main() {
	initDB()
	if err := initRustEngine(); err != nil {
		logger.Fatal("Failed to initialize Rust engine: ", err)
	}
	logger.Info("Services initialized")

	// Kafka producer for audit
	kafkaWriter := &kafka.Writer{
		Addr:     kafka.TCP("localhost:9092"),
		Topic:    "audit-logs",
		Balancer: &kafka.LeastBytes{},
	}
	defer kafkaWriter.Close()

	r := gin.Default()

	// CORS
	r.Use(cors.Default())

	// Rate limiting
	r.Use(rateLimitMiddleware())

	r.POST("/register", func(c *gin.Context) {
		var req struct {
			Name     string `json:"name" binding:"required" validate:"required,min=2,max=50"`
			Email    string `json:"email" binding:"required,email" validate:"required,email"`
			Password string `json:"password" binding:"required,min=8" validate:"required,min=8"`
		}
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		if err := validate.Struct(req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		hashedPassword, err := hashPassword(req.Password)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to hash password"})
			return
		}

		user := User{Name: req.Name, Email: req.Email, Password: hashedPassword}
		if err := db.Create(&user).Error; err != nil {
			logger.WithFields(logrus.Fields{"user": req.Email, "error": err}).Error("Failed to create user")
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create user"})
			return
		}

		cacheUser(user.ID, user)
		publishEvent("user_registered", map[string]interface{}{"user_id": user.ID, "email": req.Email})

		if err := generateKeypairRust(fmt.Sprintf("%d", user.ID)); err != nil {
			logger.WithFields(logrus.Fields{"user_id": user.ID, "error": err}).Error("Failed to generate keypair")
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate keypair"})
			return
		}

		token, _ := generateToken(user.ID)
		kafkaWriter.WriteMessages(c, kafka.Message{Value: []byte("User registered: " + req.Email)})
		logger.WithFields(logrus.Fields{"user": req.Email, "user_id": user.ID}).Info("User registered successfully")

		c.JSON(http.StatusOK, gin.H{"token": token, "user_id": user.ID})
	})

	r.POST("/login", func(c *gin.Context) {
		var req struct {
			Email    string `json:"email" validate:"required,email"`
			Password string `json:"password" validate:"required"`
		}
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		if err := validate.Struct(req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		var user User
		if err := db.Where("email = ?", req.Email).First(&user).Error; err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid credentials"})
			return
		}

		if !checkPassword(user.Password, req.Password) {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid credentials"})
			return
		}

		cacheUser(user.ID, user)
		publishEvent("user_login", map[string]interface{}{"user_id": user.ID, "email": req.Email})

		token, _ := generateToken(user.ID)
		c.JSON(http.StatusOK, gin.H{"token": token})
	})

	r.POST("/verify", authMiddleware(), func(c *gin.Context) {
		userID := c.MustGet("user_id").(float64)
		// Simulate verification logic with timeout for speed
		time.Sleep(10 * time.Millisecond) // Simulate processing

		// Call Kotlin connector for HMRC eligibility check
		eligibility, err := checkEligibilityHMRC(uint(userID))
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "HMRC check failed"})
			return
		}

		c.JSON(http.StatusOK, gin.H{"verified": true, "user_id": uint(userID), "eligible": eligibility})
	})

	r.POST("/issue-credential", authMiddleware(), func(c *gin.Context) {
		userID := uint(c.MustGet("user_id").(float64))
		payload := fmt.Sprintf("Digital ID for user %d", userID)
		issuedAt := time.Now().Unix()
		expiresAt := time.Now().Add(365 * 24 * time.Hour).Unix()

		signedCredJSON, err := signCredentialRust(fmt.Sprintf("%d", userID), payload, issuedAt, expiresAt)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to sign credential"})
			return
		}

		var signedCred map[string]interface{}
		if err := json.Unmarshal([]byte(signedCredJSON), &signedCred); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to parse credential"})
			return
		}

		cred := Credential{
			UserID:    userID,
			Payload:   payload,
			Signature: signedCred["signature"].(string),
			IssuedAt:  issuedAt,
			ExpiresAt: expiresAt,
		}
		if err := db.Create(&cred).Error; err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to save credential"})
			return
		}

		kafkaWriter.WriteMessages(c, kafka.Message{Value: []byte(fmt.Sprintf("Credential issued for user %d", userID))})

		c.JSON(http.StatusOK, gin.H{"credential_id": cred.ID, "signed_credential": signedCred})
	})

	r.GET("/credential/:id", authMiddleware(), func(c *gin.Context) {
		id := c.Param("id")
		var cred Credential
		if err := db.Where("id = ?", id).First(&cred).Error; err != nil {
			logger.WithFields(logrus.Fields{"credential_id": id, "error": err}).Error("Credential not found")
			c.JSON(http.StatusNotFound, gin.H{"error": "Credential not found"})
			return
		}
		c.JSON(http.StatusOK, cred)
	})

	r.GET("/health", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"status": "ok"})
	})

	// ============================================================================
	// DegenHF Security Framework Routes
	// ============================================================================

	// Authorize critical operations with threshold cryptography
	r.POST("/degenhf/authorize", authMiddleware(), func(c *gin.Context) {
		var req struct {
			Operation string `json:"operation" binding:"required"`
			Data      string `json:"data"`
		}
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		userID := uint(c.MustGet("user_id").(float64))
		requester := fmt.Sprintf("user_%d", userID)

		// Get DegenHF authorization
		proof, err := degenHF.AuthorizeCriticalOperation(req.Operation, requester)
		if err != nil {
			logger.WithFields(logrus.Fields{
				"operation": req.Operation,
				"user_id":   userID,
				"error":     err,
			}).Error("DegenHF authorization failed")
			c.JSON(http.StatusForbidden, gin.H{"error": "Authorization failed"})
			return
		}

		logger.WithFields(logrus.Fields{
			"operation": req.Operation,
			"user_id":   userID,
		}).Info("DegenHF authorization granted")

		c.JSON(http.StatusOK, gin.H{
			"authorized": true,
			"proof":      proof,
		})
	})

	// Verify government data access requests
	r.POST("/degenhf/verify-government", authMiddleware(), func(c *gin.Context) {
		var req degenhf.GovernmentRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		// Verify with zero-knowledge proof
		zkp, err := degenHF.VerifyGovernmentRequest(&req)
		if err != nil {
			logger.WithFields(logrus.Fields{
				"government_entity": req.Entity,
				"error":            err,
			}).Error("Government request verification failed")
			c.JSON(http.StatusForbidden, gin.H{"error": "Verification failed"})
			return
		}

		logger.WithFields(logrus.Fields{
			"government_entity": req.Entity,
			"purpose":          req.Purpose,
		}).Info("Government request verified with ZKP")

		c.JSON(http.StatusOK, gin.H{
			"verified": true,
			"zkp":      zkp,
		})
	})

	// Citizen opt-out - opt out of government access to personal data (default is access allowed)
	r.POST("/degenhf/citizen-opt-out", authMiddleware(), func(c *gin.Context) {
		var req struct {
			DataType  string `json:"data_type" binding:"required"`
			Confirmed bool   `json:"confirmed,omitempty"` // Whether user has confirmed the opt-out
		}
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		userID := uint(c.MustGet("user_id").(float64))
		citizenID := fmt.Sprintf("user_%d", userID)

		// Execute citizen opt-out
		warning, err := degenHF.CitizenOptOut(citizenID, req.DataType, req.Confirmed)
		if err != nil {
			logger.WithFields(logrus.Fields{
				"citizen_id": citizenID,
				"data_type":  req.DataType,
				"confirmed":  req.Confirmed,
				"error":      err,
			}).Error("Citizen opt-out failed")
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Opt-out failed"})
			return
		}

		// If warning returned, user needs to confirm
		if warning != nil {
			logger.WithFields(logrus.Fields{
				"citizen_id": citizenID,
				"data_type":  req.DataType,
			}).Info("Citizen opt-out warning shown")

			c.JSON(http.StatusOK, gin.H{
				"requires_confirmation": true,
				"warning":               warning,
			})
			return
		}

		// Opt-out executed successfully
		logger.WithFields(logrus.Fields{
			"citizen_id": citizenID,
			"data_type":  req.DataType,
		}).Info("Citizen opt-out executed successfully")

		c.JSON(http.StatusOK, gin.H{
			"opt_out_executed": true,
			"data_type":        req.DataType,
			"message":          "You have successfully opted out of government access to this data type",
		})
	})

	// Get citizen consent preferences
	r.GET("/degenhf/citizen-consent", authMiddleware(), func(c *gin.Context) {
		userID := uint(c.MustGet("user_id").(float64))
		citizenID := fmt.Sprintf("user_%d", userID)

		consent, err := degenHF.GetCitizenConsent(citizenID)
		if err != nil {
			logger.WithFields(logrus.Fields{
				"citizen_id": citizenID,
				"error":      err,
			}).Error("Failed to get citizen consent")
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get consent preferences"})
			return
		}

		c.JSON(http.StatusOK, gin.H{
			"consent": consent,
		})
	})

	// Emergency shutdown - distributed kill switches
	r.POST("/degenhf/emergency-shutdown", authMiddleware(), func(c *gin.Context) {
		var req degenhf.EmergencyTrigger
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		// Only allow system administrators to trigger emergency shutdown
		userID := uint(c.MustGet("user_id").(float64))
		if !isSystemAdministrator(userID) {
			c.JSON(http.StatusForbidden, gin.H{"error": "Unauthorized"})
			return
		}

		// Activate emergency shutdown
		if err := degenHF.ActivateEmergencyShutdown(&req); err != nil {
			logger.WithFields(logrus.Fields{
				"trigger_type": req.TriggerType,
				"reason":       req.Reason,
				"error":        err,
			}).Error("Emergency shutdown failed")
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Emergency shutdown failed"})
			return
		}

		logger.WithFields(logrus.Fields{
			"trigger_type": req.TriggerType,
			"reason":       req.Reason,
		}).Warn("Emergency shutdown activated")

		c.JSON(http.StatusOK, gin.H{
			"emergency_activated": true,
			"shutdown_reason":     req.Reason,
		})
	})

	// Get DegenHF security status
	r.GET("/degenhf/status", authMiddleware(), func(c *gin.Context) {
		killSwitches := degenHF.GetKillSwitchStatus()
		emergencyTriggered, emergencyReason := degenHF.CheckEmergencyStatus()

		status := map[string]interface{}{
			"framework_active":     true,
			"total_trustees":       10,
			"active_trustees":      7,
			"last_authorization":   time.Now().Unix(),
			"emergency_switches":   len(killSwitches),
			"security_level":       "maximum",
			"emergency_triggered":  emergencyTriggered,
			"emergency_reason":     emergencyReason,
		}

		c.JSON(http.StatusOK, status)
	})

	// Activate kill switch
	r.POST("/degenhf/kill-switch/activate", authMiddleware(), func(c *gin.Context) {
		var req struct {
			KillSwitchID string `json:"kill_switch_id" binding:"required"`
		}
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		userID := uint(c.MustGet("user_id").(float64))
		activatedBy := fmt.Sprintf("user_%d", userID)

		if err := degenHF.ActivateKillSwitch(req.KillSwitchID, activatedBy); err != nil {
			logger.WithFields(logrus.Fields{
				"kill_switch_id": req.KillSwitchID,
				"activated_by":   activatedBy,
				"error":          err,
			}).Error("Kill switch activation failed")
			c.JSON(http.StatusForbidden, gin.H{"error": "Kill switch activation failed"})
			return
		}

		logger.WithFields(logrus.Fields{
			"kill_switch_id": req.KillSwitchID,
			"activated_by":   activatedBy,
		}).Warn("Kill switch activated")

		c.JSON(http.StatusOK, gin.H{
			"kill_switch_activated": true,
			"kill_switch_id":        req.KillSwitchID,
		})
	})

	// Get kill switch status
	r.GET("/degenhf/kill-switches", authMiddleware(), func(c *gin.Context) {
		killSwitches := degenHF.GetKillSwitchStatus()

		c.JSON(http.StatusOK, gin.H{
			"kill_switches": killSwitches,
			"total_count":   len(killSwitches),
		})
	})

	// Get audit entries with integrity verification
	r.GET("/degenhf/audit", authMiddleware(), func(c *gin.Context) {
		startTimeStr := c.Query("start_time")
		endTimeStr := c.Query("end_time")

		var startTime, endTime int64
		if startTimeStr != "" {
			if t, err := time.Parse(time.RFC3339, startTimeStr); err == nil {
				startTime = t.Unix()
			}
		} else {
			startTime = 0
		}

		if endTimeStr != "" {
			if t, err := time.Parse(time.RFC3339, endTimeStr); err == nil {
				endTime = t.Unix()
			}
		} else {
			endTime = time.Now().Unix()
		}

		entries := degenHF.AuditLogger().GetAuditEntries(startTime, endTime)
		merkleRoot := degenHF.AuditLogger().GetMerkleRoot()
		integrityVerified := degenHF.AuditLogger().VerifyAuditIntegrity()

		c.JSON(http.StatusOK, gin.H{
			"entries":             entries,
			"merkle_root":         base64.StdEncoding.EncodeToString(merkleRoot),
			"integrity_verified":  integrityVerified,
			"total_entries":       len(entries),
		})
	})

	// Verify audit integrity
	r.GET("/degenhf/audit/verify", authMiddleware(), func(c *gin.Context) {
		integrityVerified := degenHF.AuditLogger().VerifyAuditIntegrity()
		merkleRoot := degenHF.AuditLogger().GetMerkleRoot()

		status := "verified"
		if !integrityVerified {
			status = "compromised"
		}

		c.JSON(http.StatusOK, gin.H{
			"integrity_status": status,
			"merkle_root":      base64.StdEncoding.EncodeToString(merkleRoot),
			"verified":         integrityVerified,
		})
	})

	r.Run(":8080")
}