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
}

func hashPassword(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	return string(bytes), err
}

func checkPassword(hashed, password string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hashed), []byte(password))
	return err == nil
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

	r.Run(":8080")
}