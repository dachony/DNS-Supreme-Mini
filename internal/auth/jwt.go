package auth

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
)

var jwtSecret []byte

// InitSecret loads or generates the JWT secret, persisting it in the database.
func InitSecret(getSetting func(string) string, setSetting func(string, string) error) {
	if s := getSetting("jwt_secret"); s != "" {
		jwtSecret, _ = hex.DecodeString(s)
		return
	}
	jwtSecret = make([]byte, 32)
	rand.Read(jwtSecret)
	setSetting("jwt_secret", hex.EncodeToString(jwtSecret))
}

func getSecret() []byte {
	if jwtSecret == nil {
		// Fallback: generate ephemeral secret if InitSecret was not called.
		jwtSecret = make([]byte, 32)
		rand.Read(jwtSecret)
	}
	return jwtSecret
}

type TokenClaims struct {
	UserID   int
	Username string
	Role     string
	MFADone  bool
	Exp      time.Time
}

func GenerateToken(userID int, username, role string, mfaDone bool) (string, error) {
	exp := time.Now().Add(24 * time.Hour)
	payload := fmt.Sprintf("%d|%s|%s|%v|%d", userID, username, role, mfaDone, exp.Unix())

	mac := hmac.New(sha256.New, getSecret())
	mac.Write([]byte(payload))
	sig := hex.EncodeToString(mac.Sum(nil))

	token := hex.EncodeToString([]byte(payload)) + "." + sig
	return token, nil
}

func ValidateToken(token string) (*TokenClaims, error) {
	parts := strings.SplitN(token, ".", 2)
	if len(parts) != 2 {
		return nil, errors.New("invalid token")
	}

	payloadBytes, err := hex.DecodeString(parts[0])
	if err != nil {
		return nil, errors.New("invalid token encoding")
	}
	payload := string(payloadBytes)

	mac := hmac.New(sha256.New, getSecret())
	mac.Write([]byte(payload))
	expectedSig := hex.EncodeToString(mac.Sum(nil))

	if !hmac.Equal([]byte(parts[1]), []byte(expectedSig)) {
		return nil, errors.New("invalid signature")
	}

	fields := strings.SplitN(payload, "|", 5)
	if len(fields) != 5 {
		return nil, errors.New("invalid payload")
	}

	userID, _ := strconv.Atoi(fields[0])
	expUnix, _ := strconv.ParseInt(fields[4], 10, 64)
	exp := time.Unix(expUnix, 0)

	if time.Now().After(exp) {
		return nil, errors.New("token expired")
	}

	return &TokenClaims{
		UserID:   userID,
		Username: fields[1],
		Role:     fields[2],
		MFADone:  fields[3] == "true",
		Exp:      exp,
	}, nil
}

// ValidateTokenPartial validates a token without requiring MFA to be done
func ValidateTokenPartial(token string) (*TokenClaims, error) {
	return ValidateToken(token)
}

func AuthMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		header := c.GetHeader("Authorization")
		if header == "" {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "authorization required"})
			c.Abort()
			return
		}

		token := strings.TrimPrefix(header, "Bearer ")
		claims, err := ValidateToken(token)
		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
			c.Abort()
			return
		}

		if !claims.MFADone {
			c.JSON(http.StatusForbidden, gin.H{"error": "mfa verification required"})
			c.Abort()
			return
		}

		c.Set("userID", claims.UserID)
		c.Set("username", claims.Username)
		c.Set("role", claims.Role)
		c.Next()
	}
}

func AdminOnly() gin.HandlerFunc {
	return func(c *gin.Context) {
		role, _ := c.Get("role")
		if role != "admin" {
			c.JSON(http.StatusForbidden, gin.H{"error": "admin access required"})
			c.Abort()
			return
		}
		c.Next()
	}
}
