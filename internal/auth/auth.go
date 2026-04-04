package auth

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"
)

// ValidatePassword checks if password meets minimum requirements
func ValidatePassword(password string) error {
	if len(password) < 8 {
		return fmt.Errorf("password must be at least 8 characters")
	}
	var hasUpper, hasLower, hasDigit bool
	for _, c := range password {
		switch {
		case 'A' <= c && c <= 'Z':
			hasUpper = true
		case 'a' <= c && c <= 'z':
			hasLower = true
		case '0' <= c && c <= '9':
			hasDigit = true
		}
	}
	if !hasUpper || !hasLower || !hasDigit {
		return fmt.Errorf("password must contain uppercase, lowercase, and a digit")
	}
	return nil
}

func HashPassword(password string) (string, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	return string(hash), err
}

func CheckPassword(hash, password string) bool {
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(password)) == nil
}

// TOTP implementation

func GenerateTOTPSecret() (string, error) {
	secret := make([]byte, 20)
	if _, err := rand.Read(secret); err != nil {
		return "", err
	}
	return base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(secret), nil
}

func GenerateTOTPCode(secret string, t time.Time) (string, error) {
	key, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(strings.ToUpper(secret))
	if err != nil {
		return "", err
	}

	counter := uint64(t.Unix()) / 30
	buf := make([]byte, 8)
	binary.BigEndian.PutUint64(buf, counter)

	mac := hmac.New(sha1.New, key)
	mac.Write(buf)
	hash := mac.Sum(nil)

	offset := hash[len(hash)-1] & 0x0f
	code := binary.BigEndian.Uint32(hash[offset:offset+4]) & 0x7fffffff
	code = code % 1000000

	return fmt.Sprintf("%06d", code), nil
}

func VerifyTOTP(secret, code string) bool {
	now := time.Now()
	// Check current, previous, and next time step (±30s window)
	for _, offset := range []time.Duration{0, -30 * time.Second, 30 * time.Second} {
		expected, err := GenerateTOTPCode(secret, now.Add(offset))
		if err != nil {
			continue
		}
		if expected == code {
			return true
		}
	}
	return false
}

// GenerateEmailCode creates a random 6-digit code for email MFA
func GenerateEmailCode() string {
	b := make([]byte, 4)
	rand.Read(b)
	code := int(binary.BigEndian.Uint32(b)) % 1000000
	return fmt.Sprintf("%06d", code)
}

// GenerateRecoveryCodes creates 8 one-time recovery codes
func GenerateRecoveryCodes() []string {
	codes := make([]string, 8)
	for i := range codes {
		b := make([]byte, 4)
		rand.Read(b)
		codes[i] = fmt.Sprintf("%04x-%04x", binary.BigEndian.Uint16(b[:2]), binary.BigEndian.Uint16(b[2:]))
	}
	return codes
}

// GenerateResetToken creates a URL-safe random token for password reset
func GenerateResetToken() string {
	b := make([]byte, 32)
	rand.Read(b)
	return base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(b)
}

func TOTPProvisioningURI(secret, username, issuer string) string {
	return fmt.Sprintf("otpauth://totp/%s:%s?secret=%s&issuer=%s&algorithm=SHA1&digits=6&period=30",
		issuer, username, secret, issuer)
}
