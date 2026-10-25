package scim

import (
	"strings"

	"golang.org/x/crypto/bcrypt"
)

// HashPassword hashes a raw plaintext password using bcrypt if non-empty and
// not already a bcrypt hash (i.e. does not start with $2a$ or $2b$).
func HashPassword(raw *string) *string {
	if raw == nil || *raw == "" {
		return raw
	}
	val := *raw
	if strings.HasPrefix(val, "$2a$") || strings.HasPrefix(val, "$2b$") {
		return raw
	}
	hashed, err := bcrypt.GenerateFromPassword([]byte(val), bcrypt.DefaultCost)
	if err != nil {
		return raw
	}
	h := string(hashed)
	return &h
}
