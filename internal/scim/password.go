package scim

import (
	"strings"

	"golang.org/x/crypto/bcrypt"
)

// HashPassword hashes a raw plaintext password using bcrypt if non-empty and
// not already a bcrypt hash (i.e. does not start with $2a$, $2b$, or $2y$).
// If the password exceeds 72 bytes, or if bcrypt hashing fails, an error is returned
// with HTTP 400 invalidValue so plaintext credentials are never stored.
func HashPassword(raw *string) (*string, error) {
	if raw == nil || *raw == "" {
		return raw, nil
	}
	val := *raw
	if strings.HasPrefix(val, "$2a$") || strings.HasPrefix(val, "$2b$") || strings.HasPrefix(val, "$2y$") {
		return raw, nil
	}
	if len([]byte(val)) > 72 {
		return nil, NewScimError(400, "invalidValue", "password cannot be more than 72 bytes")
	}
	hashed, err := bcrypt.GenerateFromPassword([]byte(val), bcrypt.DefaultCost)
	if err != nil {
		return nil, NewScimError(400, "invalidValue", "Failed to hash password: "+err.Error())
	}
	h := string(hashed)
	return &h, nil
}
