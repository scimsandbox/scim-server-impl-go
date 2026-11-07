package scim

import (
	"golang.org/x/crypto/bcrypt"
)

// MaxBcryptPasswordBytes is the maximum plaintext password length supported by bcrypt.
const MaxBcryptPasswordBytes = 72

// HashPassword hashes a raw plaintext password using bcrypt if non-empty.
// If the password exceeds 72 bytes, or if bcrypt hashing fails, an error is returned
// with HTTP 400 invalidValue so plaintext credentials are never stored.
func HashPassword(raw *string) (*string, error) {
	if raw == nil || *raw == "" {
		return raw, nil
	}
	val := *raw
	if len([]byte(val)) > MaxBcryptPasswordBytes {
		return nil, NewScimError(400, "invalidValue", "password cannot be more than 72 bytes")
	}
	hashed, err := bcrypt.GenerateFromPassword([]byte(val), bcrypt.DefaultCost)
	if err != nil {
		return nil, NewScimError(400, "invalidValue", "Failed to hash password: "+err.Error())
	}
	h := string(hashed)
	return &h, nil
}
