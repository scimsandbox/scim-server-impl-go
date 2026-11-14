package scim

import (
	"slices"

	"golang.org/x/crypto/bcrypt"
)

// MaxBcryptPasswordBytes is the maximum plaintext password length supported by bcrypt.
const MaxBcryptPasswordBytes = 72

const passwordAttrName = "password"

func isASCIIPasswordAttr(k string) bool {
	if len(k) != len(passwordAttrName) {
		return false
	}
	for i := 0; i < len(passwordAttrName); i++ {
		c := k[i]
		if c >= 'A' && c <= 'Z' {
			c += 'a' - 'A'
		}
		if c != passwordAttrName[i] {
			return false
		}
	}
	return true
}

func validatePassword(val string) error {
	if val == "" {
		return NewScimError(400, "invalidValue", "password cannot be empty")
	}
	if len(val) > MaxBcryptPasswordBytes {
		return NewScimError(400, "invalidValue", "password cannot be more than 72 bytes")
	}
	return nil
}

func parsePasswordValue(v any) (*string, error) {
	rawPw, err := parseRawStringPtr(v, passwordAttrName)
	if err != nil {
		return nil, err
	}
	if rawPw != nil {
		if err := validatePassword(*rawPw); err != nil {
			return nil, err
		}
	}
	return rawPw, nil
}

// extractAndValidatePassword validates every top-level ASCII case-insensitive "password"
// entry in input (RFC 7643 §2.1 ASCII attribute names, rejecting URN-qualified keys and
// non-ASCII Unicode fold equivalents such as U+017F) and deterministically selects the
// winning value: exact "password" first, otherwise the lexically smallest matching key.
func extractAndValidatePassword(input map[string]any) (*string, bool, error) {
	var keyBuf [2]string
	keys := keyBuf[:0]
	for k := range input {
		if isASCIIPasswordAttr(k) {
			keys = append(keys, k)
		}
	}
	if len(keys) == 0 {
		return nil, false, nil
	}
	if len(keys) > 1 {
		slices.Sort(keys)
	}

	var chosenKey string
	var chosenPw *string
	for _, k := range keys {
		parsed, err := parsePasswordValue(input[k])
		if err != nil {
			return nil, false, err
		}
		if chosenKey == "" || k == passwordAttrName {
			chosenKey = k
			chosenPw = parsed
		}
	}
	return chosenPw, true, nil
}

// HashPassword hashes a raw plaintext password using bcrypt if non-nil.
// Empty strings, passwords exceeding 72 UTF-8 bytes, or bcrypt failures return
// HTTP 400 invalidValue so invalid or plaintext credentials are never stored.
func HashPassword(raw *string) (*string, error) {
	if raw == nil {
		return nil, nil
	}
	if err := validatePassword(*raw); err != nil {
		return nil, err
	}
	hashed, err := bcrypt.GenerateFromPassword([]byte(*raw), bcrypt.DefaultCost)
	if err != nil {
		return nil, NewScimError(400, "invalidValue", "Failed to hash password")
	}
	h := string(hashed)
	return &h, nil
}

// ValidatePasswordInput validates all top-level ASCII case-insensitive password attributes
// present in a SCIM User payload without mutating the payload, rejecting non-string, empty,
// or >72-byte UTF-8 values with 400 invalidValue.
func ValidatePasswordInput(input map[string]any) error {
	_, _, err := extractAndValidatePassword(input)
	return err
}
