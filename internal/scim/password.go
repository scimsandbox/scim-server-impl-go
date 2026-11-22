package scim

import (
	"slices"
	"strings"

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
	if strings.TrimSpace(val) == "" {
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

// extractAndValidatePasswordOpts validates every password-bearing entry in input
// (top-level exact/case-variant "password", flat core-User-URN-prefixed ":password",
// and nested core-User-URN object "password" entries, using ASCII-only case folding)
// and deterministically selects the winning value:
// exact "password" > unprefixed case variant > core-URN-prefixed > nested core-URN object,
// tie-broken lexicographically.
func extractAndValidatePasswordOpts(input map[string]any, rejectNil bool) (*string, bool, error) {
	if len(input) == 0 {
		return nil, false, nil
	}

	outerKeys := make([]string, 0, len(input))
	for k := range input {
		outerKeys = append(outerKeys, k)
	}
	slices.Sort(outerKeys)

	var candidates []normCandidate
	for _, outerKey := range outerKeys {
		val := input[outerKey]
		if isASCIIPasswordAttr(outerKey) {
			tier := 2
			if outerKey == passwordAttrName {
				tier = 3
			}
			candidates = append(candidates, normCandidate{
				groupKey:  passwordAttrName,
				targetKey: passwordAttrName,
				tier:      tier,
				outerKey:  outerKey,
				val:       val,
			})
			continue
		}
		if suffix, ok := StripCoreUserURNPrefix(outerKey); ok && isASCIIPasswordAttr(suffix) {
			candidates = append(candidates, normCandidate{
				groupKey:  passwordAttrName,
				targetKey: passwordAttrName,
				tier:      1,
				outerKey:  outerKey,
				val:       val,
			})
			continue
		}
		if asciiEqualFold(outerKey, UserSchemaURN) {
			if subMap, ok := val.(map[string]any); ok {
				innerKeys := make([]string, 0, len(subMap))
				for ik := range subMap {
					if isASCIIPasswordAttr(ik) {
						innerKeys = append(innerKeys, ik)
					}
				}
				slices.Sort(innerKeys)
				for _, innerKey := range innerKeys {
					subTier := 0
					if innerKey == passwordAttrName {
						subTier = 1
					}
					candidates = append(candidates, normCandidate{
						groupKey:  passwordAttrName,
						targetKey: passwordAttrName,
						tier:      0,
						subTier:   subTier,
						outerKey:  outerKey,
						innerKey:  innerKey,
						val:       subMap[innerKey],
					})
				}
			}
		}
	}

	if len(candidates) == 0 {
		return nil, false, nil
	}

	var winner normCandidate
	var winnerPw *string
	hasWinner := false
	for _, cand := range candidates {
		if rejectNil && cand.val == nil {
			return nil, false, NewInvalidValue("password cannot be empty")
		}
		parsed, err := parsePasswordValue(cand.val)
		if err != nil {
			return nil, false, err
		}
		if !hasWinner || candBetter(cand, winner) {
			winner = cand
			winnerPw = parsed
			hasWinner = true
		}
	}
	return winnerPw, true, nil
}

func extractAndValidatePassword(input map[string]any) (*string, bool, error) {
	return extractAndValidatePasswordOpts(input, false)
}

func validatePatchValueMapPasswords(input map[string]any) error {
	_, _, err := extractAndValidatePasswordOpts(input, true)
	return err
}

// HashPassword hashes a raw plaintext password using bcrypt if non-nil.
// Empty/whitespace strings, passwords exceeding 72 UTF-8 bytes, or bcrypt failures return
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

// ValidatePasswordInput validates all password-bearing attributes present in a SCIM User
// payload (plain ASCII case variants, flat core-User-URN-prefixed keys, and nested core-User-URN
// object entries) without mutating the payload, rejecting non-string, empty/whitespace,
// or >72-byte UTF-8 values with 400 invalidValue.
func ValidatePasswordInput(input map[string]any) error {
	_, _, err := extractAndValidatePassword(input)
	return err
}
