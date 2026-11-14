package scim

import (
	"strings"
	"testing"

	"golang.org/x/crypto/bcrypt"

	"github.com/scimsandbox/scim-server-impl-go/internal/model"
)

func TestPassword_RejectsOver72UTF8BytesWith400InvalidValue(t *testing.T) {
	t.Parallel()

	// Exactly 72 bytes succeeds.
	exact72 := strings.Repeat("a", 72)
	hashed72, err := HashPassword(&exact72)
	if err != nil || hashed72 == nil {
		t.Fatalf("expected 72-byte password to succeed, got err=%v", err)
	}

	overCases := []struct {
		name string
		pw   string
	}{
		{"73 ASCII bytes", strings.Repeat("a", 73)},
		{"25 3-byte UTF-8 runes (75 bytes, 25 chars)", strings.Repeat("€", 25)},
	}

	for _, tc := range overCases {
		t.Run("HashPassword/"+tc.name, func(t *testing.T) {
			pw := tc.pw
			_, err := HashPassword(&pw)
			scimErr, ok := err.(*ScimError)
			if !ok || scimErr.Status != 400 || scimErr.ScimType != "invalidValue" {
				t.Fatalf("HashPassword(%s) = %T %v, want 400 invalidValue", tc.name, err, err)
			}
		})

		t.Run("ApplyFromScimInput/"+tc.name, func(t *testing.T) {
			for _, key := range []string{"password", "Password", "PASSWORD"} {
				u := &model.ScimUser{}
				err := ApplyFromScimInput(u, map[string]any{
					"userName": "alice",
					key:        tc.pw,
				})
				scimErr, ok := err.(*ScimError)
				if !ok || scimErr.Status != 400 || scimErr.ScimType != "invalidValue" {
					t.Fatalf("ApplyFromScimInput(%s, key=%s) = %T %v, want 400 invalidValue", tc.name, key, err, err)
				}
			}
		})
	}

	t.Run("PATCH replace password >72 bytes sharing same 72-byte prefix still returns 400 invalidValue", func(t *testing.T) {
		existingHash := *hashed72
		u := &model.ScimUser{
			UserName: "alice",
			Password: &existingHash,
		}
		// Same first 72 bytes as existing password + extra suffix -> must NOT silently match CompareHashAndPassword!
		overWithSamePrefix := exact72 + "extra-suffix"
		for _, path := range []string{"password", UserSchemaURN + ":password"} {
			err := ApplyPatchOperations(u, []map[string]any{
				{
					"op":    "replace",
					"path":  path,
					"value": overWithSamePrefix,
				},
			})
			scimErr, ok := err.(*ScimError)
			if !ok || scimErr.Status != 400 || scimErr.ScimType != "invalidValue" {
				t.Fatalf("ApplyPatchOperations(path=%s, same 72B prefix + suffix) = %T %v, want 400 invalidValue", path, err, err)
			}
		}
	})

	t.Run("ValidatePasswordInput, deterministic case-insensitive lookup, and no URN keys on create/replace", func(t *testing.T) {
		if err := ValidatePasswordInput(map[string]any{"userName": "alice"}); err != nil {
			t.Fatalf("missing password should succeed, got %v", err)
		}
		if err := ValidatePasswordInput(map[string]any{"userName": "alice", "password": nil}); err != nil {
			t.Fatalf("nil password should succeed, got %v", err)
		}
		if err := ValidatePasswordInput(map[string]any{"userName": "alice", "password": "ValidPassword!1"}); err != nil {
			t.Fatalf("valid password should succeed, got %v", err)
		}
		if err := ValidatePasswordInput(map[string]any{"userName": "alice", "password": 12345}); err == nil {
			t.Fatal("non-string password should fail")
		}
		if err := ValidatePasswordInput(map[string]any{"userName": "alice", "Password": strings.Repeat("z", 73)}); err == nil {
			t.Fatal("case-insensitive >72B password should fail")
		}
		if err := ValidatePasswordInput(map[string]any{"userName": "alice", "password": ""}); err == nil {
			t.Fatal("empty string password should fail")
		}
		empty := ""
		if _, err := HashPassword(&empty); err == nil {
			t.Fatal("HashPassword(\"\") should fail with 400 invalidValue")
		}
		for _, op := range []map[string]any{
			{"op": "add", "path": "password", "value": ""},
			{"op": "replace", "path": "password", "value": ""},
			{"op": "replace", "path": UserSchemaURN + ":password", "value": ""},
			{"op": "replace", "value": map[string]any{"password": ""}},
		} {
			uEmpty := &model.ScimUser{UserName: "alice"}
			err := ApplyPatchOperations(uEmpty, []map[string]any{op})
			scimErr, ok := err.(*ScimError)
			if !ok || scimErr.Status != 400 || scimErr.ScimType != "invalidValue" {
				t.Fatalf("ApplyPatchOperations(%v) = %T %v, want 400 invalidValue", op, err, err)
			}
		}
		// $2a$-prefixed input is hashed as cleartext rather than stored raw
		rawPrefix := "$2a$hello"
		hashedPrefix, err := HashPassword(&rawPrefix)
		if err != nil || hashedPrefix == nil || *hashedPrefix == rawPrefix {
			t.Fatalf("expected $2a$hello to be bcrypt-hashed, got %v, err=%v", hashedPrefix, err)
		}
		if err := bcrypt.CompareHashAndPassword([]byte(*hashedPrefix), []byte(rawPrefix)); err != nil {
			t.Fatalf("bcrypt verification failed for $2a$hello: %v", err)
		}

		// URN-qualified keys on create/replace are NOT treated as top-level core attributes,
		// while PATCH URN paths continue to work via stripPatchURNPrefix.
		uIgnored := &model.ScimUser{}
		if err := ApplyFromScimInput(uIgnored, map[string]any{
			"userName":                  "alice",
			UserSchemaURN + ":password": "IgnoredOnCreate!1",
			UserSchemaURN: map[string]any{
				"password": "AlsoIgnoredOnCreate!1",
			},
		}); err != nil {
			t.Fatalf("unexpected error ignoring URN keys on create/replace: %v", err)
		}
		if uIgnored.Password != nil {
			t.Fatalf("expected URN keys on create/replace to be ignored, got Password=%v", *uIgnored.Password)
		}

		uPatched := &model.ScimUser{UserName: "alice"}
		if err := ApplyPatchOperations(uPatched, []map[string]any{
			{"op": "replace", "path": UserSchemaURN + ":password", "value": "PatchedViaURN!1"},
		}); err != nil || uPatched.Password == nil {
			t.Fatalf("expected PATCH URN path to set password, err=%v", err)
		}
		if err := bcrypt.CompareHashAndPassword([]byte(*uPatched.Password), []byte("PatchedViaURN!1")); err != nil {
			t.Fatalf("PATCH URN password hash mismatch: %v", err)
		}

		// Non-ASCII Unicode case-fold equivalent ("pa\u017fsword", Latin Small Letter Long S)
		// MUST NOT be treated as the ASCII SCIM "password" attribute (RFC 7643 §2.1).
		if isASCIIPasswordAttr("pa\u017fsword") || isASCIIPasswordAttr("passworx") {
			t.Fatal("expected non-ASCII 'pa\\u017fsword' and 'passworx' not to match ASCII password attribute")
		}
		uLongS := &model.ScimUser{}
		if err := ApplyFromScimInput(uLongS, map[string]any{
			"userName":       "alice",
			"pa\u017fsword": "ShouldNotBeHashedAsPassword!1",
		}); err != nil {
			t.Fatalf("unexpected error for unknown non-ASCII attribute 'pa\\u017fsword': %v", err)
		}
		if uLongS.Password != nil {
			t.Fatalf("expected 'pa\\u017fsword' NOT to populate user.Password, got %v", *uLongS.Password)
		}

		// Mixed valid + invalid ASCII case variants MUST fail validation (400 invalidValue)
		// rather than silently ignoring the invalid sibling key.
		for _, mixed := range []map[string]any{
			{"userName": "alice", "password": "ValidPassword!1", "Password": 123},
			{"userName": "alice", "Password": "ValidPassword!1", "password": 123},
			{"userName": "alice", "password": "ValidPassword!1", "Password": ""},
			{"userName": "alice", "password": "ValidPassword!1", "PASSWORD": strings.Repeat("b", 73)},
		} {
			if err := ValidatePasswordInput(mixed); err == nil {
				t.Fatalf("ValidatePasswordInput(%v) = nil, want 400 invalidValue", mixed)
			} else if scimErr, ok := err.(*ScimError); !ok || scimErr.Status != 400 || scimErr.ScimType != "invalidValue" {
				t.Fatalf("ValidatePasswordInput(%v) = %T %v, want 400 invalidValue", mixed, err, err)
			}

			uMixed := &model.ScimUser{}
			if err := ApplyFromScimInput(uMixed, mixed); err == nil {
				t.Fatalf("ApplyFromScimInput(%v) = nil, want 400 invalidValue", mixed)
			} else if scimErr, ok := err.(*ScimError); !ok || scimErr.Status != 400 || scimErr.ScimType != "invalidValue" {
				t.Fatalf("ApplyFromScimInput(%v) = %T %v, want 400 invalidValue", mixed, err, err)
			}
		}

		// Determinism check across 100 fresh maps with multiple valid ASCII case variants:
		// 1) Exact "password" always wins when present.
		for i := 0; i < 100; i++ {
			m := map[string]any{
				"userName": "alice",
				"PASSWORD": "UpperCaseWinner",
				"Password": "MixedCaseLoser",
				"password": "ExactLowerWinner",
			}
			got, ok, err := extractAndValidatePassword(m)
			if err != nil || !ok || got == nil || *got != "ExactLowerWinner" {
				t.Fatalf("iter %d: extractAndValidatePassword with exact key = (%v, %v, %v), want ExactLowerWinner", i, got, ok, err)
			}
		}
		// 2) Without exact "password", lexically smallest key ("PASSWORD" < "Password" < "pAssword") always wins.
		for i := 0; i < 100; i++ {
			m := map[string]any{
				"userName": "alice",
				"pAssword": "ThirdLexical",
				"Password": "SecondLexical",
				"PASSWORD": "FirstLexical",
			}
			got, ok, err := extractAndValidatePassword(m)
			if err != nil || !ok || got == nil || *got != "FirstLexical" {
				t.Fatalf("iter %d: extractAndValidatePassword without exact key = (%v, %v, %v), want FirstLexical", i, got, ok, err)
			}
		}
	})
}
