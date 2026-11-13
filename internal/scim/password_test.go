package scim

import (
	"strings"
	"testing"

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
			for _, key := range []string{"password", "Password", UserSchemaURN + ":password"} {
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
		err := ApplyPatchOperations(u, []map[string]any{
			{
				"op":    "replace",
				"path":  "password",
				"value": overWithSamePrefix,
			},
		})
		scimErr, ok := err.(*ScimError)
		if !ok || scimErr.Status != 400 || scimErr.ScimType != "invalidValue" {
			t.Fatalf("ApplyPatchOperations(same 72B prefix + suffix) = %T %v, want 400 invalidValue", err, err)
		}
	})
}
