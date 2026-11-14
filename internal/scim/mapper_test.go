package scim

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"

	"github.com/scimsandbox/scim-server-impl-go/internal/model"
)

func TestClearMutableAttributes(t *testing.T) {
	u := &model.ScimUser{
		ID:           uuid.New(),
		UserName:     "testUser",
		Active:       false,
		CreatedAt:    time.Now(),
		LastModified: time.Now(),
	}
	ext := "ext"
	u.ExternalID = &ext
	u.DisplayName = &ext
	u.NickName = &ext
	u.Title = &ext
	u.Emails = append(u.Emails, model.ScimUserEmail{Value: "test"})
	u.EnterpriseDivision = &ext

	ClearMutableAttributes(u)

	if u.ExternalID != nil {
		t.Fatalf("ExternalID not cleared")
	}
	if u.DisplayName != nil {
		t.Fatalf("DisplayName not cleared")
	}
	if !u.Active {
		t.Fatalf("Active should default to true after clear")
	}
	if u.Emails != nil {
		t.Fatalf("Emails not cleared")
	}
	if u.EnterpriseDivision != nil {
		t.Fatalf("EnterpriseDivision not cleared")
	}
	// UserName should be untouched
	if u.UserName != "testUser" {
		t.Fatalf("UserName should not be cleared")
	}
}

func TestUserToScimResponse(t *testing.T) {
	u := &model.ScimUser{
		ID:           uuid.MustParse("12345678-1234-1234-1234-123456789abc"),
		UserName:     "testUser",
		Active:       true,
		CreatedAt:    time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC),
		LastModified: time.Date(2024, 1, 2, 0, 0, 0, 0, time.UTC),
		Version:      3,
	}
	dn := "Test User"
	u.DisplayName = &dn

	response := UserToScimResponse(u, "http://example.com/scim/v2", nil)

	if response["id"] != "12345678-1234-1234-1234-123456789abc" {
		t.Fatalf("id = %v", response["id"])
	}
	if response["userName"] != "testUser" {
		t.Fatalf("userName = %v", response["userName"])
	}
	if response["displayName"] != "Test User" {
		t.Fatalf("displayName = %v", response["displayName"])
	}
	if response["active"] != true {
		t.Fatalf("active = %v", response["active"])
	}

	meta := response["meta"].(map[string]any)
	if meta["resourceType"] != "User" {
		t.Fatalf("meta.resourceType = %v", meta["resourceType"])
	}
	if meta["version"] != `W/"3"` {
		t.Fatalf("meta.version = %v", meta["version"])
	}
}

func TestUserToScimResponse_Enterprise(t *testing.T) {
	u := &model.ScimUser{
		ID:           uuid.New(),
		UserName:     "testUser",
		Active:       true,
		CreatedAt:    time.Now(),
		LastModified: time.Now(),
	}
	emp := "EMP001"
	u.EnterpriseEmployeeNumber = &emp

	response := UserToScimResponse(u, "http://example.com/scim/v2", nil)

	schemas := response["schemas"].([]string)
	if len(schemas) != 2 {
		t.Fatalf("expected 2 schemas with enterprise, got %d", len(schemas))
	}
	if schemas[1] != EnterpriseSchemaURN {
		t.Fatalf("second schema = %v, want enterprise URN", schemas[1])
	}

	ext := response[EnterpriseSchemaURN].(map[string]any)
	if ext["employeeNumber"] != "EMP001" {
		t.Fatalf("enterprise.employeeNumber = %v", ext["employeeNumber"])
	}
}

func TestGroupToScimResponse(t *testing.T) {
	g := &model.ScimGroup{
		ID:           uuid.MustParse("12345678-1234-1234-1234-123456789abc"),
		DisplayName:  "Admins",
		CreatedAt:    time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC),
		LastModified: time.Date(2024, 1, 2, 0, 0, 0, 0, time.UTC),
		Version:      1,
	}

	response := GroupToScimResponse(g, "http://example.com/scim/v2")

	if response["id"] != "12345678-1234-1234-1234-123456789abc" {
		t.Fatalf("id = %v", response["id"])
	}
	if response["displayName"] != "Admins" {
		t.Fatalf("displayName = %v", response["displayName"])
	}

	schemas := response["schemas"].([]string)
	if len(schemas) != 1 || schemas[0] != GroupSchemaURN {
		t.Fatalf("schemas = %v", schemas)
	}

	meta := response["meta"].(map[string]any)
	if meta["resourceType"] != "Group" {
		t.Fatalf("meta.resourceType = %v", meta["resourceType"])
	}
}

func TestApplyMsCompat(t *testing.T) {
	response := map[string]any{
		"entitlements": []map[string]any{
			{"value": "Premium", "primary": true},
		},
		"roles": []map[string]any{
			{"value": "Admin", "primary": false},
		},
		"x509Certificates": []map[string]any{
			{"value": "cert", "primary": true},
		},
	}

	result := ApplyMsCompat(response)

	ents := result["entitlements"].([]map[string]any)
	if ents[0]["primary"] != "true" {
		t.Fatalf("entitlements primary = %v, want string true", ents[0]["primary"])
	}

	roles := result["roles"].([]map[string]any)
	if roles[0]["primary"] != "false" {
		t.Fatalf("roles primary = %v, want string false", roles[0]["primary"])
	}
}

func TestHashPassword(t *testing.T) {
	// Plaintext password should be hashed
	pw := "mySecretPass123"
	hashed, err := HashPassword(&pw)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if hashed == nil {
		t.Fatalf("expected non-nil hashed password")
	}
	if *hashed == pw {
		t.Fatalf("expected password to be hashed, but was identical to plaintext")
	}
	if err := bcrypt.CompareHashAndPassword([]byte(*hashed), []byte(pw)); err != nil {
		t.Fatalf("bcrypt verification failed: %v", err)
	}

	// Inputs starting with $2a$, $2b$, and $2y$ must still be hashed as plaintext passwords
	for _, prefixInput := range []string{
		"$2a$10$abcdefghijklmnopqrstuvwxyz0123456789",
		"$2b$10$abcdefghijklmnopqrstuvwxyz0123456789",
		"$2y$10$abcdefghijklmnopqrstuvwxyz0123456789",
	} {
		input := prefixInput
		hashedPrefix, err := HashPassword(&input)
		if err != nil || hashedPrefix == nil {
			t.Fatalf("expected password starting with bcrypt prefix %q to be hashed, got err=%v", input, err)
		}
		if *hashedPrefix == input {
			t.Fatalf("expected password starting with bcrypt prefix %q to be hashed, but returned unchanged", input)
		}
		if err := bcrypt.CompareHashAndPassword([]byte(*hashedPrefix), []byte(input)); err != nil {
			t.Fatalf("bcrypt verification failed for %q: %v", input, err)
		}
	}

	// Nil stays nil; empty string is rejected as invalidValue (400)
	if res, err := HashPassword(nil); err != nil || res != nil {
		t.Fatalf("nil password should return nil, nil")
	}
	empty := ""
	resEmpty, err := HashPassword(&empty)
	if err == nil || resEmpty != nil {
		t.Fatalf("expected 400 invalidValue error for empty password, got %v", resEmpty)
	}
	var emptyScimErr *ScimError
	if !errors.As(err, &emptyScimErr) || emptyScimErr.Status != 400 || emptyScimErr.ScimType != "invalidValue" {
		t.Fatalf("expected 400 invalidValue ScimError for empty password, got %v", err)
	}

	// Password exceeding 72 bytes must return error
	longPw := strings.Repeat("a", 73)
	resLong, err := HashPassword(&longPw)
	if err == nil {
		t.Fatalf("expected error for password > 72 bytes, got %v", resLong)
	}
	var scimErr *ScimError
	if !errors.As(err, &scimErr) {
		t.Fatalf("expected *ScimError, got %T", err)
	}
	if scimErr.Status != 400 || scimErr.ScimType != "invalidValue" {
		t.Fatalf("expected status 400 and invalidValue, got %d, %s", scimErr.Status, scimErr.ScimType)
	}
}

func TestApplyUserAttributes_Password(t *testing.T) {
	u := &model.ScimUser{}
	input := map[string]any{
		"userName": "test@example.com",
		"password": "Password123!",
	}
	if err := ApplyFromScimInput(u, input); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if u.Password == nil {
		t.Fatalf("expected user password to be set")
	}
	if err := bcrypt.CompareHashAndPassword([]byte(*u.Password), []byte("Password123!")); err != nil {
		t.Fatalf("bcrypt compare failed: %v", err)
	}

	// Long password rejected
	inputLong := map[string]any{
		"userName": "test2@example.com",
		"password": strings.Repeat("X", 80),
	}
	if err := ApplyFromScimInput(&model.ScimUser{}, inputLong); err == nil {
		t.Fatalf("expected error for password > 72 bytes in ApplyFromScimInput")
	}
}
