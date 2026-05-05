package scim

import (
	"testing"
	"time"

	"github.com/google/uuid"
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
