package scim

import (
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/scimsandbox/scim-server-impl-go/internal/model"
)

func newTestUser() *model.ScimUser {
	return &model.ScimUser{
		ID:           uuid.New(),
		UserName:     "testUser",
		CreatedAt:    time.Now(),
		LastModified: time.Now(),
	}
}

func TestApplyPatchOperations_Empty(t *testing.T) {
	u := newTestUser()
	if err := ApplyPatchOperations(u, nil); err == nil {
		t.Fatalf("expected error for nil operations")
	}
	if err := ApplyPatchOperations(u, []map[string]any{}); err == nil {
		t.Fatalf("expected error for empty operations")
	}
}

func TestApplyPatchOperations_ReadOnlyAttributes(t *testing.T) {
	u := newTestUser()
	readOnly := []string{"id", "meta", "meta.created", "meta.lastModified", "meta.location", "meta.resourceType", "meta.version", "groups"}
	for _, attr := range readOnly {
		ops := []map[string]any{{"op": "replace", "path": attr, "value": "newId"}}
		if err := ApplyPatchOperations(u, ops); err == nil {
			t.Fatalf("expected error for read-only attribute %s", attr)
		}
	}
}

func TestApplyPatchOperations_UnknownOperation(t *testing.T) {
	u := newTestUser()
	ops := []map[string]any{{"op": "unknown", "path": "userName", "value": "newId"}}
	if err := ApplyPatchOperations(u, ops); err == nil {
		t.Fatalf("expected error for unknown operation")
	}
}

func TestApplyPatchOperations_AddNoPath(t *testing.T) {
	u := newTestUser()
	ops := []map[string]any{{"op": "add", "value": map[string]any{"userName": "newValue", "nickName": "newNick"}}}
	if err := ApplyPatchOperations(u, ops); err != nil {
		t.Fatalf("apply failed: %v", err)
	}
	if u.UserName != "newValue" {
		t.Fatalf("expected username updated, got %s", u.UserName)
	}
	if u.NickName == nil || *u.NickName != "newNick" {
		t.Fatalf("expected nickName updated")
	}

	// Invalid Add no path (not a map)
	opsInvalid := []map[string]any{{"op": "add", "value": "string"}}
	if err := ApplyPatchOperations(u, opsInvalid); err == nil {
		t.Fatalf("expected error for non-map value with no path")
	}
}

func TestApplyPatchOperations_AddSingleAttributes(t *testing.T) {
	u := newTestUser()
	ops := []map[string]any{
		{"op": "add", "path": "externalId", "value": "ext123"},
		{"op": "add", "path": "displayName", "value": "Display Name"},
		{"op": "add", "path": "nickName", "value": "Nick"},
		{"op": "add", "path": "profileUrl", "value": "http://example.com"},
		{"op": "add", "path": "title", "value": "Title"},
		{"op": "add", "path": "userType", "value": "Employee"},
		{"op": "add", "path": "preferredLanguage", "value": "en"},
		{"op": "add", "path": "locale", "value": "en-US"},
		{"op": "add", "path": "timezone", "value": "UTC"},
		{"op": "add", "path": "active", "value": true},
		{"op": "add", "path": "password", "value": "secret"},
	}
	if err := ApplyPatchOperations(u, ops); err != nil {
		t.Fatalf("apply failed: %v", err)
	}
	assertStringPtrEquals(t, "externalId", u.ExternalID, "ext123")
	assertStringPtrEquals(t, "displayName", u.DisplayName, "Display Name")
	assertStringPtrEquals(t, "nickName", u.NickName, "Nick")
	assertStringPtrEquals(t, "profileUrl", u.ProfileUrl, "http://example.com")
	assertStringPtrEquals(t, "title", u.Title, "Title")
	assertStringPtrEquals(t, "userType", u.UserType, "Employee")
	assertStringPtrEquals(t, "preferredLanguage", u.PreferredLanguage, "en")
	assertStringPtrEquals(t, "locale", u.Locale, "en-US")
	assertStringPtrEquals(t, "timezone", u.Timezone, "UTC")
	if !u.Active {
		t.Fatalf("active expected true")
	}
	assertStringPtrEquals(t, "password", u.Password, "secret")
}

func TestApplyPatchOperations_AddSubAttributes(t *testing.T) {
	u := newTestUser()
	ops := []map[string]any{
		{"op": "add", "path": "name.formatted", "value": "Formatted"},
		{"op": "add", "path": "name.familyName", "value": "Family"},
		{"op": "add", "path": "name.givenName", "value": "Given"},
		{"op": "add", "path": "name.middleName", "value": "Middle"},
		{"op": "add", "path": "name.honorificPrefix", "value": "Prefix"},
		{"op": "add", "path": "name.honorificSuffix", "value": "Suffix"},
	}
	if err := ApplyPatchOperations(u, ops); err != nil {
		t.Fatalf("apply failed: %v", err)
	}
	assertStringPtrEquals(t, "nameFormatted", u.NameFormatted, "Formatted")
	assertStringPtrEquals(t, "nameFamilyName", u.NameFamilyName, "Family")
	assertStringPtrEquals(t, "nameGivenName", u.NameGivenName, "Given")
	assertStringPtrEquals(t, "nameMiddleName", u.NameMiddleName, "Middle")
	assertStringPtrEquals(t, "nameHonorificPrefix", u.NameHonorificPrefix, "Prefix")
	assertStringPtrEquals(t, "nameHonorificSuffix", u.NameHonorificSuffix, "Suffix")

	// Unknown name sub-attribute
	opsErr := []map[string]any{{"op": "add", "path": "name.unknown", "value": "Val"}}
	if err := ApplyPatchOperations(u, opsErr); err == nil {
		t.Fatalf("expected error for unknown name sub-attribute")
	}

	// Unknown parent attribute
	opsErr2 := []map[string]any{{"op": "add", "path": "unknown.sub", "value": "Val"}}
	if err := ApplyPatchOperations(u, opsErr2); err == nil {
		t.Fatalf("expected error for unknown parent attribute")
	}
}

func TestApplyPatchOperations_AddEnterpriseAttributes(t *testing.T) {
	u := newTestUser()
	prefix := "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User:"
	ops := []map[string]any{
		{"op": "add", "path": prefix + "employeeNumber", "value": "12345"},
		{"op": "add", "path": prefix + "costCenter", "value": "CC1"},
		{"op": "add", "path": prefix + "organization", "value": "Org"},
		{"op": "add", "path": prefix + "division", "value": "Div"},
		{"op": "add", "path": prefix + "department", "value": "Dept"},
		{"op": "add", "path": prefix + "manager", "value": "bob"},
	}
	if err := ApplyPatchOperations(u, ops); err != nil {
		t.Fatalf("apply failed: %v", err)
	}
	assertStringPtrEquals(t, "employeeNumber", u.EnterpriseEmployeeNumber, "12345")
	assertStringPtrEquals(t, "costCenter", u.EnterpriseCostCenter, "CC1")
	assertStringPtrEquals(t, "organization", u.EnterpriseOrganization, "Org")
	assertStringPtrEquals(t, "division", u.EnterpriseDivision, "Div")
	assertStringPtrEquals(t, "department", u.EnterpriseDepartment, "Dept")
	assertStringPtrEquals(t, "managerValue", u.EnterpriseManagerValue, "bob")

	// Manager as complex object
	mgrObj := map[string]any{"value": "alice", "$ref": "http://example.com/Users/alice", "displayName": "Alice"}
	opsObjMgr := []map[string]any{{"op": "add", "path": prefix + "manager", "value": mgrObj}}
	if err := ApplyPatchOperations(u, opsObjMgr); err != nil {
		t.Fatalf("apply manager object failed: %v", err)
	}
	assertStringPtrEquals(t, "managerValue", u.EnterpriseManagerValue, "alice")
	assertStringPtrEquals(t, "managerRef", u.EnterpriseManagerRef, "http://example.com/Users/alice")
	assertStringPtrEquals(t, "managerDisplay", u.EnterpriseManagerDisplay, "Alice")

	// Unknown enterprise attribute
	opsErr := []map[string]any{{"op": "add", "path": prefix + "unknown", "value": "Val"}}
	if err := ApplyPatchOperations(u, opsErr); err == nil {
		t.Fatalf("expected error for unknown enterprise attribute")
	}
}

func TestApplyPatchOperations_AddMultiValuedAttributes(t *testing.T) {
	u := newTestUser()
	ops := []map[string]any{
		{"op": "add", "path": "emails", "value": []any{map[string]any{"value": "bob@example.com", "type": "work", "primary": true}}},
		{"op": "add", "path": "phoneNumbers", "value": map[string]any{"value": "123-456", "type": "work"}},
		{"op": "add", "path": "addresses", "value": []any{map[string]any{"type": "work", "streetAddress": "123 Main St", "postalCode": "12345", "region": "NY", "country": "USA"}}},
		{"op": "add", "path": "ims", "value": []any{map[string]any{"value": "bob_aim", "type": "aim"}}},
		{"op": "add", "path": "photos", "value": []any{map[string]any{"value": "http://example.com/photo.jpg", "type": "photo"}}},
		{"op": "add", "path": "roles", "value": []any{map[string]any{"value": "Admin"}}},
		{"op": "add", "path": "entitlements", "value": []any{map[string]any{"value": "Premium"}}},
		{"op": "add", "path": "x509Certificates", "value": []any{map[string]any{"value": "dGVzdA=="}}},
	}
	if err := ApplyPatchOperations(u, ops); err != nil {
		t.Fatalf("apply failed: %v", err)
	}
	if len(u.Emails) != 1 || u.Emails[0].Value != "bob@example.com" {
		t.Fatalf("emails not added correctly")
	}
	if len(u.PhoneNumbers) != 1 || u.PhoneNumbers[0].Value != "123-456" {
		t.Fatalf("phoneNumbers not added correctly")
	}
	if len(u.Addresses) != 1 || u.Addresses[0].StreetAddress != "123 Main St" {
		t.Fatalf("addresses not added correctly")
	}
	if len(u.Ims) != 1 || u.Ims[0].Value != "bob_aim" {
		t.Fatalf("ims not added correctly")
	}
	if len(u.Photos) != 1 {
		t.Fatalf("photos not added correctly")
	}
	if len(u.Roles) != 1 || u.Roles[0].Value != "Admin" {
		t.Fatalf("roles not added correctly")
	}
	if len(u.Entitlements) != 1 || u.Entitlements[0].Value != "Premium" {
		t.Fatalf("entitlements not added correctly")
	}
	if len(u.X509Certificates) != 1 || u.X509Certificates[0].Value != "dGVzdA==" {
		t.Fatalf("x509Certificates not added correctly")
	}

	// Invalid: multi-valued with non-list/map value
	opsErr := []map[string]any{{"op": "add", "path": "emails", "value": "NotAListOrMap"}}
	if err := ApplyPatchOperations(u, opsErr); err == nil {
		t.Fatalf("expected error for non-list/map multi-valued value")
	}

	// Unknown collection
	opsErr2 := []map[string]any{{"op": "add", "path": "unknownCollection", "value": "val"}}
	if err := ApplyPatchOperations(u, opsErr2); err == nil {
		t.Fatalf("expected error for unknown collection")
	}
}

func TestApplyPatchOperations_ReplaceNoPath(t *testing.T) {
	u := newTestUser()
	ops := []map[string]any{{"op": "replace", "value": map[string]any{"userName": "newValue", "nickName": "newNick"}}}
	if err := ApplyPatchOperations(u, ops); err != nil {
		t.Fatalf("apply failed: %v", err)
	}
	if u.UserName != "newValue" {
		t.Fatalf("expected userName newValue, got %s", u.UserName)
	}

	// Invalid: non-map value
	opsInvalid := []map[string]any{{"op": "replace", "value": "string"}}
	if err := ApplyPatchOperations(u, opsInvalid); err == nil {
		t.Fatalf("expected error for non-map replace with no path")
	}
}

func TestApplyPatchOperations_ReplaceMultiValuedAttributes(t *testing.T) {
	u := newTestUser()
	u.Emails = append(u.Emails, model.ScimUserEmail{Value: "old@example.com", Type: "work"})

	ops := []map[string]any{
		{"op": "replace", "path": "emails", "value": []any{map[string]any{"value": "new@example.com", "type": "work"}}},
	}
	if err := ApplyPatchOperations(u, ops); err != nil {
		t.Fatalf("apply failed: %v", err)
	}
	if len(u.Emails) != 1 || u.Emails[0].Value != "new@example.com" {
		t.Fatalf("emails not replaced correctly")
	}
}

func TestApplyPatchOperations_RemoveAttributes(t *testing.T) {
	u := newTestUser()
	ext := "ext123"
	disp := "Display"
	nick := "nick"
	prof := "url"
	title := "Title"
	utype := "dev"
	lang := "en"
	loc := "US"
	tz := "UTC"
	fmt := "Formatted"
	cc := "CC1"

	u.ExternalID = &ext
	u.DisplayName = &disp
	u.NickName = &nick
	u.ProfileUrl = &prof
	u.Title = &title
	u.UserType = &utype
	u.PreferredLanguage = &lang
	u.Locale = &loc
	u.Timezone = &tz
	u.NameFormatted = &fmt
	u.EnterpriseCostCenter = &cc
	u.Emails = append(u.Emails, model.ScimUserEmail{})
	u.PhoneNumbers = append(u.PhoneNumbers, model.ScimUserPhoneNumber{})
	u.Addresses = append(u.Addresses, model.ScimUserAddress{})
	u.Ims = append(u.Ims, model.ScimUserIm{})
	u.Photos = append(u.Photos, model.ScimUserPhoto{})
	u.Entitlements = append(u.Entitlements, model.ScimUserEntitlement{})
	u.Roles = append(u.Roles, model.ScimUserRole{})
	u.X509Certificates = append(u.X509Certificates, model.ScimUserX509Certificate{})

	ops := []map[string]any{
		{"op": "remove", "path": "externalId"},
		{"op": "remove", "path": "displayName"},
		{"op": "remove", "path": "nickName"},
		{"op": "remove", "path": "profileUrl"},
		{"op": "remove", "path": "title"},
		{"op": "remove", "path": "userType"},
		{"op": "remove", "path": "preferredLanguage"},
		{"op": "remove", "path": "locale"},
		{"op": "remove", "path": "timezone"},
		{"op": "remove", "path": "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User:costCenter"},
		{"op": "remove", "path": "emails"},
		{"op": "remove", "path": "phoneNumbers"},
		{"op": "remove", "path": "addresses"},
		{"op": "remove", "path": "ims"},
		{"op": "remove", "path": "photos"},
		{"op": "remove", "path": "entitlements"},
		{"op": "remove", "path": "roles"},
		{"op": "remove", "path": "x509Certificates"},
	}
	if err := ApplyPatchOperations(u, ops); err != nil {
		t.Fatalf("apply failed: %v", err)
	}

	if u.ExternalID != nil {
		t.Fatalf("externalId not cleared")
	}
	if u.DisplayName != nil {
		t.Fatalf("displayName not cleared")
	}
	if u.NickName != nil {
		t.Fatalf("nickName not cleared")
	}
	if u.EnterpriseCostCenter != nil {
		t.Fatalf("costCenter not cleared")
	}
	if u.Emails != nil {
		t.Fatalf("emails not cleared")
	}
	if u.PhoneNumbers != nil {
		t.Fatalf("phoneNumbers not cleared")
	}

	// Unknown attribute
	opsErr := []map[string]any{{"op": "remove", "path": "unknownAttr"}}
	if err := ApplyPatchOperations(u, opsErr); err == nil {
		t.Fatalf("expected error for unknown attribute")
	}

	// Remove without path
	opsErrNoPath := []map[string]any{{"op": "remove"}}
	if err := ApplyPatchOperations(u, opsErrNoPath); err == nil {
		t.Fatalf("expected error for remove without path")
	}
}

func TestApplyPatchOperations_FilteredReplace(t *testing.T) {
	u := newTestUser()
	u.Emails = append(u.Emails, model.ScimUserEmail{Value: "work@example.com", Type: "work"})
	u.Emails = append(u.Emails, model.ScimUserEmail{Value: "home@example.com", Type: "home"})

	ops := []map[string]any{{"op": "replace", "path": `emails[type eq "work"].value`, "value": "new_work@example.com"}}
	if err := ApplyPatchOperations(u, ops); err != nil {
		t.Fatalf("apply failed: %v", err)
	}
	if u.Emails[0].Value != "new_work@example.com" {
		t.Fatalf("filtered replace didn't update")
	}
	if u.Emails[1].Value != "home@example.com" {
		t.Fatalf("other email modified")
	}
}

func TestApplyPatchOperations_FilteredRemoveAllTypes(t *testing.T) {
	u := newTestUser()
	u.Emails = append(u.Emails, model.ScimUserEmail{Value: "work@example.com", Type: "work"})
	u.Emails = append(u.Emails, model.ScimUserEmail{Value: "home@example.com", Type: "home"})
	u.PhoneNumbers = append(u.PhoneNumbers, model.ScimUserPhoneNumber{Type: "work"})
	u.Addresses = append(u.Addresses, model.ScimUserAddress{Type: "work"})
	u.Roles = append(u.Roles, model.ScimUserRole{Value: "Admin"})
	u.Entitlements = append(u.Entitlements, model.ScimUserEntitlement{Value: "Prem"})
	u.Ims = append(u.Ims, model.ScimUserIm{Type: "aim"})
	u.Photos = append(u.Photos, model.ScimUserPhoto{Type: "photo"})
	u.X509Certificates = append(u.X509Certificates, model.ScimUserX509Certificate{Value: "abc"})

	ops := []map[string]any{
		{"op": "remove", "path": `emails[type eq "work"]`},
		{"op": "remove", "path": `phoneNumbers[type eq "work"]`},
		{"op": "remove", "path": `addresses[type eq "work"]`},
		{"op": "remove", "path": `roles[value eq "Admin"]`},
		{"op": "remove", "path": `entitlements[value eq "Prem"]`},
		{"op": "remove", "path": `ims[type eq "aim"]`},
		{"op": "remove", "path": `photos[type eq "photo"]`},
		{"op": "remove", "path": `x509Certificates[value eq "abc"]`},
	}
	if err := ApplyPatchOperations(u, ops); err != nil {
		t.Fatalf("apply failed: %v", err)
	}

	if len(u.Emails) != 1 || u.Emails[0].Value != "home@example.com" {
		t.Fatalf("email filtered remove incorrect")
	}
	if len(u.PhoneNumbers) != 0 {
		t.Fatalf("phoneNumbers not cleared")
	}
	if len(u.Addresses) != 0 {
		t.Fatalf("addresses not cleared")
	}
	if len(u.Roles) != 0 {
		t.Fatalf("roles not cleared")
	}
	if len(u.Entitlements) != 0 {
		t.Fatalf("entitlements not cleared")
	}
	if len(u.Ims) != 0 {
		t.Fatalf("ims not cleared")
	}
	if len(u.Photos) != 0 {
		t.Fatalf("photos not cleared")
	}
	if len(u.X509Certificates) != 0 {
		t.Fatalf("x509Certificates not cleared")
	}

	// Unknown collection
	opsErr := []map[string]any{{"op": "remove", "path": `unknown[type eq "work"]`}}
	if err := ApplyPatchOperations(u, opsErr); err == nil {
		t.Fatalf("expected error for unknown filtered collection")
	}
}

func TestApplyPatchOperations_FilteredReplaceSubAttributes(t *testing.T) {
	u := newTestUser()
	u.Emails = append(u.Emails, model.ScimUserEmail{Type: "work"})
	u.PhoneNumbers = append(u.PhoneNumbers, model.ScimUserPhoneNumber{Type: "work"})
	u.Addresses = append(u.Addresses, model.ScimUserAddress{Type: "work"})
	u.Ims = append(u.Ims, model.ScimUserIm{Type: "aim"})
	u.Photos = append(u.Photos, model.ScimUserPhoto{Type: "photo"})
	u.Roles = append(u.Roles, model.ScimUserRole{Value: "Admin"})
	u.Entitlements = append(u.Entitlements, model.ScimUserEntitlement{Value: "Prem"})
	u.X509Certificates = append(u.X509Certificates, model.ScimUserX509Certificate{Value: "abc"})

	ops := []map[string]any{
		{"op": "replace", "path": `emails[type eq "work"].display`, "value": "Work Email"},
		{"op": "replace", "path": `phoneNumbers[type eq "work"].primary`, "value": true},
		{"op": "replace", "path": `phoneNumbers[type eq "work"].display`, "value": "Disp"},
		{"op": "replace", "path": `addresses[type eq "work"].locality`, "value": "City"},
		{"op": "replace", "path": `addresses[type eq "work"].primary`, "value": true},
		{"op": "replace", "path": `addresses[type eq "work"].formatted`, "value": "Formatted"},
		{"op": "replace", "path": `ims[type eq "aim"].value`, "value": "bob_aim2"},
		{"op": "replace", "path": `ims[type eq "aim"].primary`, "value": true},
		{"op": "replace", "path": `ims[type eq "aim"].display`, "value": "disp"},
		{"op": "replace", "path": `photos[type eq "photo"].primary`, "value": true},
		{"op": "replace", "path": `photos[type eq "photo"].display`, "value": "disp"},
		{"op": "replace", "path": `roles[value eq "Admin"].display`, "value": "Administrator"},
		{"op": "replace", "path": `roles[value eq "Admin"].primary`, "value": true},
		{"op": "replace", "path": `entitlements[value eq "Prem"].type`, "value": "type2"},
		{"op": "replace", "path": `entitlements[value eq "Prem"].primary`, "value": true},
		{"op": "replace", "path": `entitlements[value eq "Prem"].display`, "value": "Disp"},
		{"op": "replace", "path": `x509Certificates[value eq "abc"].display`, "value": "certDisplay"},
		{"op": "replace", "path": `x509Certificates[value eq "abc"].primary`, "value": true},
	}
	if err := ApplyPatchOperations(u, ops); err != nil {
		t.Fatalf("apply failed: %v", err)
	}

	if u.Emails[0].Display != "Work Email" {
		t.Fatalf("email display not set")
	}
	if !u.PhoneNumbers[0].PrimaryFlag {
		t.Fatalf("phone primary not set")
	}
	if u.Addresses[0].Locality != "City" {
		t.Fatalf("address locality not set")
	}
	if u.Ims[0].Value != "bob_aim2" {
		t.Fatalf("im value not set")
	}
	if !u.Photos[0].PrimaryFlag {
		t.Fatalf("photo primary not set")
	}
	if u.Roles[0].Display != "Administrator" {
		t.Fatalf("role display not set")
	}
	if u.Entitlements[0].Type != "type2" {
		t.Fatalf("entitlement type not set")
	}
	if u.X509Certificates[0].Display != "certDisplay" {
		t.Fatalf("cert display not set")
	}
}

func TestApplyPatchOperations_FilteredMatchNotFound(t *testing.T) {
	u := newTestUser()
	// No emails => filter should not find match
	ops := []map[string]any{
		{"op": "replace", "path": `emails[type eq "work"].value`, "value": "new"},
	}
	if err := ApplyPatchOperations(u, ops); err == nil {
		t.Fatalf("expected error for no matching item")
	}
}

func TestApplyPatchOperations_FilteredInvalidSyntax(t *testing.T) {
	u := newTestUser()
	u.Emails = append(u.Emails, model.ScimUserEmail{Type: "work"})

	// Filter without space before value
	ops := []map[string]any{
		{"op": "replace", "path": `emails[type eq"work"].value`, "value": "new"},
	}
	if err := ApplyPatchOperations(u, ops); err == nil {
		t.Fatalf("expected error for invalid filter syntax")
	}
}

func assertStringPtrEquals(t *testing.T, name string, ptr *string, want string) {
	t.Helper()
	if ptr == nil {
		t.Fatalf("%s is nil, expected %q", name, want)
	}
	if *ptr != want {
		t.Fatalf("%s = %q, want %q", name, *ptr, want)
	}
}
