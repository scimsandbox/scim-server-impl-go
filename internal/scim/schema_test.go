package scim

import (
    "testing"
)

func TestAllSchemas_ReturnsExpectedCount(t *testing.T) {
    schemas := AllSchemas()
    if len(schemas) != 6 {
        t.Fatalf("AllSchemas() returned %d schemas, want 6", len(schemas))
    }
}

func TestGetSchemaByID_User(t *testing.T) {
    s := GetSchemaByID("urn:ietf:params:scim:schemas:core:2.0:User")
    if s == nil {
        t.Fatalf("User schema not found")
    }
    if s["name"] != "User" {
        t.Fatalf("User schema name = %v, want User", s["name"])
    }
    attrs := s["attributes"].([]map[string]any)
    if len(attrs) == 0 {
        t.Fatalf("User schema has no attributes")
    }
}

func TestGetSchemaByID_Group(t *testing.T) {
    s := GetSchemaByID("urn:ietf:params:scim:schemas:core:2.0:Group")
    if s == nil {
        t.Fatalf("Group schema not found")
    }
    if s["name"] != "Group" {
        t.Fatalf("Group schema name = %v, want Group", s["name"])
    }
    attrs := s["attributes"].([]map[string]any)
    if len(attrs) != 4 {
        t.Fatalf("Group schema attribute count = %d, want 4", len(attrs))
    }
}

func TestGetSchemaByID_Enterprise(t *testing.T) {
    s := GetSchemaByID("urn:ietf:params:scim:schemas:extension:enterprise:2.0:User")
    if s == nil {
        t.Fatalf("Enterprise User schema not found")
    }
    if s["name"] != "EnterpriseUser" {
        t.Fatalf("Enterprise schema name = %v, want EnterpriseUser", s["name"])
    }
    attrs := s["attributes"].([]map[string]any)
    if len(attrs) != 6 {
        t.Fatalf("Enterprise schema attribute count = %d, want 6", len(attrs))
    }
}

func TestGetSchemaByID_Unknown(t *testing.T) {
    s := GetSchemaByID("urn:unknown")
    if s != nil {
        t.Fatalf("expected nil for unknown schema, got %v", s)
    }
}

func TestResourceTypes_ReturnsExpected(t *testing.T) {
    rts := ResourceTypes("http://example.com")
    if len(rts) != 2 {
        t.Fatalf("ResourceTypes() returned %d, want 2", len(rts))
    }
    if rts[0]["name"] != "User" {
        t.Fatalf("first resource type name = %v, want User", rts[0]["name"])
    }
    if rts[1]["name"] != "Group" {
        t.Fatalf("second resource type name = %v, want Group", rts[1]["name"])
    }
}

func TestGetResourceTypeByID(t *testing.T) {
    rt := GetResourceTypeByID("User", "http://example.com")
    if rt == nil {
        t.Fatalf("User resource type not found")
    }
    if rt["endpoint"] != "/Users" {
        t.Fatalf("User resource type endpoint = %v, want /Users", rt["endpoint"])
    }

    rt = GetResourceTypeByID("Unknown", "http://example.com")
    if rt != nil {
        t.Fatalf("expected nil for unknown resource type")
    }
}

func TestServiceProviderConfig(t *testing.T) {
    spc := ServiceProviderConfig()
    if spc == nil {
        t.Fatalf("ServiceProviderConfig() returned nil")
    }

    patch := spc["patch"].(map[string]any)
    if patch["supported"] != true {
        t.Fatalf("patch.supported = %v, want true", patch["supported"])
    }

    bulk := spc["bulk"].(map[string]any)
    if bulk["supported"] != true {
        t.Fatalf("bulk.supported = %v, want true", bulk["supported"])
    }

    filter := spc["filter"].(map[string]any)
    if filter["supported"] != true {
        t.Fatalf("filter.supported = %v, want true", filter["supported"])
    }
}
