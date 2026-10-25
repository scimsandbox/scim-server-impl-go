package handler

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/scimsandbox/scim-server-impl-go/internal/middleware"
)

// RFC 7644 §3.4.3 requires 501 from the root .search endpoint when cross-resource search is not
// supported, so the status is part of the contract rather than an implementation detail.
func TestGlobalSearchNotImplemented(t *testing.T) {
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/ws/24fb7ccb-3458-44da-b5c8-92b97e2ad702/scim/v2/.search", nil)

	NewDiscoveryHandler().GlobalSearchNotImplemented(rec, req)

	if rec.Code != http.StatusNotImplemented {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusNotImplemented)
	}
	if ct := rec.Header().Get("Content-Type"); ct != ScimContentType {
		t.Fatalf("Content-Type = %q, want %q", ct, ScimContentType)
	}

	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("response body is not JSON: %v", err)
	}
	if got := body["status"]; got != "501" {
		t.Errorf("body status = %v, want \"501\"", got)
	}
	schemas, ok := body["schemas"].([]any)
	if !ok || len(schemas) != 1 || schemas[0] != "urn:ietf:params:scim:api:messages:2.0:Error" {
		t.Errorf("schemas = %v, want the SCIM Error schema URN", body["schemas"])
	}
	if detail, _ := body["detail"].(string); detail == "" {
		t.Error("detail is empty, want an explanation of the unsupported operation")
	}
}

func TestRootSearch_MissingWorkspace(t *testing.T) {
	dh := NewDiscoveryHandler()
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)

	dh.RootSearch(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("expected 404 for missing workspace, got %d", rec.Code)
	}
}

func TestRootSearch_EmptyHandlersReturnsEmptyList(t *testing.T) {
	dh := NewDiscoveryHandler()
	rec := httptest.NewRecorder()
	wsID := uuid.New()
	req := httptest.NewRequest(http.MethodGet, "/?startIndex=1&count=10", nil)
	req = req.WithContext(context.WithValue(req.Context(), middleware.WorkspaceIDKey, wsID))

	dh.RootSearch(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}

	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("failed to unmarshal JSON: %v", err)
	}
	if body["totalResults"] != float64(0) {
		t.Fatalf("expected totalResults 0, got %v", body["totalResults"])
	}
	resources, ok := body["Resources"].([]any)
	if !ok || len(resources) != 0 {
		t.Fatalf("expected empty Resources array, got %v", body["Resources"])
	}
}

func TestRootSearch_PostInvalidJSON(t *testing.T) {
	dh := NewDiscoveryHandler()
	rec := httptest.NewRecorder()
	wsID := uuid.New()
	req := httptest.NewRequest(http.MethodPost, "/.search", strings.NewReader("{invalid-json"))
	req = req.WithContext(context.WithValue(req.Context(), middleware.WorkspaceIDKey, wsID))

	dh.RootSearch(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for invalid JSON, got %d", rec.Code)
	}
}

func TestRootSearch_InvalidFilterSyntax(t *testing.T) {
	dh := NewDiscoveryHandler()
	rec := httptest.NewRecorder()
	wsID := uuid.New()
	req := httptest.NewRequest(http.MethodGet, `/?filter=userName%20eq`, nil)
	req = req.WithContext(context.WithValue(req.Context(), middleware.WorkspaceIDKey, wsID))

	dh.RootSearch(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for invalid filter syntax, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestSortResources(t *testing.T) {
	items := []map[string]any{
		{"id": "3", "displayName": "Charlie"},
		{"id": "1", "displayName": "Alice"},
		{"id": "4", "displayName": nil},
		{"id": "2", "displayName": "Bob"},
	}

	// Ascending: nulls last
	sortResources(items, "displayName", "ascending")
	if items[0]["displayName"] != "Alice" || items[1]["displayName"] != "Bob" || items[2]["displayName"] != "Charlie" || items[3]["displayName"] != nil {
		t.Fatalf("unexpected asc sort order: %+v", items)
	}

	// Descending: nulls first
	sortResources(items, "displayName", "descending")
	if items[0]["displayName"] != nil || items[1]["displayName"] != "Charlie" || items[2]["displayName"] != "Bob" || items[3]["displayName"] != "Alice" {
		t.Fatalf("unexpected desc sort order: %+v", items)
	}

	// Mixed resource types sorted by meta.resourceType
	mixed := []map[string]any{
		{"id": "u1", "meta": map[string]any{"resourceType": "User"}},
		{"id": "g1", "meta": map[string]any{"resourceType": "Group"}},
	}
	sortResources(mixed, "meta.resourceType", "ascending")
	if mixed[0]["id"] != "g1" || mixed[1]["id"] != "u1" {
		t.Fatalf("expected Group before User on asc, got %+v", mixed)
	}
	sortResources(mixed, "meta.resourceType", "descending")
	if mixed[0]["id"] != "u1" || mixed[1]["id"] != "g1" {
		t.Fatalf("expected User before Group on desc, got %+v", mixed)
	}
}

func TestExtractSortAttr(t *testing.T) {
	res := map[string]any{
		"displayName": "Test",
		"meta": map[string]any{
			"resourceType": "User",
			"created":      "2026-01-01T00:00:00Z",
		},
	}

	val, ok := extractSortAttr(res, "displayName")
	if !ok || val != "Test" {
		t.Fatalf("expected Test, got %v (ok=%v)", val, ok)
	}

	// Case-insensitivity on key
	val, ok = extractSortAttr(res, "displayname")
	if !ok || val != "Test" {
		t.Fatalf("expected Test, got %v (ok=%v)", val, ok)
	}

	// Nested key
	val, ok = extractSortAttr(res, "meta.resourceType")
	if !ok || val != "User" {
		t.Fatalf("expected User, got %v (ok=%v)", val, ok)
	}

	// Missing key
	_, ok = extractSortAttr(res, "nonexistent")
	if ok {
		t.Fatalf("expected false for missing key")
	}

	// Nil map
	_, ok = extractSortAttr(nil, "displayName")
	if ok {
		t.Fatalf("expected false for nil map")
	}
}

