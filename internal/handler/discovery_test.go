package handler

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
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
