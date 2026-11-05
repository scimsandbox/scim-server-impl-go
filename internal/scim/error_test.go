package scim

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestBuildErrorBody_WithScimType(t *testing.T) {
	err := NewScimError(400, "invalidValue", "some detail")
	if err.Status != 400 {
		t.Fatalf("Status = %d, want 400", err.Status)
	}
	if err.ScimType != "invalidValue" {
		t.Fatalf("ScimType = %q, want invalidValue", err.ScimType)
	}
	if err.Detail != "some detail" {
		t.Fatalf("Detail = %q, want some detail", err.Detail)
	}
}

func TestBuildErrorBody_WithoutScimType(t *testing.T) {
	err := NewScimError(500, "", "internal error")
	if err.Status != 500 {
		t.Fatalf("Status = %d, want 500", err.Status)
	}
	if err.ScimType != "" {
		t.Fatalf("ScimType = %q, want empty", err.ScimType)
	}
	if err.Detail != "internal error" {
		t.Fatalf("Detail = %q, want internal error", err.Detail)
	}
	if err.Error() != "SCIM error 500: internal error" {
		t.Fatalf("Error() = %q", err.Error())
	}
}

// RFC7644-3.12-991537 (Group 5): 500 Internal Server Error returns descriptive SCIM Error JSON
// without leaking SQL/JDBC/driver exception internals.
func TestWriteErrorFromAny_SanitizesInternal500Error_RFC7644_3_12_991537(t *testing.T) {
	simulatedDBErr := errors.New(`pq: syntax error at or near "SELECT" in query: SELECT password FROM scim_users WHERE dsn='postgres://admin:SuperSecretDBPass@10.0.0.5:5432/scim'`)
	rec := httptest.NewRecorder()

	WriteErrorFromAny(rec, simulatedDBErr)

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("HTTP status = %d, want 500", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "application/scim+json") {
		t.Errorf("Content-Type = %q, want application/scim+json", ct)
	}

	raw := rec.Body.String()
	for _, forbidden := range []string{"SELECT", "scim_users", "SuperSecretDBPass", "postgres://", "pq:"} {
		if strings.Contains(raw, forbidden) {
			t.Fatalf("internal SQL/DB secret %q leaked in 500 response: %s", forbidden, raw)
		}
	}

	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("unmarshal 500 SCIM Error JSON: %v", err)
	}
	schemas, _ := body["schemas"].([]any)
	if len(schemas) != 1 || schemas[0] != "urn:ietf:params:scim:api:messages:2.0:Error" {
		t.Errorf("schemas = %v, want [urn:ietf:params:scim:api:messages:2.0:Error]", body["schemas"])
	}
	if body["status"] != "500" {
		t.Errorf("status = %v, want \"500\"", body["status"])
	}
	if body["detail"] != "Internal server error" {
		t.Errorf("detail = %v, want \"Internal server error\"", body["detail"])
	}
}
