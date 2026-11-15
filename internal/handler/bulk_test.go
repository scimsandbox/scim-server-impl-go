package handler

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/scimsandbox/scim-server-impl-go/internal/middleware"
	"github.com/scimsandbox/scim-server-impl-go/internal/model"
	"github.com/scimsandbox/scim-server-impl-go/internal/scim"
)

func TestNormalizeBulkPath(t *testing.T) {
	tests := []struct {
		name         string
		input        string
		expectedPath string
		wantErr      bool
		wantScimType string
	}{
		{
			name:         "canonical users path",
			input:        "/Users",
			expectedPath: "/Users",
		},
		{
			name:         "double leading slash users path (production issue)",
			input:        "//Users",
			expectedPath: "/Users",
		},
		{
			name:         "triple leading slash users path",
			input:        "///Users",
			expectedPath: "/Users",
		},
		{
			name:         "relative users path without leading slash",
			input:        "Users",
			expectedPath: "/Users",
		},
		{
			name:         "users path with trailing slash",
			input:        "/Users/",
			expectedPath: "/Users",
		},
		{
			name:         "double slash with trailing slash",
			input:        "//Users/",
			expectedPath: "/Users",
		},
		{
			name:         "canonical groups path",
			input:        "/Groups",
			expectedPath: "/Groups",
		},
		{
			name:         "double leading slash groups path",
			input:        "//Groups",
			expectedPath: "/Groups",
		},
		{
			name:         "canonical resource item path",
			input:        "/Users/123e4567-e89b-12d3-a456-426614174000",
			expectedPath: "/Users/123e4567-e89b-12d3-a456-426614174000",
		},
		{
			name:         "double leading slash resource item path",
			input:        "//Users/123e4567-e89b-12d3-a456-426614174000",
			expectedPath: "/Users/123e4567-e89b-12d3-a456-426614174000",
		},
		{
			name:         "redundant internal slashes in resource item path",
			input:        "//Users//123e4567-e89b-12d3-a456-426614174000",
			expectedPath: "/Users/123e4567-e89b-12d3-a456-426614174000",
		},
		{
			name:         "empty string",
			input:        "",
			expectedPath: "",
		},
		{
			name:         "whitespace string",
			input:        "   ",
			expectedPath: "",
		},
		{
			name:         "dot path traversal rejected",
			input:        "/Users/./123",
			wantErr:      true,
			wantScimType: "invalidPath",
		},
		{
			name:         "dot-dot path traversal rejected",
			input:        "/Users/../Groups/123",
			wantErr:      true,
			wantScimType: "invalidPath",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			segments, err := normalizeBulkPath(tc.input)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("normalizeBulkPath(%q) expected error, got nil", tc.input)
				}
				var scimErr *scim.ScimError
				if errors.As(err, &scimErr) {
					if scimErr.ScimType != tc.wantScimType {
						t.Errorf("normalizeBulkPath(%q) scimType = %q; want %q", tc.input, scimErr.ScimType, tc.wantScimType)
					}
				} else {
					t.Errorf("normalizeBulkPath(%q) error is not a ScimError: %v", tc.input, err)
				}
			} else {
				if err != nil {
					t.Fatalf("normalizeBulkPath(%q) unexpected error: %v", tc.input, err)
				}
				var path string
				if len(segments) > 0 {
					path = "/" + strings.Join(segments, "/")
				}
				if path != tc.expectedPath {
					t.Errorf("normalizeBulkPath(%q) = %q; want %q", tc.input, path, tc.expectedPath)
				}
			}
		})
	}
}

func TestParseBulkTarget_Post(t *testing.T) {
	tests := []struct {
		name         string
		path         string
		wantType     bulkResourceType
		wantErr      bool
		wantScimType string
		wantStatus   int
	}{
		{
			name:     "valid Users endpoint canonical",
			path:     "/Users",
			wantType: bulkResourceUsers,
		},
		{
			name:     "valid Users endpoint double slash",
			path:     "//Users",
			wantType: bulkResourceUsers,
		},
		{
			name:     "valid Users endpoint lowercase",
			path:     "/users",
			wantType: bulkResourceUsers,
		},
		{
			name:     "valid Groups endpoint canonical",
			path:     "/Groups",
			wantType: bulkResourceGroups,
		},
		{
			name:     "valid Groups endpoint lowercase",
			path:     "/groups",
			wantType: bulkResourceGroups,
		},
		{
			name:         "POST to item path rejected",
			path:         "/Users/123e4567-e89b-12d3-a456-426614174000",
			wantErr:      true,
			wantScimType: "invalidPath",
			wantStatus:   400,
		},
		{
			name:         "POST to double slash item path rejected",
			path:         "//Users//123e4567-e89b-12d3-a456-426614174000",
			wantErr:      true,
			wantScimType: "invalidPath",
			wantStatus:   400,
		},
		{
			name:         "POST to unknown endpoint rejected",
			path:         "/UnknownEndpoint",
			wantErr:      true,
			wantScimType: "invalidValue",
			wantStatus:   400,
		},
		{
			name:         "POST to traversal path rejected",
			path:         "/Users/../Groups",
			wantErr:      true,
			wantScimType: "invalidPath",
			wantStatus:   400,
		},
		{
			name:         "POST to empty path rejected",
			path:         "",
			wantErr:      true,
			wantScimType: "invalidPath",
			wantStatus:   400,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			target, err := parseBulkTarget(tc.path, false)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("parseBulkTarget(%q, false) expected error, got nil", tc.path)
				}
				var scimErr *scim.ScimError
				if errors.As(err, &scimErr) {
					if scimErr.Status != tc.wantStatus {
						t.Errorf("parseBulkTarget(%q) status = %d; want %d", tc.path, scimErr.Status, tc.wantStatus)
					}
					if scimErr.ScimType != tc.wantScimType {
						t.Errorf("parseBulkTarget(%q) scimType = %q; want %q", tc.path, scimErr.ScimType, tc.wantScimType)
					}
				} else {
					t.Errorf("parseBulkTarget(%q) error is not a ScimError: %v", tc.path, err)
				}
			} else {
				if err != nil {
					t.Fatalf("parseBulkTarget(%q, false) unexpected error: %v", tc.path, err)
				}
				if target.resourceType != tc.wantType {
					t.Errorf("parseBulkTarget(%q) resourceType = %v; want %v", tc.path, target.resourceType, tc.wantType)
				}
			}
		})
	}
}

func TestParseBulkTarget_Item(t *testing.T) {
	validUUID := uuid.New()
	validUUIDStr := validUUID.String()

	tests := []struct {
		name         string
		path         string
		wantType     bulkResourceType
		wantID       uuid.UUID
		wantErr      bool
		wantScimType string
		wantStatus   int
	}{
		{
			name:     "valid Users path canonical",
			path:     "/Users/" + validUUIDStr,
			wantType: bulkResourceUsers,
			wantID:   validUUID,
			wantErr:  false,
		},
		{
			name:     "valid Users path double slash",
			path:     "//Users/" + validUUIDStr,
			wantType: bulkResourceUsers,
			wantID:   validUUID,
			wantErr:  false,
		},
		{
			name:     "valid Users path no leading slash",
			path:     "Users/" + validUUIDStr,
			wantType: bulkResourceUsers,
			wantID:   validUUID,
			wantErr:  false,
		},
		{
			name:     "valid Users path lowercase",
			path:     "/users/" + validUUIDStr,
			wantType: bulkResourceUsers,
			wantID:   validUUID,
			wantErr:  false,
		},
		{
			name:     "valid Groups path canonical",
			path:     "/Groups/" + validUUIDStr,
			wantType: bulkResourceGroups,
			wantID:   validUUID,
			wantErr:  false,
		},
		{
			name:     "valid Groups path double slash",
			path:     "//Groups/" + validUUIDStr,
			wantType: bulkResourceGroups,
			wantID:   validUUID,
			wantErr:  false,
		},
		{
			name:     "valid Groups path lowercase",
			path:     "/groups/" + validUUIDStr,
			wantType: bulkResourceGroups,
			wantID:   validUUID,
			wantErr:  false,
		},
		{
			name:         "missing ID in Users path",
			path:         "/Users",
			wantErr:      true,
			wantScimType: "invalidPath",
			wantStatus:   400,
		},
		{
			name:         "missing ID in double slash Users path",
			path:         "//Users",
			wantErr:      true,
			wantScimType: "invalidPath",
			wantStatus:   400,
		},
		{
			name:         "trailing slash only no ID",
			path:         "/Users/",
			wantErr:      true,
			wantScimType: "invalidPath",
			wantStatus:   400,
		},
		{
			name:         "unknown resource type",
			path:         "/UnknownEndpoint/" + validUUIDStr,
			wantErr:      true,
			wantScimType: "invalidValue",
			wantStatus:   400,
		},
		{
			name:         "unknown resource type double slash",
			path:         "//UnknownEndpoint/" + validUUIDStr,
			wantErr:      true,
			wantScimType: "invalidValue",
			wantStatus:   400,
		},
		{
			name:         "invalid UUID format",
			path:         "/Users/not-a-uuid",
			wantErr:      true,
			wantScimType: "invalidValue",
			wantStatus:   400,
		},
		{
			name:         "UUID with braces rejected",
			path:         "/Users/{" + validUUIDStr + "}",
			wantErr:      true,
			wantScimType: "invalidValue",
			wantStatus:   400,
		},
		{
			name:         "URN UUID format rejected",
			path:         "/Users/urn:uuid:" + validUUIDStr,
			wantErr:      true,
			wantScimType: "invalidValue",
			wantStatus:   400,
		},
		{
			name:         "traversal path rejected",
			path:         "/Users/../Groups/" + validUUIDStr,
			wantErr:      true,
			wantScimType: "invalidPath",
			wantStatus:   400,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			target, err := parseBulkTarget(tc.path, true)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("parseBulkTarget(%q, true) expected error, got nil", tc.path)
				}
				var scimErr *scim.ScimError
				if errors.As(err, &scimErr) {
					if scimErr.Status != tc.wantStatus {
						t.Errorf("parseBulkTarget(%q, true) status = %d; want %d", tc.path, scimErr.Status, tc.wantStatus)
					}
					if scimErr.ScimType != tc.wantScimType {
						t.Errorf("parseBulkTarget(%q, true) scimType = %q; want %q", tc.path, scimErr.ScimType, tc.wantScimType)
					}
				} else {
					t.Errorf("parseBulkTarget(%q, true) error is not a ScimError: %v", tc.path, err)
				}
			} else {
				if err != nil {
					t.Fatalf("parseBulkTarget(%q, true) unexpected error: %v", tc.path, err)
				}
				if target.resourceType != tc.wantType {
					t.Errorf("parseBulkTarget(%q, true) resourceType = %v; want %v", tc.path, target.resourceType, tc.wantType)
				}
				if target.id != tc.wantID {
					t.Errorf("parseBulkTarget(%q, true) id = %v; want %v", tc.path, target.id, tc.wantID)
				}
			}
		})
	}
}

func TestBulkHandler_ProcessOperation_BulkIdValidation_BLK20(t *testing.T) {
	bh := &BulkHandler{}
	req, _ := http.NewRequest(http.MethodPost, "/Bulk", nil)
	bulkIdMap := make(map[string]string)

	tests := []struct {
		name       string
		op         map[string]any
		wantStatus string
	}{
		{
			name: "POST without bulkId returns 400 invalidValue",
			op: map[string]any{
				"method": "POST",
				"path":   "/Users",
				"data": map[string]any{
					"schemas":  []string{"urn:ietf:params:scim:schemas:core:2.0:User"},
					"userName": "alice@example.com",
				},
			},
			wantStatus: "400",
		},
		{
			name: "POST with empty whitespace bulkId returns 400 invalidValue",
			op: map[string]any{
				"method": "POST",
				"path":   "/Users",
				"bulkId": "   ",
				"data": map[string]any{
					"schemas":  []string{"urn:ietf:params:scim:schemas:core:2.0:User"},
					"userName": "alice@example.com",
				},
			},
			wantStatus: "400",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			res := bh.processOperation(req, tc.op, uuid.New(), bulkIdMap)
			if status, _ := res["status"].(string); status != tc.wantStatus {
				t.Fatalf("expected status %s, got %s", tc.wantStatus, status)
			}
			resp, ok := res["response"].(map[string]any)
			if !ok {
				t.Fatalf("expected error response map in result")
			}
			schemas, _ := resp["schemas"].([]string)
			if len(schemas) == 0 || schemas[0] != "urn:ietf:params:scim:api:messages:2.0:Error" {
				t.Fatalf("expected error schema in response, got %v", schemas)
			}
			if scimType, _ := resp["scimType"].(string); scimType != "invalidValue" {
				t.Fatalf("expected scimType 'invalidValue', got %q", scimType)
			}
		})
	}
}

func TestBulk_MissingDataLocationAndTopologicalOrder(t *testing.T) {
	bh := &BulkHandler{}
	uid := uuid.New()
	req, _ := http.NewRequest(http.MethodPost, "https://example.com/ws/123/scim/v2/Bulk", nil)
	req.Host = "example.com"

	t.Run("PUT without data returns 400 invalidSyntax and still includes location", func(t *testing.T) {
		res := bh.processOperation(req, map[string]any{
			"method": "PUT",
			"path":   "/Users/" + uid.String(),
		}, uuid.New(), map[string]string{})
		if res["status"] != "400" {
			t.Fatalf("status = %v, want 400", res["status"])
		}
		if res["location"] == nil || res["location"] == "" {
			t.Fatalf("expected non-empty location on PUT failure, got %v", res["location"])
		}
		errMap, _ := res["response"].(map[string]any)
		if errMap["scimType"] != "invalidSyntax" {
			t.Fatalf("scimType = %v, want invalidSyntax", errMap["scimType"])
		}
	})

	t.Run("forward bulkId dependency reorders producer ahead of consumer", func(t *testing.T) {
		ops := []map[string]any{
			{"method": "POST", "path": "/Groups", "bulkId": "g1", "data": map[string]any{"members": []any{map[string]any{"value": "bulkId:u1"}}}},
			{"method": "POST", "path": "/Users", "bulkId": "u1", "data": map[string]any{"userName": "u1"}},
		}
		producers := map[string]int{"g1": 0, "u1": 1}
		order := computeBulkExecutionOrder(ops, producers)
		if len(order) != 2 || order[0] != 1 || order[1] != 0 {
			t.Fatalf("computeBulkExecutionOrder = %v, want [1 0]", order)
		}
	})

	t.Run("circular bulkId dependency schedules cleanly without deadlock", func(t *testing.T) {
		ops := []map[string]any{
			{"method": "POST", "path": "/Groups", "bulkId": "qwerty", "data": map[string]any{"members": []any{map[string]any{"value": "bulkId:ytrewq"}}}},
			{"method": "POST", "path": "/Groups", "bulkId": "ytrewq", "data": map[string]any{"members": []any{map[string]any{"value": "bulkId:qwerty"}}}},
		}
		producers := map[string]int{"qwerty": 0, "ytrewq": 1}
		order := computeBulkExecutionOrder(ops, producers)
		if len(order) != 2 || order[0] != 0 || order[1] != 1 {
			t.Fatalf("computeBulkExecutionOrder = %v, want [0 1]", order)
		}
	})

	t.Run("same-resource operations preserve client order when first op waits on forward bulkId", func(t *testing.T) {
		gid := uuid.New().String()
		ops := []map[string]any{
			{"method": "PATCH", "path": "/Groups/" + gid, "data": map[string]any{"Operations": []any{map[string]any{"op": "add", "path": "members", "value": []any{map[string]any{"value": "bulkId:u1"}}}}}},
			{"method": "DELETE", "path": "/Groups/" + gid},
			{"method": "POST", "path": "/Users", "bulkId": "u1", "data": map[string]any{"userName": "u1"}},
		}
		producers := map[string]int{"u1": 2}
		order := computeBulkExecutionOrder(ops, producers)
		if len(order) != 3 || order[0] != 2 || order[1] != 0 || order[2] != 1 {
			t.Fatalf("computeBulkExecutionOrder = %v, want [2 0 1]", order)
		}
	})

	t.Run("resolveBulkIdReferences avoids prefix collision and resolves filter paths", func(t *testing.T) {
		m := map[string]string{
			"u1":  "11111111-1111-1111-1111-111111111111",
			"u10": "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
		}
		if got := resolveBulkIdReferences("/Users/bulkId:u10", m); got != "/Users/aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa" {
			t.Fatalf("prefix collision in resolveBulkIdReferences: got %q", got)
		}
		if got := resolveBulkIdReferences(`members[value eq "bulkId:u1"]`, m); got != `members[value eq "11111111-1111-1111-1111-111111111111"]` {
			t.Fatalf("embedded filter bulkId failed to resolve: got %q", got)
		}
	})

	t.Run("entire POST cycle is scheduled before dependent PUT PATCH DELETE", func(t *testing.T) {
		ops := []map[string]any{
			{"method": "POST", "path": "/Groups", "bulkId": "g1", "data": map[string]any{"members": []any{map[string]any{"value": "bulkId:g2"}}}},
			{"method": "PATCH", "path": "/Groups/bulkId:g1", "data": map[string]any{"Operations": []any{}}},
			{"method": "POST", "path": "/Groups", "bulkId": "g2", "data": map[string]any{"members": []any{map[string]any{"value": "bulkId:g1"}}}},
			{"method": "DELETE", "path": "/Groups/bulkId:g1"},
		}
		producers := map[string]int{"g1": 0, "g2": 2}
		order := computeBulkExecutionOrder(ops, producers)
		// Both POST g1 (0) and POST g2 (2) must execute before PATCH (1) and DELETE (3)
		if len(order) != 4 || order[0] != 0 || order[1] != 2 || order[2] != 1 || order[3] != 3 {
			t.Fatalf("computeBulkExecutionOrder = %v, want [0 2 1 3]", order)
		}
	})
}

func TestBulk_MaxBytesReader_ChunkedAndKnownContentLengthExceedingLimitReturn413(t *testing.T) {
	bh := &BulkHandler{}
	wsID := uuid.New()

	oversized := `{"schemas":["urn:ietf:params:scim:api:messages:2.0:BulkRequest"],"Operations":[{"data":"` +
		strings.Repeat("x", maxBulkPayloadBytes+1024) + `"}]}`

	for _, chunked := range []bool{false, true} {
		req := httptest.NewRequest(http.MethodPost, "/Bulk", bytes.NewBufferString(oversized))
		if chunked {
			req.ContentLength = -1 // Simulate chunked transfer encoding with unknown Content-Length
		}
		req = req.WithContext(context.WithValue(req.Context(), middleware.WorkspaceIDKey, wsID))

		rec := httptest.NewRecorder()
		bh.ProcessBulk(rec, req)

		if rec.Code != http.StatusRequestEntityTooLarge {
			t.Fatalf("chunked=%v: status = %d, want 413 Request Entity Too Large", chunked, rec.Code)
		}
		if !strings.Contains(rec.Body.String(), "Bulk request exceeds maxPayloadSize (1048576 bytes)") {
			t.Fatalf("chunked=%v: unexpected 413 detail: %s", chunked, rec.Body.String())
		}
	}
}

func TestBulk_DeferredFixupRollback_RemovesBulkIdAndCountsErrors(t *testing.T) {
	bh := &BulkHandler{
		userHandler:  &UserHandler{},
		groupHandler: &GroupHandler{},
	}
	wsID := uuid.New()
	req := httptest.NewRequest(http.MethodPost, "https://example.com/ws/"+wsID.String()+"/scim/v2/Bulk", nil)

	g1ID := uuid.New()
	g2ID := uuid.New()
	bulkIdMap := map[string]string{
		"g1": g1ID.String(),
		"g2": g2ID.String(),
	}
	indexedResults := []map[string]any{
		{"method": "POST", "bulkId": "g1", "status": "201", "location": "https://example.com/Groups/" + g1ID.String(), "version": `W/"0"`},
		{"method": "POST", "bulkId": "g2", "status": "201", "location": "https://example.com/Groups/" + g2ID.String(), "version": `W/"0"`},
	}
	createdPosts := map[int]*createdPostRecord{
		0: {origIdx: 0, resourceType: bulkResourceGroups, resourceID: g1ID, bulkID: "g1", depBulkIDs: []string{"bad"}},
		1: {origIdx: 1, resourceType: bulkResourceGroups, resourceID: g2ID, bulkID: "g2", depBulkIDs: []string{"g1"}},
	}
	fixups := []deferredBulkFixup{
		{
			kind:            bulkFixupGroupMembers,
			origIdx:         0,
			resourceID:      g1ID,
			bulkID:          "g1",
			deferredMembers: []map[string]any{{"value": "bulkId:bad"}},
		},
	}

	rolledBack := make(map[string]bool)
	rollbackErrors := bh.applyDeferredBulkFixups(req, wsID, "https://example.com", bulkIdMap, indexedResults, fixups, createdPosts, rolledBack)

	// Both g1 (direct fixup failure) and g2 (cascade dependency on g1) must be rolled back
	if rollbackErrors != 2 {
		t.Fatalf("rollbackErrors = %d, want 2", rollbackErrors)
	}
	if _, exists := bulkIdMap["g1"]; exists {
		t.Fatal("expected g1 to be removed from bulkIdMap after rollback")
	}
	if _, exists := bulkIdMap["g2"]; exists {
		t.Fatal("expected g2 to be removed from bulkIdMap after cascade rollback")
	}
	if indexedResults[0]["status"] != "400" || indexedResults[1]["status"] != "400" {
		t.Fatalf("expected both POST operations to have status 400 after rollback, got %v and %v",
			indexedResults[0]["status"], indexedResults[1]["status"])
	}
	var _ *model.ScimGroup
}


