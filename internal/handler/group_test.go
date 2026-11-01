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
	"github.com/scimsandbox/scim-server-impl-go/internal/model"
	"github.com/scimsandbox/scim-server-impl-go/internal/scim"
)

func TestGroupHandler_ListGroups_MissingWorkspace(t *testing.T) {
	gh := &GroupHandler{}
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/Groups", nil)

	gh.ListGroups(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", rec.Code)
	}
}

func TestGroupHandler_ListGroups_MutualExclusion(t *testing.T) {
	gh := &GroupHandler{}
	rec := httptest.NewRecorder()
	wsID := uuid.New()
	req := httptest.NewRequest(http.MethodGet, "/Groups?cursor=&startIndex=1", nil)
	req = req.WithContext(context.WithValue(req.Context(), middleware.WorkspaceIDKey, wsID))

	gh.ListGroups(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}

	var resp map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to unmarshal JSON: %v", err)
	}
	if resp["scimType"] != "invalidValue" && resp["scimType"] != "invalidCursor" {
		t.Errorf("scimType = %v, want invalidValue or invalidCursor", resp["scimType"])
	}
}

func TestGroupHandler_ListGroups_InvalidCursor(t *testing.T) {
	gh := &GroupHandler{}
	rec := httptest.NewRecorder()
	wsID := uuid.New()
	req := httptest.NewRequest(http.MethodGet, "/Groups?cursor=invalid-opaque-cursor-999", nil)
	req = req.WithContext(context.WithValue(req.Context(), middleware.WorkspaceIDKey, wsID))

	gh.ListGroups(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}

	var resp map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to unmarshal JSON: %v", err)
	}
	if resp["scimType"] != "invalidCursor" {
		t.Errorf("scimType = %v, want invalidCursor", resp["scimType"])
	}
}

func TestGroupHandler_ListGroups_WorkspaceMismatch(t *testing.T) {
	gh := &GroupHandler{}
	rec := httptest.NewRecorder()
	wsA := uuid.New()
	wsB := uuid.New()

	token, err := scim.EncodeCursor(wsA, 10, 3600)
	if err != nil {
		t.Fatalf("failed to encode cursor: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/Groups?cursor="+token, nil)
	req = req.WithContext(context.WithValue(req.Context(), middleware.WorkspaceIDKey, wsB))

	gh.ListGroups(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}

	var resp map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to unmarshal JSON: %v", err)
	}
	if resp["scimType"] != "invalidCursor" {
		t.Errorf("scimType = %v, want invalidCursor", resp["scimType"])
	}
}

func TestGroupHandler_SearchGroups_MutualExclusion(t *testing.T) {
	gh := &GroupHandler{}
	rec := httptest.NewRecorder()
	wsID := uuid.New()
	body := `{"schemas":["urn:ietf:params:scim:api:messages:2.0:SearchRequest"],"cursor":"","startIndex":1}`
	req := httptest.NewRequest(http.MethodPost, "/Groups/.search", strings.NewReader(body))
	req = req.WithContext(context.WithValue(req.Context(), middleware.WorkspaceIDKey, wsID))

	gh.SearchGroups(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}

	var resp map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to unmarshal JSON: %v", err)
	}
	if resp["scimType"] != "invalidValue" && resp["scimType"] != "invalidCursor" {
		t.Errorf("scimType = %v, want invalidValue or invalidCursor", resp["scimType"])
	}
}

func TestGroupHandler_SearchGroups_InvalidCursor(t *testing.T) {
	gh := &GroupHandler{}
	rec := httptest.NewRecorder()
	wsID := uuid.New()
	body := `{"schemas":["urn:ietf:params:scim:api:messages:2.0:SearchRequest"],"cursor":"bad-cursor"}`
	req := httptest.NewRequest(http.MethodPost, "/Groups/.search", strings.NewReader(body))
	req = req.WithContext(context.WithValue(req.Context(), middleware.WorkspaceIDKey, wsID))

	gh.SearchGroups(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}

	var resp map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to unmarshal JSON: %v", err)
	}
	if resp["scimType"] != "invalidCursor" {
		t.Errorf("scimType = %v, want invalidCursor", resp["scimType"])
	}
}

func TestGroupHandler_SearchGroups_NonStringCursor(t *testing.T) {
	gh := &GroupHandler{}
	rec := httptest.NewRecorder()
	wsID := uuid.New()
	body := `{"schemas":["urn:ietf:params:scim:api:messages:2.0:SearchRequest"],"cursor":false}`
	req := httptest.NewRequest(http.MethodPost, "/Groups/.search", strings.NewReader(body))
	req = req.WithContext(context.WithValue(req.Context(), middleware.WorkspaceIDKey, wsID))

	gh.SearchGroups(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}

	var resp map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to unmarshal JSON: %v", err)
	}
	if resp["scimType"] != "invalidCursor" {
		t.Errorf("scimType = %v, want invalidCursor", resp["scimType"])
	}
}

func TestValidateMemberTypeImmutability_GRP21(t *testing.T) {
	userType := "User"
	groupType := "Group"
	memberA := uuid.New()
	memberB := uuid.New()
	memberNew := uuid.New()

	existing := []model.ScimGroupMembership{
		{MemberValue: memberA, MemberType: &userType},
		{MemberValue: memberB, MemberType: &groupType},
	}

	t.Run("changing User member type to Group returns 400 mutability ([]any input)", func(t *testing.T) {
		rawMembers := []any{
			map[string]any{"value": memberA.String(), "type": "Group"},
		}
		err := validateMemberTypeImmutability(existing, rawMembers)
		if err == nil {
			t.Fatal("expected mutability error when changing member type from User to Group")
		}
		scimErr, ok := err.(*scim.ScimError)
		if !ok {
			t.Fatalf("expected *scim.ScimError, got %T: %v", err, err)
		}
		if scimErr.Status != http.StatusBadRequest || scimErr.ScimType != "mutability" {
			t.Fatalf("status=%d scimType=%q, want 400 mutability", scimErr.Status, scimErr.ScimType)
		}
	})

	t.Run("changing Group member type to User returns 400 mutability ([]map[string]any input)", func(t *testing.T) {
		rawMembers := []map[string]any{
			{"value": memberB.String(), "type": "User"},
		}
		err := validateMemberTypeImmutability(existing, rawMembers)
		if err == nil {
			t.Fatal("expected mutability error when changing member type from Group to User")
		}
		scimErr, ok := err.(*scim.ScimError)
		if !ok {
			t.Fatalf("expected *scim.ScimError, got %T: %v", err, err)
		}
		if scimErr.Status != http.StatusBadRequest || scimErr.ScimType != "mutability" {
			t.Fatalf("status=%d scimType=%q, want 400 mutability", scimErr.Status, scimErr.ScimType)
		}
	})

	t.Run("preserving member type (case-insensitive) or omitting type succeeds", func(t *testing.T) {
		rawMembers := []any{
			map[string]any{"value": memberA.String(), "type": "user"},
			map[string]any{"value": memberB.String()},
			map[string]any{"value": memberNew.String(), "type": "Group"},
		}
		if err := validateMemberTypeImmutability(existing, rawMembers); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})
}
