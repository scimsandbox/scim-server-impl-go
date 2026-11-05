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

// Traced RFC requirements (Group 2):
//   - RFC7643-7-031493: Immutable attribute SHALL NOT be updated.
//   - RFC7644-3.5.2-0cc87d: On PATCH, client MAY add a value to an immutable attribute if it had no previous value.
func TestGroupPatchImmutableSubAttributes_Group2(t *testing.T) {
	gh := &GroupHandler{}
	wsID := uuid.New()
	memberUnset := uuid.New()
	memberTyped := uuid.New()
	userType := "User"

	group := &model.ScimGroup{
		ID:          uuid.New(),
		WorkspaceID: wsID,
		DisplayName: "ImmutableTestGroup",
		Members: []model.ScimGroupMembership{
			{MemberValue: memberUnset, MemberType: nil},
			{MemberValue: memberTyped, MemberType: &userType},
		},
	}

	// 1. replace or remove targeting .type, .value, or .$ref -> 400 mutability
	for _, op := range []string{"replace", "remove"} {
		for _, sub := range []string{".type", ".value", ".$ref"} {
			opMap := map[string]any{
				"op":   op,
				"path": `members[value eq "` + memberTyped.String() + `"]` + sub,
			}
			if op == "replace" {
				opMap["value"] = "Group"
			}
			err := gh.applyGroupPatchOp(context.Background(), group, wsID, opMap)
			scimErr, ok := err.(*scim.ScimError)
			if !ok || scimErr.Status != http.StatusBadRequest || scimErr.ScimType != "mutability" {
				t.Fatalf("PATCH %s %s: got %v, want 400 mutability", op, sub, err)
			}
		}
	}

	// 2. add targeting .value or .$ref on existing member -> 400 mutability
	for _, sub := range []string{".value", ".$ref"} {
		err := gh.applyGroupPatchOp(context.Background(), group, wsID, map[string]any{
			"op":    "add",
			"path":  `members[value eq "` + memberTyped.String() + `"]` + sub,
			"value": "anything",
		})
		scimErr, ok := err.(*scim.ScimError)
		if !ok || scimErr.Status != http.StatusBadRequest || scimErr.ScimType != "mutability" {
			t.Fatalf("PATCH add %s: got %v, want 400 mutability", sub, err)
		}
	}

	// 3. RFC7644-3.5.2-0cc87d: add targeting .type when member had NO previous type -> succeeds and sets type
	if err := gh.applyGroupPatchOp(context.Background(), group, wsID, map[string]any{
		"op":    "add",
		"path":  `members[value eq "` + memberUnset.String() + `"].type`,
		"value": "User",
	}); err != nil {
		t.Fatalf("PATCH add .type on untyped member failed: %v", err)
	}
	if group.Members[0].MemberType == nil || *group.Members[0].MemberType != "User" {
		t.Fatalf("MemberType = %v, want 'User'", group.Members[0].MemberType)
	}

	// 4. Subsequent add targeting .type with a DIFFERENT value -> 400 mutability
	err := gh.applyGroupPatchOp(context.Background(), group, wsID, map[string]any{
		"op":    "add",
		"path":  `members[value eq "` + memberUnset.String() + `"].type`,
		"value": "Group",
	})
	scimErr, ok := err.(*scim.ScimError)
	if !ok || scimErr.Status != http.StatusBadRequest || scimErr.ScimType != "mutability" {
		t.Fatalf("PATCH add conflicting .type on already-typed member: got %v, want 400 mutability", err)
	}

	// 5. Empty-string MemberType (matching DB VARCHAR NOT NULL unset state) + $ref valuePath add .type
	emptyType := ""
	memberEmptyType := uuid.New()
	group.Members = append(group.Members, model.ScimGroupMembership{
		MemberValue: memberEmptyType,
		MemberType:  &emptyType,
	})
	if err := gh.applyGroupPatchOp(context.Background(), group, wsID, map[string]any{
		"op":    "add",
		"path":  `members[$ref eq "/Users/` + memberEmptyType.String() + `"].type`,
		"value": "User",
	}); err != nil {
		t.Fatalf("PATCH add .type via $ref valuePath on empty-string member_type failed: %v", err)
	}
	if group.Members[2].MemberType == nil || *group.Members[2].MemberType != "User" {
		t.Fatalf("MemberType = %v, want 'User'", group.Members[2].MemberType)
	}
}

func TestGroupMemberVersionAgnosticRefHelpers_RFC7643_2_4(t *testing.T) {
	u1 := uuid.New()
	u2 := uuid.New()

	// 1. resolveMemberID across value, unversioned $ref, and v1 $ref
	for _, m := range []map[string]any{
		{"value": u1.String()},
		{"$ref": "/Users/" + u1.String()},
		{"$ref": "https://legacy.idp.example/scim/v1/Users/" + u1.String()},
	} {
		if got := resolveMemberID(m); got != u1.String() {
			t.Fatalf("resolveMemberID(%v) = %q, want %q", m, got, u1.String())
		}
	}

	// 2. checkMemberValueRefConflict rejects mismatched UUIDs and accepts matching ones
	if err := checkMemberValueRefConflict(map[string]any{
		"value": u1.String(),
		"$ref":  "https://legacy.idp.example/scim/v1/Users/" + u1.String(),
	}); err != nil {
		t.Fatalf("unexpected error for matching value and $ref: %v", err)
	}
	if err := checkMemberValueRefConflict(map[string]any{
		"value": u1.String(),
		"$ref":  "/Users/" + u2.String(),
	}); err == nil {
		t.Fatal("expected 400 invalidValue for conflicting member value and $ref")
	}

	// 3. validateMemberTypeImmutability enforces type immutability even when member is referenced by $ref only
	userType := "User"
	existing := []model.ScimGroupMembership{{MemberValue: u1, MemberType: &userType}}
	if err := validateMemberTypeImmutability(existing, []any{
		map[string]any{"$ref": "/Users/" + u1.String(), "type": "Group"},
	}); err == nil {
		t.Fatal("expected mutability error when changing type via $ref-only member entry")
	}

	// 4. PATCH remove via unversioned $ref valuePath and v1 $ref list
	gh := &GroupHandler{}
	wsID := uuid.New()
	group := &model.ScimGroup{
		ID:          uuid.New(),
		WorkspaceID: wsID,
		DisplayName: "RefRemoveTestGroup",
		Members: []model.ScimGroupMembership{
			{MemberValue: u1, MemberType: &userType},
			{MemberValue: u2, MemberType: &userType},
		},
	}
	if err := gh.applyGroupPatchOp(context.Background(), group, wsID, map[string]any{
		"op":   "remove",
		"path": `members[$ref eq "/Users/` + u1.String() + `"]`,
	}); err != nil {
		t.Fatalf("PATCH remove via unversioned $ref valuePath failed: %v", err)
	}
	if len(group.Members) != 1 || group.Members[0].MemberValue != u2 {
		t.Fatalf("expected only u2 remaining, got %+v", group.Members)
	}
	if err := gh.applyGroupPatchOp(context.Background(), group, wsID, map[string]any{
		"op":    "remove",
		"path":  "members",
		"value": []any{map[string]any{"$ref": "https://legacy.idp.example/scim/v1/Users/" + u2.String()}},
	}); err != nil {
		t.Fatalf("PATCH remove via v1 $ref list failed: %v", err)
	}
	if len(group.Members) != 0 {
		t.Fatalf("expected 0 members remaining, got %+v", group.Members)
	}
}
