package handler

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/scimsandbox/scim-server-impl-go/internal/jdbc"
	"github.com/scimsandbox/scim-server-impl-go/internal/middleware"
	"github.com/scimsandbox/scim-server-impl-go/internal/model"
	"github.com/scimsandbox/scim-server-impl-go/internal/repository"
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
			err := gh.applyGroupPatchOpTx(context.Background(), nil, group, wsID, opMap)
			scimErr, ok := err.(*scim.ScimError)
			if !ok || scimErr.Status != http.StatusBadRequest || scimErr.ScimType != "mutability" {
				t.Fatalf("PATCH %s %s: got %v, want 400 mutability", op, sub, err)
			}
		}
	}

	// 2. add targeting .value or .$ref on existing member -> 400 mutability
	for _, sub := range []string{".value", ".$ref"} {
		err := gh.applyGroupPatchOpTx(context.Background(), nil, group, wsID, map[string]any{
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
	if err := gh.applyGroupPatchOpTx(context.Background(), nil, group, wsID, map[string]any{
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
	err := gh.applyGroupPatchOpTx(context.Background(), nil, group, wsID, map[string]any{
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
	if err := gh.applyGroupPatchOpTx(context.Background(), nil, group, wsID, map[string]any{
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
	if err := gh.applyGroupPatchOpTx(context.Background(), nil, group, wsID, map[string]any{
		"op":   "remove",
		"path": `members[$ref eq "/Users/` + u1.String() + `"]`,
	}); err != nil {
		t.Fatalf("PATCH remove via unversioned $ref valuePath failed: %v", err)
	}
	if len(group.Members) != 1 || group.Members[0].MemberValue != u2 {
		t.Fatalf("expected only u2 remaining, got %+v", group.Members)
	}
	if err := gh.applyGroupPatchOpTx(context.Background(), nil, group, wsID, map[string]any{
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

func TestResolveMemberID_CanonicalizesUUIDAndHandlesEdgeCases(t *testing.T) {
	t.Parallel()

	u := uuid.New()
	upper := strings.ToUpper(u.String())

	if got := resolveMemberID(nil); got != "" {
		t.Fatalf("resolveMemberID(nil) = %q, want empty", got)
	}
	if got := resolveMemberID(map[string]any{}); got != "" {
		t.Fatalf("resolveMemberID({}) = %q, want empty", got)
	}
	if got := resolveMemberID(map[string]any{"value": "  " + upper + "  "}); got != u.String() {
		t.Fatalf("resolveMemberID(uppercase value) = %q, want %q", got, u.String())
	}
	if got := resolveMemberID(map[string]any{"$ref": "https://example.com/scim/v2/Users/" + upper}); got != u.String() {
		t.Fatalf("resolveMemberID(uppercase $ref) = %q, want %q", got, u.String())
	}
	if got := resolveMemberID(map[string]any{"value": "  not-a-uuid  "}); got != "not-a-uuid" {
		t.Fatalf("resolveMemberID(non-UUID) = %q, want %q", got, "not-a-uuid")
	}
}

func TestAddMemberTx_RejectsSelfMembershipAndInvalidMemberIDs(t *testing.T) {
	t.Parallel()

	gh := &GroupHandler{}
	wsID := uuid.New()
	groupID := uuid.New()
	upperGroupID := strings.ToUpper(groupID.String())

	selfCases := []struct {
		name      string
		memberMap map[string]any
	}{
		{
			name:      "self-membership via lowercase value",
			memberMap: map[string]any{"value": groupID.String()},
		},
		{
			name:      "self-membership via uppercase value",
			memberMap: map[string]any{"value": upperGroupID},
		},
		{
			name:      "self-membership via relative $ref",
			memberMap: map[string]any{"$ref": "/Groups/" + groupID.String()},
		},
		{
			name:      "self-membership via absolute uppercase $ref",
			memberMap: map[string]any{"$ref": "https://example.com/scim/v2/Groups/" + upperGroupID},
		},
	}

	for _, tc := range selfCases {
		t.Run(tc.name, func(t *testing.T) {
			err := gh.addMemberTx(context.Background(), nil, groupID, wsID, tc.memberMap)
			scimErr, ok := err.(*scim.ScimError)
			if !ok || scimErr.Status != http.StatusBadRequest || scimErr.ScimType != "invalidValue" {
				t.Fatalf("%s: got %T %v, want 400 invalidValue", tc.name, err, err)
			}
			if !strings.Contains(scimErr.Detail, "itself") {
				t.Fatalf("%s: detail = %q, want self-membership message", tc.name, scimErr.Detail)
			}
		})
	}

	for _, invalid := range []map[string]any{
		{},
		{"value": "not-a-uuid"},
		{"value": uuid.New().String(), "$ref": "/Groups/" + uuid.New().String()},
	} {
		err := gh.addMemberTx(context.Background(), nil, groupID, wsID, invalid)
		scimErr, ok := err.(*scim.ScimError)
		if !ok || scimErr.Status != http.StatusBadRequest || scimErr.ScimType != "invalidValue" {
			t.Fatalf("addMemberTx(%v) = %T %v, want 400 invalidValue", invalid, err, err)
		}
	}
}

func TestApplyMemberSubAttrAdd_RejectsSelfMembershipWithoutMutatingGroup(t *testing.T) {
	t.Parallel()

	gh := &GroupHandler{}
	wsID := uuid.New()
	groupID := uuid.New()

	// When targetUUID == group.ID is NOT a member of group, applyMemberSubAttrAdd MUST return 400 noTarget (not invalidValue).
	emptyGroup := &model.ScimGroup{
		ID:          groupID,
		WorkspaceID: wsID,
		DisplayName: "Empty Group",
	}
	errNoTarget := gh.applyMemberSubAttrAdd(context.Background(), nil, emptyGroup, wsID, `members[value eq "`+groupID.String()+`"].type`, "Group")
	scimNoTarget, ok := errNoTarget.(*scim.ScimError)
	if !ok || scimNoTarget.Status != http.StatusBadRequest || scimNoTarget.ScimType != "noTarget" {
		t.Fatalf("applyMemberSubAttrAdd(non-existent self member) = %T %v, want 400 noTarget", errNoTarget, errNoTarget)
	}

	group := &model.ScimGroup{
		ID:          groupID,
		WorkspaceID: wsID,
		DisplayName: "Self SubAttr Test",
		Members: []model.ScimGroupMembership{
			{MemberValue: groupID, MemberType: nil},
		},
	}

	for _, path := range []string{
		`members[value eq "` + groupID.String() + `"].type`,
		`members[$ref eq "/Groups/` + strings.ToUpper(groupID.String()) + `"].type`,
	} {
		err := gh.applyMemberSubAttrAdd(context.Background(), nil, group, wsID, path, "Group")
		scimErr, ok := err.(*scim.ScimError)
		if !ok || scimErr.Status != http.StatusBadRequest || scimErr.ScimType != "invalidValue" {
			t.Fatalf("applyMemberSubAttrAdd(%s) = %T %v, want 400 invalidValue", path, err, err)
		}
		if scimErr.Detail != "Group cannot include itself as a member" {
			t.Fatalf("detail = %q, want %q", scimErr.Detail, "Group cannot include itself as a member")
		}
		if group.Members[0].MemberType != nil {
			t.Fatalf("expected group.Members not to be mutated in memory, got MemberType=%v", *group.Members[0].MemberType)
		}
	}
}

type inMemoryGroupGraphExecutor struct {
	wsID   uuid.UUID
	groups map[uuid.UUID]*model.ScimGroup
	edges  map[uuid.UUID][]model.ScimGroupMembership
}

type graphExecutorRow struct {
	scanFn func(dest ...any) error
}

func (r graphExecutorRow) Scan(dest ...any) error {
	return r.scanFn(dest...)
}

func (g *inMemoryGroupGraphExecutor) ExecContext(_ context.Context, query string, args ...any) (jdbc.Result, error) {
	switch {
	case strings.Contains(query, "INSERT INTO scim_group_memberships"):
		id := args[0].(uuid.UUID)
		groupID := args[1].(uuid.UUID)
		wsID := args[2].(uuid.UUID)
		memberValue := args[3].(uuid.UUID)
		memberType, _ := args[4].(*string)
		display, _ := args[5].(*string)
		g.edges[groupID] = append(g.edges[groupID], model.ScimGroupMembership{
			ID:          id,
			GroupID:     groupID,
			WorkspaceID: wsID,
			MemberValue: memberValue,
			MemberType:  memberType,
			Display:     display,
		})
	case strings.Contains(query, "UPDATE scim_group_memberships SET member_type"):
		newType := args[0].(string)
		membershipID := args[1].(uuid.UUID)
		for gid := range g.edges {
			for idx := range g.edges[gid] {
				if g.edges[gid][idx].ID == membershipID {
					tCopy := newType
					g.edges[gid][idx].MemberType = &tCopy
				}
			}
		}
	}
	return nil, nil
}

func (g *inMemoryGroupGraphExecutor) QueryContext(_ context.Context, _ string, _ ...any) (jdbc.Rows, error) {
	return nil, nil
}

func (g *inMemoryGroupGraphExecutor) isReachable(wsID, startGroupID, targetGroupID uuid.UUID) bool {
	visited := make(map[uuid.UUID]bool)
	queue := []uuid.UUID{startGroupID}
	for len(queue) > 0 {
		curr := queue[0]
		queue = queue[1:]
		for _, m := range g.edges[curr] {
			if m.WorkspaceID != wsID {
				continue
			}
			mType := ""
			if m.MemberType != nil {
				mType = strings.TrimSpace(*m.MemberType)
			}
			isGroupEdge := strings.EqualFold(mType, "group") || (mType == "" && g.groups[m.MemberValue] != nil && g.groups[m.MemberValue].WorkspaceID == wsID)
			if !isGroupEdge {
				continue
			}
			if m.MemberValue == targetGroupID {
				return true
			}
			if !visited[m.MemberValue] {
				visited[m.MemberValue] = true
				queue = append(queue, m.MemberValue)
			}
		}
	}
	return false
}

func (g *inMemoryGroupGraphExecutor) QueryRowContext(_ context.Context, query string, args ...any) jdbc.Row {
	switch {
	case strings.Contains(query, "WITH RECURSIVE reachable"):
		wsID := args[0].(uuid.UUID)
		candID := args[1].(uuid.UUID)
		groupID := args[2].(uuid.UUID)
		reachable := g.isReachable(wsID, candID, groupID)
		return graphExecutorRow{scanFn: func(dest ...any) error {
			*(dest[0].(*bool)) = reachable
			return nil
		}}
	case strings.Contains(query, "FROM scim_groups WHERE id = $1 AND workspace_id = $2"):
		id := args[0].(uuid.UUID)
		wsID := args[1].(uuid.UUID)
		grp := g.groups[id]
		if grp == nil || grp.WorkspaceID != wsID {
			return graphExecutorRow{scanFn: func(_ ...any) error { return jdbc.ErrNoRows }}
		}
		return graphExecutorRow{scanFn: func(dest ...any) error {
			*(dest[0].(*uuid.UUID)) = grp.ID
			*(dest[1].(*uuid.UUID)) = grp.WorkspaceID
			*(dest[2].(**string)) = grp.ExternalID
			*(dest[3].(*string)) = grp.DisplayName
			*(dest[4].(*time.Time)) = grp.CreatedAt
			*(dest[5].(*time.Time)) = grp.LastModified
			*(dest[6].(*int64)) = grp.Version
			return nil
		}}
	default:
		// scim_users lookup returns ErrNoRows when member is a Group.
		return graphExecutorRow{scanFn: func(_ ...any) error { return jdbc.ErrNoRows }}
	}
}

func TestGroupHandler_TransitiveCycleDetectionAndDiamondDAG(t *testing.T) {
	t.Parallel()

	wsID := uuid.New()
	now := time.Now().UTC()
	mkGroup := func(name string) *model.ScimGroup {
		return &model.ScimGroup{
			ID:           uuid.New(),
			WorkspaceID:  wsID,
			DisplayName:  name,
			CreatedAt:    now,
			LastModified: now,
		}
	}

	groupA := mkGroup("Group A")
	groupB := mkGroup("Group B")
	groupC := mkGroup("Group C")
	groupD := mkGroup("Group D")

	exec := &inMemoryGroupGraphExecutor{
		wsID: wsID,
		groups: map[uuid.UUID]*model.ScimGroup{
			groupA.ID: groupA,
			groupB.ID: groupB,
			groupC.ID: groupC,
			groupD.ID: groupD,
		},
		edges: make(map[uuid.UUID][]model.ScimGroupMembership),
	}

	gh := &GroupHandler{
		userRepo:       repository.NewUserRepository(),
		groupRepo:      repository.NewGroupRepository(),
		membershipRepo: repository.NewMembershipRepository(),
	}

	// 1. Direct self-membership (A -> A) rejected with 400 invalidValue.
	if err := gh.addMemberTx(context.Background(), exec, groupA.ID, wsID, map[string]any{"value": groupA.ID.String(), "type": "Group"}); err == nil {
		t.Fatal("expected self-membership A -> A to fail")
	}

	// 2. Build chain A -> B -> C (with B -> C added without explicit "type" to verify untyped group inference & cycle detection).
	if err := gh.addMemberTx(context.Background(), exec, groupA.ID, wsID, map[string]any{"value": groupB.ID.String(), "type": "Group"}); err != nil {
		t.Fatalf("addMemberTx(A -> B) error = %v", err)
	}
	if err := gh.addMemberTx(context.Background(), exec, groupB.ID, wsID, map[string]any{"value": groupC.ID.String()}); err != nil {
		t.Fatalf("addMemberTx(B -> C untyped) error = %v", err)
	}

	// 3. 2-hop cycle (B -> A) rejected with 400 invalidValue.
	errBA := gh.addMemberTx(context.Background(), exec, groupB.ID, wsID, map[string]any{"value": groupA.ID.String(), "type": "Group"})
	scimBA, ok := errBA.(*scim.ScimError)
	if !ok || scimBA.Status != http.StatusBadRequest || scimBA.ScimType != "invalidValue" {
		t.Fatalf("2-hop cycle B -> A got %T %v, want 400 invalidValue", errBA, errBA)
	}

	// 4. 3-hop cycle (C -> A, both typed and untyped) rejected with 400 invalidValue.
	for _, m := range []map[string]any{
		{"value": groupA.ID.String(), "type": "Group"},
		{"value": groupA.ID.String()},
	} {
		errCA := gh.addMemberTx(context.Background(), exec, groupC.ID, wsID, m)
		scimCA, ok := errCA.(*scim.ScimError)
		if !ok || scimCA.Status != http.StatusBadRequest || scimCA.ScimType != "invalidValue" {
			t.Fatalf("3-hop cycle C -> A (%v) got %T %v, want 400 invalidValue", m, errCA, errCA)
		}
	}

	// 5. Diamond DAG (A -> B, A -> C, B -> D, C -> D) MUST be allowed!
	if err := gh.addMemberTx(context.Background(), exec, groupA.ID, wsID, map[string]any{"value": groupC.ID.String(), "type": "Group"}); err != nil {
		t.Fatalf("diamond DAG A -> C error = %v", err)
	}
	if err := gh.addMemberTx(context.Background(), exec, groupB.ID, wsID, map[string]any{"value": groupD.ID.String(), "type": "Group"}); err != nil {
		t.Fatalf("diamond DAG B -> D error = %v", err)
	}
	if err := gh.addMemberTx(context.Background(), exec, groupC.ID, wsID, map[string]any{"value": groupD.ID.String(), "type": "Group"}); err != nil {
		t.Fatalf("diamond DAG C -> D error = %v", err)
	}

	// Adding D -> A at the bottom of the diamond DAG creates a 3-hop cycle and MUST be rejected!
	errDA := gh.addMemberTx(context.Background(), exec, groupD.ID, wsID, map[string]any{"value": groupA.ID.String(), "type": "Group"})
	if scimDA, ok := errDA.(*scim.ScimError); !ok || scimDA.Status != http.StatusBadRequest || scimDA.ScimType != "invalidValue" {
		t.Fatalf("diamond cycle D -> A got %T %v, want 400 invalidValue", errDA, errDA)
	}

	// 6. applyMemberSubAttrAdd retyping a legacy untyped member (D -> A) to "Group" rejects the indirect cycle without mutating groupD.Members!
	groupDWithLegacyMember := &model.ScimGroup{
		ID:          groupD.ID,
		WorkspaceID: wsID,
		DisplayName: "Group D",
		Members: []model.ScimGroupMembership{
			{ID: uuid.New(), GroupID: groupD.ID, WorkspaceID: wsID, MemberValue: groupA.ID, MemberType: nil},
		},
	}
	errSubAttrCycle := gh.applyMemberSubAttrAdd(
		context.Background(),
		exec,
		groupDWithLegacyMember,
		wsID,
		`members[value eq "`+groupA.ID.String()+`"].type`,
		"Group",
	)
	scimSubAttr, ok := errSubAttrCycle.(*scim.ScimError)
	if !ok || scimSubAttr.Status != http.StatusBadRequest || scimSubAttr.ScimType != "invalidValue" {
		t.Fatalf("applyMemberSubAttrAdd indirect cycle = %T %v, want 400 invalidValue", errSubAttrCycle, errSubAttrCycle)
	}
	if groupDWithLegacyMember.Members[0].MemberType != nil {
		t.Fatalf("expected groupD.Members[0].MemberType to remain nil on cycle error, got %v", *groupDWithLegacyMember.Members[0].MemberType)
	}
}

func TestGroupHandler_NormalizedGroupAndMemberKeys(t *testing.T) {
	t.Parallel()

	wsID := uuid.New()
	groupID := uuid.New()
	memberID := uuid.New()

	// 1. resolveMemberID and checkMemberValueRefConflict work with PascalCase/UPPERCASE member keys.
	if got := resolveMemberID(map[string]any{"Value": memberID.String(), "Type": "User"}); got != memberID.String() {
		t.Fatalf("resolveMemberID(Value) = %q, want %q", got, memberID.String())
	}
	if got := resolveMemberID(map[string]any{"$REF": "https://example.com/scim/v2/Users/" + memberID.String()}); got != memberID.String() {
		t.Fatalf("resolveMemberID($REF) = %q, want %q", got, memberID.String())
	}
	if err := checkMemberValueRefConflict(map[string]any{
		"Value": memberID.String(),
		"$REF":  "https://example.com/scim/v2/Users/" + uuid.New().String(),
	}); err == nil {
		t.Fatal("expected conflict error for mismatched Value and $REF")
	}

	// 2. CreateGroup & ReplaceGroup accept DisplayName and GroupSchemaURN:displayName past 400 validation.
	for _, payload := range []map[string]any{
		{"DisplayName": "Engineering", "ExternalId": "ext-eng"},
		{scim.GroupSchemaURN + ":displayName": "Engineering", scim.GroupSchemaURN + ":externalId": "ext-eng"},
		{scim.GroupSchemaURN: map[string]any{"displayName": "Engineering"}},
	} {
		gh := NewGroupHandler(nil, nil, nil, nil)
		rawBody, _ := json.Marshal(payload)

		recCreate := httptest.NewRecorder()
		reqCreate := httptest.NewRequest(http.MethodPost, "/Groups", strings.NewReader(string(rawBody)))
		reqCreate = reqCreate.WithContext(context.WithValue(reqCreate.Context(), middleware.WorkspaceIDKey, wsID))
		gh.CreateGroup(recCreate, reqCreate)
		if recCreate.Code != http.StatusInternalServerError {
			t.Fatalf("CreateGroup(%v) status = %d, want 500 (past 400 displayName validation); body=%s", payload, recCreate.Code, recCreate.Body.String())
		}

		recReplace := httptest.NewRecorder()
		reqReplace := httptest.NewRequest(http.MethodPut, "/Groups/"+groupID.String(), strings.NewReader(string(rawBody)))
		ctx := context.WithValue(reqReplace.Context(), middleware.WorkspaceIDKey, wsID)
		rctx := chi.NewRouteContext()
		rctx.URLParams.Add("workspaceId", wsID.String())
		rctx.URLParams.Add("id", groupID.String())
		reqReplace = reqReplace.WithContext(context.WithValue(ctx, chi.RouteCtxKey, rctx))
		gh.ReplaceGroup(recReplace, reqReplace)
		if recReplace.Code != http.StatusInternalServerError {
			t.Fatalf("ReplaceGroup(%v) status = %d, want 500 (past 400 displayName validation); body=%s", payload, recReplace.Code, recReplace.Body.String())
		}
	}

	// 3. PatchGroup normalizes Schemas / operations and rejects non-object operation before respond-async.
	asyncRepo := newMockAsyncEventRepo()
	gh := NewGroupHandler(nil, nil, nil, nil, asyncRepo)
	badPatch, _ := json.Marshal(map[string]any{
		"Schemas":    []string{"urn:ietf:params:scim:api:messages:2.0:PatchOp"},
		"operations": []any{"not-an-object"},
	})
	recPatch := httptest.NewRecorder()
	reqPatch := httptest.NewRequest(http.MethodPatch, "/Groups/"+groupID.String(), strings.NewReader(string(badPatch)))
	reqPatch.Header.Set("Prefer", "respond-async")
	ctx := context.WithValue(reqPatch.Context(), middleware.WorkspaceIDKey, wsID)
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("workspaceId", wsID.String())
	rctx.URLParams.Add("id", groupID.String())
	reqPatch = reqPatch.WithContext(context.WithValue(ctx, chi.RouteCtxKey, rctx))
	gh.PatchGroup(recPatch, reqPatch)
	if recPatch.Code != http.StatusBadRequest {
		t.Fatalf("PatchGroup(non-object op + respond-async) status = %d, want 400; body=%s", recPatch.Code, recPatch.Body.String())
	}
	asyncRepo.mu.Lock()
	if len(asyncRepo.events) != 0 {
		asyncRepo.mu.Unlock()
		t.Fatalf("expected 0 async events queued, got %d", len(asyncRepo.events))
	}
	asyncRepo.mu.Unlock()

	// Verify non-ASCII Unicode folding ('ſ' U+017F) is rejected with 400 invalidPath in Group PATCH operations.
	grp := &model.ScimGroup{ID: groupID, WorkspaceID: wsID, DisplayName: "Existing"}
	for _, badOp := range []map[string]any{
		{"op": "replace", "path": "di\u017fplayName", "value": "New"},
		{"op": "add", "path": "member\u017f", "value": []any{}},
		{"op": "remove", "path": "member\u017f"},
		{"op": "remove", "path": `members[value eq "` + memberID.String() + `"].di` + "\u017f" + `play`},
		{"op": "add", "path": `members[value eq "` + memberID.String() + `"].di` + "\u017f" + `play`, "value": "Disp"},
		{"op": "add", "value": map[string]any{"\u017fchemas": []any{scim.GroupSchemaURN}}},
		{"op": "replace", "value": map[string]any{"\u017fchemas": []any{scim.GroupSchemaURN}}},
	} {
		err := gh.applyGroupPatchOpTx(context.Background(), nil, grp, wsID, badOp)
		se, ok := err.(*scim.ScimError)
		if !ok || se.Status != 400 || se.ScimType != "invalidPath" {
			t.Fatalf("expected 400 invalidPath for %+v, got %v", badOp, err)
		}
	}
	// Removing .display (ASCII) on members[...] is a valid no-op.
	if err := gh.applyGroupPatchOpTx(context.Background(), nil, grp, wsID, map[string]any{
		"op":   "remove",
		"path": `members[value eq "` + memberID.String() + `"].DISPLAY`,
	}); err != nil {
		t.Fatalf("expected nil removing members[...].DISPLAY, got %v", err)
	}
}
