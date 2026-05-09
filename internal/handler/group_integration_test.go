package handler

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/google/uuid"
)

func TestCreateAndGetGroup(t *testing.T) {
	env := setupTestEnv(t)

	wsID := uuid.New()
	token := generateToken()
	seedWorkspaceAndToken(t, env.ctx, wsID, token)

	// Create group
	body := `{
		"schemas": ["urn:ietf:params:scim:schemas:core:2.0:Group"],
		"displayName": "Test Admins Group"
	}`
	resp := doRequest(t, http.MethodPost, scimURL(env.server.URL, wsID, "/Groups"), token, body)
	respBody := readBody(t, resp)

	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("create: expected 201, got %d: %s", resp.StatusCode, respBody)
	}

	var created map[string]any
	if err := json.Unmarshal([]byte(respBody), &created); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	groupID := created["id"].(string)

	// Get group
	resp = doRequest(t, http.MethodGet, scimURL(env.server.URL, wsID, "/Groups/"+groupID), token, "")
	respBody = readBody(t, resp)

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("get: expected 200, got %d: %s", resp.StatusCode, respBody)
	}
	if !strings.Contains(respBody, "Test Admins Group") {
		t.Fatal("get response missing displayName")
	}
}

func TestGetGroupSeeded(t *testing.T) {
	env := setupTestEnv(t)

	wsID := uuid.New()
	groupID := uuid.New()
	token := generateToken()
	seedWorkspaceAndToken(t, env.ctx, wsID, token)
	seedGroup(t, env.ctx, wsID, groupID, "Test Admins Group")

	resp := doRequest(t, http.MethodGet, scimURL(env.server.URL, wsID, "/Groups/"+groupID.String()), token, "")
	respBody := readBody(t, resp)

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", resp.StatusCode, respBody)
	}
	if !strings.Contains(respBody, "Test Admins Group") {
		t.Fatal("response missing displayName")
	}
}

func TestGroupWithMembers(t *testing.T) {
	env := setupTestEnv(t)

	wsID := uuid.New()
	token := generateToken()
	seedWorkspaceAndToken(t, env.ctx, wsID, token)

	// Create a user first
	userBody := `{
		"schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
		"userName": "member@example.com",
		"displayName": "Member User",
		"active": true
	}`
	resp := doRequest(t, http.MethodPost, scimURL(env.server.URL, wsID, "/Users"), token, userBody)
	respBody := readBody(t, resp)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("create user: expected 201, got %d: %s", resp.StatusCode, respBody)
	}
	var createdUser map[string]any
	json.Unmarshal([]byte(respBody), &createdUser)
	userID := createdUser["id"].(string)

	// Create group with the user as a member
	groupBody := `{
		"schemas": ["urn:ietf:params:scim:schemas:core:2.0:Group"],
		"displayName": "Group With Members",
		"members": [{"value": "` + userID + `", "type": "User"}]
	}`
	resp = doRequest(t, http.MethodPost, scimURL(env.server.URL, wsID, "/Groups"), token, groupBody)
	respBody = readBody(t, resp)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("create group: expected 201, got %d: %s", resp.StatusCode, respBody)
	}

	var createdGroup map[string]any
	json.Unmarshal([]byte(respBody), &createdGroup)
	groupID := createdGroup["id"].(string)

	// Get group and verify member
	resp = doRequest(t, http.MethodGet, scimURL(env.server.URL, wsID, "/Groups/"+groupID), token, "")
	respBody = readBody(t, resp)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("get group: expected 200, got %d: %s", resp.StatusCode, respBody)
	}
	if !strings.Contains(respBody, userID) {
		t.Fatal("group response should contain member user ID")
	}
}

func TestPatchGroupAddRemoveMembers(t *testing.T) {
	env := setupTestEnv(t)

	wsID := uuid.New()
	token := generateToken()
	seedWorkspaceAndToken(t, env.ctx, wsID, token)

	// Create user
	userBody := `{
		"schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
		"userName": "patchmember@example.com",
		"displayName": "Patch Member",
		"active": true
	}`
	resp := doRequest(t, http.MethodPost, scimURL(env.server.URL, wsID, "/Users"), token, userBody)
	respBody := readBody(t, resp)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("create user: expected 201, got %d: %s", resp.StatusCode, respBody)
	}
	var createdUser map[string]any
	json.Unmarshal([]byte(respBody), &createdUser)
	userID := createdUser["id"].(string)

	// Create empty group
	groupBody := `{
		"schemas": ["urn:ietf:params:scim:schemas:core:2.0:Group"],
		"displayName": "Patch Group"
	}`
	resp = doRequest(t, http.MethodPost, scimURL(env.server.URL, wsID, "/Groups"), token, groupBody)
	respBody = readBody(t, resp)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("create group: expected 201, got %d: %s", resp.StatusCode, respBody)
	}
	var createdGroup map[string]any
	json.Unmarshal([]byte(respBody), &createdGroup)
	groupID := createdGroup["id"].(string)

	// Patch: add member
	patchAdd := `{
		"schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
		"Operations": [{
			"op": "add",
			"path": "members",
			"value": [{"value": "` + userID + `", "type": "User"}]
		}]
	}`
	resp = doRequest(t, http.MethodPatch, scimURL(env.server.URL, wsID, "/Groups/"+groupID), token, patchAdd)
	respBody = readBody(t, resp)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("patch add: expected 200, got %d: %s", resp.StatusCode, respBody)
	}
	if !strings.Contains(respBody, userID) {
		t.Fatal("patch add: response should contain added member")
	}

	// Patch: remove member
	patchRemove := `{
		"schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
		"Operations": [{
			"op": "remove",
			"path": "members[value eq \"` + userID + `\"]"
		}]
	}`
	resp = doRequest(t, http.MethodPatch, scimURL(env.server.URL, wsID, "/Groups/"+groupID), token, patchRemove)
	respBody = readBody(t, resp)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("patch remove: expected 200, got %d: %s", resp.StatusCode, respBody)
	}
	if strings.Contains(respBody, userID) {
		t.Fatal("patch remove: response should not contain removed member")
	}
}

func TestPatchGroupAddDuplicateMembersInSingleRequest(t *testing.T) {
	env := setupTestEnv(t)

	wsID := uuid.New()
	token := generateToken()
	seedWorkspaceAndToken(t, env.ctx, wsID, token)

	createUser := func(userName, displayName string) string {
		body := `{
			"schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
			"userName": "` + userName + `",
			"displayName": "` + displayName + `",
			"active": true
		}`
		resp := doRequest(t, http.MethodPost, scimURL(env.server.URL, wsID, "/Users"), token, body)
		respBody := readBody(t, resp)
		if resp.StatusCode != http.StatusCreated {
			t.Fatalf("create user: expected 201, got %d: %s", resp.StatusCode, respBody)
		}
		var created map[string]any
		if err := json.Unmarshal([]byte(respBody), &created); err != nil {
			t.Fatalf("create user unmarshal: %v", err)
		}
		return created["id"].(string)
	}

	userID1 := createUser("dup1@example.com", "Duplicate One")
	userID2 := createUser("dup2@example.com", "Duplicate Two")

	groupBody := `{
		"schemas": ["urn:ietf:params:scim:schemas:core:2.0:Group"],
		"displayName": "Duplicate Patch Group"
	}`
	resp := doRequest(t, http.MethodPost, scimURL(env.server.URL, wsID, "/Groups"), token, groupBody)
	respBody := readBody(t, resp)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("create group: expected 201, got %d: %s", resp.StatusCode, respBody)
	}
	var createdGroup map[string]any
	if err := json.Unmarshal([]byte(respBody), &createdGroup); err != nil {
		t.Fatalf("create group unmarshal: %v", err)
	}
	groupID := createdGroup["id"].(string)

	patchAdd := `{
		"schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
		"Operations": [{
			"op": "add",
			"path": "members",
			"value": [
				{"value": "` + userID1 + `", "type": "User"},
				{"value": "` + userID1 + `", "type": "User"},
				{"value": "` + userID2 + `", "type": "User"}
			]
		}]
	}`
	resp = doRequest(t, http.MethodPatch, scimURL(env.server.URL, wsID, "/Groups/"+groupID), token, patchAdd)
	respBody = readBody(t, resp)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("patch add: expected 200, got %d: %s", resp.StatusCode, respBody)
	}

	var patched map[string]any
	if err := json.Unmarshal([]byte(respBody), &patched); err != nil {
		t.Fatalf("patch add unmarshal: %v", err)
	}
	members, ok := patched["members"].([]any)
	if !ok {
		t.Fatalf("patch add: expected members array, got %T: %s", patched["members"], respBody)
	}
	if len(members) != 2 {
		t.Fatalf("patch add: expected 2 unique members, got %d: %s", len(members), respBody)
	}

	resp = doRequest(t, http.MethodGet, scimURL(env.server.URL, wsID, "/Groups/"+groupID), token, "")
	respBody = readBody(t, resp)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("get group: expected 200, got %d: %s", resp.StatusCode, respBody)
	}
	var gotGroup map[string]any
	if err := json.Unmarshal([]byte(respBody), &gotGroup); err != nil {
		t.Fatalf("get group unmarshal: %v", err)
	}
	members, ok = gotGroup["members"].([]any)
	if !ok {
		t.Fatalf("get group: expected members array, got %T: %s", gotGroup["members"], respBody)
	}
	if len(members) != 2 {
		t.Fatalf("get group: expected 2 unique members, got %d: %s", len(members), respBody)
	}
	values := make(map[string]bool, len(members))
	for _, member := range members {
		memberMap, ok := member.(map[string]any)
		if !ok {
			t.Fatalf("get group: expected member object, got %T: %s", member, respBody)
		}
		value, _ := memberMap["value"].(string)
		values[value] = true
	}
	if !values[userID1] {
		t.Fatalf("get group: missing first member, body: %s", respBody)
	}
	if !values[userID2] {
		t.Fatalf("get group: missing second member, body: %s", respBody)
	}
}

func TestDeleteGroup(t *testing.T) {
	env := setupTestEnv(t)

	wsID := uuid.New()
	token := generateToken()
	seedWorkspaceAndToken(t, env.ctx, wsID, token)

	// Create group
	body := `{
		"schemas": ["urn:ietf:params:scim:schemas:core:2.0:Group"],
		"displayName": "To Delete Group"
	}`
	resp := doRequest(t, http.MethodPost, scimURL(env.server.URL, wsID, "/Groups"), token, body)
	respBody := readBody(t, resp)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("create: expected 201, got %d: %s", resp.StatusCode, respBody)
	}
	var created map[string]any
	json.Unmarshal([]byte(respBody), &created)
	groupID := created["id"].(string)

	// Delete
	resp = doRequest(t, http.MethodDelete, scimURL(env.server.URL, wsID, "/Groups/"+groupID), token, "")
	readBody(t, resp)
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("delete: expected 204, got %d", resp.StatusCode)
	}

	// Verify gone
	resp = doRequest(t, http.MethodGet, scimURL(env.server.URL, wsID, "/Groups/"+groupID), token, "")
	readBody(t, resp)
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("get after delete: expected 404, got %d", resp.StatusCode)
	}
}
