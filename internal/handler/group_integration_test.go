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
