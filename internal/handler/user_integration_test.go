package handler

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/google/uuid"
)

func TestCreateAndGetUser(t *testing.T) {
	env := setupTestEnv(t)

	wsID := uuid.New()
	token := generateToken()
	seedWorkspaceAndToken(t, env.ctx, wsID, token)

	// Create user
	body := `{
		"schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
		"userName": "testuser@example.com",
		"displayName": "Test User",
		"active": true,
		"emails": [{"value": "testuser@example.com", "type": "work", "primary": true}]
	}`
	resp := doRequest(t, http.MethodPost, scimURL(env.server.URL, wsID, "/Users"), token, body)
	respBody := readBody(t, resp)

	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("expected 201, got %d: %s", resp.StatusCode, respBody)
	}

	var created map[string]any
	if err := json.Unmarshal([]byte(respBody), &created); err != nil {
		t.Fatalf("unmarshal create response: %v", err)
	}
	userID, ok := created["id"].(string)
	if !ok || userID == "" {
		t.Fatal("created user missing id")
	}

	// Get user
	resp = doRequest(t, http.MethodGet, scimURL(env.server.URL, wsID, "/Users/"+userID), token, "")
	respBody = readBody(t, resp)

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", resp.StatusCode, respBody)
	}
	if !strings.Contains(respBody, "testuser@example.com") {
		t.Fatal("get response missing userName")
	}
}

func TestListUsers(t *testing.T) {
	env := setupTestEnv(t)

	wsID := uuid.New()
	token := generateToken()
	seedWorkspaceAndToken(t, env.ctx, wsID, token)

	// Create users via API
	for _, un := range []string{"listuser1@example.com", "listuser2@example.com"} {
		body := `{"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],"userName":"` + un + `","displayName":"` + un + `","active":true}`
		r := doRequest(t, http.MethodPost, scimURL(env.server.URL, wsID, "/Users"), token, body)
		readBody(t, r)
		if r.StatusCode != http.StatusCreated {
			t.Fatalf("seed user %s: expected 201, got %d", un, r.StatusCode)
		}
	}

	resp := doRequest(t, http.MethodGet, scimURL(env.server.URL, wsID, "/Users"), token, "")
	respBody := readBody(t, resp)

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", resp.StatusCode, respBody)
	}
	if !strings.Contains(respBody, "listuser1@example.com") || !strings.Contains(respBody, "listuser2@example.com") {
		t.Fatalf("list response missing users: %s", respBody)
	}
}

func TestListUsersFilterMultiValuedJsonAttributes(t *testing.T) {
	env := setupTestEnv(t)

	wsID := uuid.New()
	token := generateToken()
	seedWorkspaceAndToken(t, env.ctx, wsID, token)

	// Create user1 with work email via API
	u1Body := `{
		"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],
		"userName":"user1","displayName":"user1","active":true,
		"emails":[{"value":"user1@work.com","type":"work","primary":true}]
	}`
	r1 := doRequest(t, http.MethodPost, scimURL(env.server.URL, wsID, "/Users"), token, u1Body)
	readBody(t, r1)
	if r1.StatusCode != http.StatusCreated {
		t.Fatalf("seed user1: expected 201, got %d", r1.StatusCode)
	}

	// Create user2 with home email via API
	u2Body := `{
		"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],
		"userName":"user2","displayName":"user2","active":true,
		"emails":[{"value":"user2@home.com","type":"home","primary":false}]
	}`
	r2 := doRequest(t, http.MethodPost, scimURL(env.server.URL, wsID, "/Users"), token, u2Body)
	readBody(t, r2)
	if r2.StatusCode != http.StatusCreated {
		t.Fatalf("seed user2: expected 201, got %d", r2.StatusCode)
	}

	// Filter by emails.value eq "user1@work.com"
	resp := doRequest(t, http.MethodGet,
		scimURL(env.server.URL, wsID, "/Users?filter=emails.value+eq+%22user1%40work.com%22"), token, "")
	respBody := readBody(t, resp)

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", resp.StatusCode, respBody)
	}
	if !strings.Contains(respBody, `"user1"`) {
		t.Fatal("filter response should contain user1")
	}
	if strings.Contains(respBody, `"user2"`) {
		t.Fatal("filter response should not contain user2")
	}

	// Filter by emails.type eq "home"
	resp = doRequest(t, http.MethodGet,
		scimURL(env.server.URL, wsID, `/Users?filter=emails.type+eq+%22home%22`), token, "")
	respBody = readBody(t, resp)

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", resp.StatusCode, respBody)
	}
	if !strings.Contains(respBody, `"user2"`) {
		t.Fatal("filter response should contain user2")
	}
	if strings.Contains(respBody, `"user1"`) {
		t.Fatal("filter response should not contain user1")
	}
}

func TestReplaceUser(t *testing.T) {
	env := setupTestEnv(t)

	wsID := uuid.New()
	token := generateToken()
	seedWorkspaceAndToken(t, env.ctx, wsID, token)

	// Create user first
	createBody := `{
		"schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
		"userName": "replace@example.com",
		"displayName": "Before Replace",
		"active": true
	}`
	resp := doRequest(t, http.MethodPost, scimURL(env.server.URL, wsID, "/Users"), token, createBody)
	respBody := readBody(t, resp)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("create: expected 201, got %d: %s", resp.StatusCode, respBody)
	}

	var created map[string]any
	json.Unmarshal([]byte(respBody), &created)
	userID := created["id"].(string)
	etag := resp.Header.Get("ETag")

	// Replace user
	replaceBody := `{
		"schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
		"userName": "replace@example.com",
		"displayName": "After Replace",
		"active": true
	}`
	req, _ := http.NewRequest(http.MethodPut, scimURL(env.server.URL, wsID, "/Users/"+userID), strings.NewReader(replaceBody))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/scim+json")
	req.Header.Set("If-Match", etag)
	resp2, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("replace request: %v", err)
	}
	respBody = readBody(t, resp2)

	if resp2.StatusCode != http.StatusOK {
		t.Fatalf("replace: expected 200, got %d: %s", resp2.StatusCode, respBody)
	}
	if !strings.Contains(respBody, "After Replace") {
		t.Fatal("replace response missing updated displayName")
	}
}

func TestPatchUser(t *testing.T) {
	env := setupTestEnv(t)

	wsID := uuid.New()
	token := generateToken()
	seedWorkspaceAndToken(t, env.ctx, wsID, token)

	// Create user
	createBody := `{
		"schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
		"userName": "patch@example.com",
		"displayName": "Before Patch",
		"active": true
	}`
	resp := doRequest(t, http.MethodPost, scimURL(env.server.URL, wsID, "/Users"), token, createBody)
	respBody := readBody(t, resp)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("create: expected 201, got %d: %s", resp.StatusCode, respBody)
	}

	var created map[string]any
	json.Unmarshal([]byte(respBody), &created)
	userID := created["id"].(string)

	// Patch user
	patchBody := `{
		"schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
		"Operations": [{
			"op": "replace",
			"path": "displayName",
			"value": "After Patch"
		}]
	}`
	resp = doRequest(t, http.MethodPatch, scimURL(env.server.URL, wsID, "/Users/"+userID), token, patchBody)
	respBody = readBody(t, resp)

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("patch: expected 200, got %d: %s", resp.StatusCode, respBody)
	}
	if !strings.Contains(respBody, "After Patch") {
		t.Fatal("patch response missing updated displayName")
	}
}

func TestDeleteUser(t *testing.T) {
	env := setupTestEnv(t)

	wsID := uuid.New()
	token := generateToken()
	seedWorkspaceAndToken(t, env.ctx, wsID, token)

	// Create user
	createBody := `{
		"schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
		"userName": "delete@example.com",
		"displayName": "To Delete",
		"active": true
	}`
	resp := doRequest(t, http.MethodPost, scimURL(env.server.URL, wsID, "/Users"), token, createBody)
	respBody := readBody(t, resp)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("create: expected 201, got %d: %s", resp.StatusCode, respBody)
	}

	var created map[string]any
	json.Unmarshal([]byte(respBody), &created)
	userID := created["id"].(string)

	// Delete user
	resp = doRequest(t, http.MethodDelete, scimURL(env.server.URL, wsID, "/Users/"+userID), token, "")
	readBody(t, resp)
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("delete: expected 204, got %d", resp.StatusCode)
	}

	// Verify user is gone
	resp = doRequest(t, http.MethodGet, scimURL(env.server.URL, wsID, "/Users/"+userID), token, "")
	readBody(t, resp)
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("get after delete: expected 404, got %d", resp.StatusCode)
	}
}

func TestUserNameUniqueness(t *testing.T) {
	env := setupTestEnv(t)

	wsID := uuid.New()
	token := generateToken()
	seedWorkspaceAndToken(t, env.ctx, wsID, token)

	body := `{
		"schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
		"userName": "duplicate@example.com",
		"active": true
	}`
	resp := doRequest(t, http.MethodPost, scimURL(env.server.URL, wsID, "/Users"), token, body)
	readBody(t, resp)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("first create: expected 201, got %d", resp.StatusCode)
	}

	// Same userName should fail
	resp = doRequest(t, http.MethodPost, scimURL(env.server.URL, wsID, "/Users"), token, body)
	respBody := readBody(t, resp)
	if resp.StatusCode != http.StatusConflict {
		t.Fatalf("duplicate create: expected 409, got %d: %s", resp.StatusCode, respBody)
	}
}
