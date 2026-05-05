package handler

import (
	"net/http"
	"strings"
	"testing"

	"github.com/google/uuid"
)

func TestUserEndpointsRejectCrossWorkspaceToken(t *testing.T) {
	env := setupTestEnv(t)

	wsA := uuid.New()
	wsB := uuid.New()
	tokenA := generateToken()
	tokenB := generateToken()
	userID := uuid.New()

	seedWorkspaceAndToken(t, env.ctx, wsA, tokenA)
	seedWorkspaceAndToken(t, env.ctx, wsB, tokenB)
	seedUser(t, env.ctx, wsA, userID, "isolateduser@example.com", "Isolated User")

	endpoints := []struct {
		method string
		path   string
		body   string
	}{
		{http.MethodGet, "/Users", ""},
		{http.MethodGet, "/Users/" + userID.String(), ""},
		{http.MethodPost, "/Users", `{
			"schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
			"userName": "crossuser@example.com",
			"displayName": "Cross User",
			"active": true
		}`},
		{http.MethodPut, "/Users/" + userID.String(), `{
			"schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
			"userName": "crossupdate@example.com",
			"displayName": "Cross Update",
			"active": true
		}`},
		{http.MethodPatch, "/Users/" + userID.String(), `{
			"schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
			"Operations": [{"op": "replace", "path": "displayName", "value": "Hacked"}]
		}`},
		{http.MethodDelete, "/Users/" + userID.String(), ""},
	}

	for _, ep := range endpoints {
		t.Run(ep.method+" "+ep.path, func(t *testing.T) {
			// Use token B to access workspace A — should fail
			resp := doRequest(t, ep.method, scimURL(env.server.URL, wsA, ep.path), tokenB, ep.body)
			respBody := readBody(t, resp)

			if resp.StatusCode != http.StatusUnauthorized {
				t.Fatalf("cross-workspace %s %s: expected 401, got %d: %s",
					ep.method, ep.path, resp.StatusCode, respBody)
			}
		})
	}

	// Verify original user is untouched on wsA
	resp := doRequest(t, http.MethodGet, scimURL(env.server.URL, wsA, "/Users/"+userID.String()), tokenA, "")
	respBody := readBody(t, resp)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 with correct token, got %d: %s", resp.StatusCode, respBody)
	}
	if !strings.Contains(respBody, "Isolated User") {
		t.Fatal("user should be unchanged after cross-workspace attempts")
	}
}

func TestGroupEndpointsRejectCrossWorkspaceToken(t *testing.T) {
	env := setupTestEnv(t)

	wsA := uuid.New()
	wsB := uuid.New()
	tokenA := generateToken()
	tokenB := generateToken()
	groupID := uuid.New()

	seedWorkspaceAndToken(t, env.ctx, wsA, tokenA)
	seedWorkspaceAndToken(t, env.ctx, wsB, tokenB)
	seedGroup(t, env.ctx, wsA, groupID, "Isolated Group")

	endpoints := []struct {
		method string
		path   string
		body   string
	}{
		{http.MethodGet, "/Groups", ""},
		{http.MethodGet, "/Groups/" + groupID.String(), ""},
		{http.MethodPost, "/Groups", `{
			"schemas": ["urn:ietf:params:scim:schemas:core:2.0:Group"],
			"displayName": "Cross Group"
		}`},
		{http.MethodPut, "/Groups/" + groupID.String(), `{
			"schemas": ["urn:ietf:params:scim:schemas:core:2.0:Group"],
			"displayName": "Cross Update Group"
		}`},
		{http.MethodPatch, "/Groups/" + groupID.String(), `{
			"schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
			"Operations": [{"op": "replace", "path": "displayName", "value": "Hacked Group"}]
		}`},
		{http.MethodDelete, "/Groups/" + groupID.String(), ""},
	}

	for _, ep := range endpoints {
		t.Run(ep.method+" "+ep.path, func(t *testing.T) {
			resp := doRequest(t, ep.method, scimURL(env.server.URL, wsA, ep.path), tokenB, ep.body)
			respBody := readBody(t, resp)

			if resp.StatusCode != http.StatusUnauthorized {
				t.Fatalf("cross-workspace %s %s: expected 401, got %d: %s",
					ep.method, ep.path, resp.StatusCode, respBody)
			}
		})
	}

	// Verify original group is untouched on wsA
	resp := doRequest(t, http.MethodGet, scimURL(env.server.URL, wsA, "/Groups/"+groupID.String()), tokenA, "")
	respBody := readBody(t, resp)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 with correct token, got %d: %s", resp.StatusCode, respBody)
	}
	if !strings.Contains(respBody, "Isolated Group") {
		t.Fatal("group should be unchanged after cross-workspace attempts")
	}
}
