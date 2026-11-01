package handler

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"

	"github.com/google/uuid"
)

func TestBulkResolvesBulkIdsAcrossOperations(t *testing.T) {
	env := setupTestEnv(t)

	wsID := uuid.New()
	token := generateToken()
	seedWorkspaceAndToken(t, env.ctx, wsID, token)

	bulkBody := `{
		"schemas": ["urn:ietf:params:scim:api:messages:2.0:BulkRequest"],
		"Operations": [
			{
				"method": "POST",
				"path": "/Users",
				"bulkId": "bulk-user",
				"data": {
					"schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
					"userName": "bulkuser@example.com",
					"displayName": "Bulk User",
					"active": true
				}
			},
			{
				"method": "POST",
				"path": "/Groups",
				"bulkId": "bulk-group",
				"data": {
					"schemas": ["urn:ietf:params:scim:schemas:core:2.0:Group"],
					"displayName": "Bulk Group",
					"members": [{"value": "bulkId:bulk-user", "type": "User"}]
				}
			},
			{
				"method": "PATCH",
				"path": "/Groups/bulkId:bulk-group",
				"data": {
					"schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
					"Operations": [{
						"op": "add",
						"path": "displayName",
						"value": "Bulk Group Updated"
					}]
				}
			}
		]
	}`

	resp := doRequest(t, http.MethodPost, scimURL(env.server.URL, wsID, "/Bulk"), token, bulkBody)
	respBody := readBody(t, resp)

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", resp.StatusCode, respBody)
	}

	var result map[string]any
	if err := json.Unmarshal([]byte(respBody), &result); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	ops, ok := result["Operations"].([]any)
	if !ok {
		t.Fatal("response missing Operations")
	}
	if len(ops) != 3 {
		t.Fatalf("expected 3 operations, got %d", len(ops))
	}

	// First op: user created (201)
	op0 := ops[0].(map[string]any)
	if op0["status"] != "201" {
		t.Fatalf("op[0] expected status 201, got %v", op0["status"])
	}
	userLocation, _ := op0["location"].(string)
	if userLocation == "" || !strings.Contains(userLocation, "/Users/") {
		t.Fatalf("op[0] missing valid user location: %v", userLocation)
	}

	// Second op: group created (201)
	op1 := ops[1].(map[string]any)
	if op1["status"] != "201" {
		t.Fatalf("op[1] expected status 201, got %v", op1["status"])
	}
	groupLocation, _ := op1["location"].(string)
	if groupLocation == "" || !strings.Contains(groupLocation, "/Groups/") {
		t.Fatalf("op[1] missing valid group location: %v", groupLocation)
	}

	// Third op: patch succeeded (200)
	op2 := ops[2].(map[string]any)
	if op2["status"] != "200" {
		t.Fatalf("op[2] expected status 200, got %v: %v", op2["status"], op2)
	}

	// Verify group was actually resolved using real IDs (not bulkId references)
	if strings.Contains(groupLocation, "bulkId") {
		t.Fatal("group location should not contain unresolved bulkId")
	}
}

func TestBulkStopsAfterConfiguredErrorThreshold(t *testing.T) {
	env := setupTestEnv(t)

	wsID := uuid.New()
	token := generateToken()
	seedWorkspaceAndToken(t, env.ctx, wsID, token)

	bulkBody := `{
		"schemas": ["urn:ietf:params:scim:api:messages:2.0:BulkRequest"],
		"failOnErrors": 1,
		"Operations": [
			{
				"method": "POST",
				"path": "/Users",
				"bulkId": "valid-user",
				"data": {
					"schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
					"userName": "validuser@example.com",
					"displayName": "Valid User",
					"active": true
				}
			},
			{
				"method": "PUT",
				"path": "/Users",
				"data": {
					"schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
					"userName": "invalid@example.com"
				}
			},
			{
				"method": "POST",
				"path": "/Users",
				"bulkId": "should-not-run",
				"data": {
					"schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
					"userName": "skippeduser@example.com",
					"displayName": "Should Not Run",
					"active": true
				}
			}
		]
	}`

	resp := doRequest(t, http.MethodPost, scimURL(env.server.URL, wsID, "/Bulk"), token, bulkBody)
	respBody := readBody(t, resp)

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", resp.StatusCode, respBody)
	}

	var result map[string]any
	if err := json.Unmarshal([]byte(respBody), &result); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	ops, ok := result["Operations"].([]any)
	if !ok {
		t.Fatal("response missing Operations")
	}

	// Should have stopped after first error (op[1]); only 2 results
	if len(ops) != 2 {
		t.Fatalf("expected 2 operations (stopped at failOnErrors=1), got %d", len(ops))
	}

	// First op should succeed
	op0 := ops[0].(map[string]any)
	if op0["status"] != "201" {
		t.Fatalf("op[0] expected status 201, got %v", op0["status"])
	}

	// Second op should be an error (PUT with no resource ID)
	op1 := ops[1].(map[string]any)
	status1, _ := op1["status"].(string)
	if status1 == "200" || status1 == "201" {
		t.Fatalf("op[1] expected error status, got %v", status1)
	}
}

func TestBulkRollsBackGroupOnCircularBulkIdFailure_BLK23(t *testing.T) {
	env := setupTestEnv(t)

	wsID := uuid.New()
	token := generateToken()
	seedWorkspaceAndToken(t, env.ctx, wsID, token)

	circGroup1 := "circ_g1_" + uuid.New().String()[:8]
	circGroup2 := "circ_g2_" + uuid.New().String()[:8]

	bulkBody := fmt.Sprintf(`{
		"schemas": ["urn:ietf:params:scim:api:messages:2.0:BulkRequest"],
		"Operations": [
			{
				"method": "POST",
				"path": "/Groups",
				"bulkId": "circG1",
				"data": {
					"schemas": ["urn:ietf:params:scim:schemas:core:2.0:Group"],
					"displayName": "%s",
					"members": [{"value": "bulkId:circG2", "type": "Group"}]
				}
			},
			{
				"method": "POST",
				"path": "/Groups",
				"bulkId": "circG2",
				"data": {
					"schemas": ["urn:ietf:params:scim:schemas:core:2.0:Group"],
					"displayName": "%s",
					"members": [{"value": "bulkId:circG1", "type": "Group"}]
				}
			}
		]
	}`, circGroup1, circGroup2)

	resp := doRequest(t, http.MethodPost, scimURL(env.server.URL, wsID, "/Bulk"), token, bulkBody)
	respBody := readBody(t, resp)

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", resp.StatusCode, respBody)
	}

	var result map[string]any
	if err := json.Unmarshal([]byte(respBody), &result); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	ops, ok := result["Operations"].([]any)
	if !ok || len(ops) != 2 {
		t.Fatalf("expected 2 operations, got %v", ops)
	}

	// Both operations should report 400 error due to unresolvable circular bulkId
	for i, rawOp := range ops {
		op := rawOp.(map[string]any)
		if op["status"] != "400" {
			t.Fatalf("op[%d] expected status 400, got %v", i, op["status"])
		}
		if op["location"] != nil {
			t.Fatalf("failed op[%d] must not return a location: %v", i, op["location"])
		}
	}

	// Verify NO group was persisted in the database (transaction rolled back)
	checkResp := doRequest(t, http.MethodGet, scimURL(env.server.URL, wsID, "/Groups"), token, "")
	checkBody := readBody(t, checkResp)
	if checkResp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 from GET /Groups, got %d: %s", checkResp.StatusCode, checkBody)
	}

	var groupList map[string]any
	if err := json.Unmarshal([]byte(checkBody), &groupList); err != nil {
		t.Fatalf("unmarshal groups list: %v", err)
	}
	resources, _ := groupList["Resources"].([]any)
	for _, r := range resources {
		groupMap, ok := r.(map[string]any)
		if !ok {
			continue
		}
		dName, _ := groupMap["displayName"].(string)
		if dName == circGroup1 || dName == circGroup2 {
			t.Fatalf("persisted group leaked after circular bulkId failure: %s (BLK_23 violation)", dName)
		}
	}
}

func TestBulkReplaceGroup_MemberTypeImmutabilityAndNotFoundBeforeValidation(t *testing.T) {
	env := setupTestEnv(t)

	wsID := uuid.New()
	token := generateToken()
	seedWorkspaceAndToken(t, env.ctx, wsID, token)

	userID := uuid.New()
	seedUser(t, env.ctx, wsID, userID, "member1@example.com", "Member One")

	missingGroupID := uuid.New()

	bulkBody := fmt.Sprintf(`{
		"schemas": ["urn:ietf:params:scim:api:messages:2.0:BulkRequest"],
		"Operations": [
			{
				"method": "POST",
				"path": "/Groups",
				"bulkId": "grp1",
				"data": {
					"schemas": ["urn:ietf:params:scim:schemas:core:2.0:Group"],
					"displayName": "Immutable Member Type Group",
					"members": [{"value": "%s", "type": "User"}]
				}
			},
			{
				"method": "PUT",
				"path": "/Groups/bulkId:grp1",
				"data": {
					"schemas": ["urn:ietf:params:scim:schemas:core:2.0:Group"],
					"displayName": "Immutable Member Type Group",
					"members": [{"value": "%s", "type": "Group"}]
				}
			},
			{
				"method": "PUT",
				"path": "/Groups/%s",
				"data": {
					"schemas": ["urn:ietf:params:scim:schemas:core:2.0:Group"]
				}
			}
		]
	}`, userID, userID, missingGroupID)

	resp := doRequest(t, http.MethodPost, scimURL(env.server.URL, wsID, "/Bulk"), token, bulkBody)
	respBody := readBody(t, resp)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", resp.StatusCode, respBody)
	}

	var result map[string]any
	if err := json.Unmarshal([]byte(respBody), &result); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	ops, ok := result["Operations"].([]any)
	if !ok || len(ops) != 3 {
		t.Fatalf("expected 3 operations, got %v", ops)
	}

	op0 := ops[0].(map[string]any)
	if op0["status"] != "201" {
		t.Fatalf("op[0] expected 201, got %v", op0["status"])
	}

	op1 := ops[1].(map[string]any)
	if op1["status"] != "400" {
		t.Fatalf("op[1] expected 400 mutability for GRP_21 member type mutation in bulk PUT, got %v: %v", op1["status"], op1)
	}
	if respObj, ok := op1["response"].(map[string]any); !ok || respObj["scimType"] != "mutability" {
		t.Fatalf("op[1] expected scimType=mutability, got %v", op1["response"])
	}

	op2 := ops[2].(map[string]any)
	if op2["status"] != "404" {
		t.Fatalf("op[2] expected 404 for non-existent group before 400 displayName check, got %v: %v", op2["status"], op2)
	}
}
