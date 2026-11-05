package handler

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"

	"github.com/scimsandbox/scim-server-impl-go/internal/jdbc"
	"github.com/scimsandbox/scim-server-impl-go/internal/middleware"
	"github.com/scimsandbox/scim-server-impl-go/internal/scim"
)

func doRequestWithHeaders(
	t *testing.T,
	method, targetURL, token, body string,
	headers map[string]string,
) *http.Response {
	t.Helper()
	var bodyReader io.Reader
	if body != "" {
		bodyReader = strings.NewReader(body)
	}
	req, err := http.NewRequest(method, targetURL, bodyReader)
	if err != nil {
		t.Fatalf("create request: %v", err)
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	req.Header.Set("Accept", "application/scim+json")
	if body != "" {
		req.Header.Set("Content-Type", "application/scim+json")
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("send request: %v", err)
	}
	return resp
}

func assertScimErrorJSON(t *testing.T, statusCode int, rawBody string, wantStatus int, wantScimType string) map[string]any {
	t.Helper()
	if statusCode != wantStatus {
		t.Fatalf("HTTP status = %d, want %d; body: %s", statusCode, wantStatus, rawBody)
	}
	var errMap map[string]any
	if err := json.Unmarshal([]byte(rawBody), &errMap); err != nil {
		t.Fatalf("response is not valid SCIM Error JSON: %v; body: %s", err, rawBody)
	}
	schemas, _ := errMap["schemas"].([]any)
	foundErrSchema := false
	for _, s := range schemas {
		if s == "urn:ietf:params:scim:api:messages:2.0:Error" {
			foundErrSchema = true
			break
		}
	}
	if !foundErrSchema {
		t.Fatalf("missing SCIM Error schema in %v", errMap["schemas"])
	}
	if errMap["status"] != fmt.Sprintf("%d", wantStatus) {
		t.Fatalf("Error status = %v, want %q", errMap["status"], fmt.Sprintf("%d", wantStatus))
	}
	if wantScimType != "" && errMap["scimType"] != wantScimType {
		t.Fatalf("Error scimType = %v, want %q (body: %s)", errMap["scimType"], wantScimType, rawBody)
	}
	return errMap
}

// ─────────────────────────────────────────────────────────────────────────────
// Group 1 — Password Non-Cleartext Storage, Hashing & Request-Log Redaction
// Traced IDs:
//   - RFC7643-9.2-287493: Password values MUST NOT be stored in cleartext form.
//   - RFC7643-4.1.1-6515f1: Locally held password values SHOULD be hashed.
//   - RFC7643-4.1.1-328207: Cleartext password set/changed by client SHOULD be processed securely.
//   - RFC7643-9.2-e4d59c: Protect credential storage.
//   - RFC7644-7.7-f11467: Protect credential storage.
// ─────────────────────────────────────────────────────────────────────────────

func TestNACompliance_Group1_PasswordHashingAndZeroCleartextStorage(t *testing.T) {
	env := setupTestEnv(t)

	wsID := uuid.New()
	token := generateToken()
	seedWorkspaceAndToken(t, env.ctx, wsID, token)

	postSecret := "PostClear!Pwd#101"
	putSecret := "PutClear!Pwd#202"
	patchPathSecret := "PatchPathClear!Pwd#303"
	patchMapSecret := "PatchMapClear!Pwd#404"
	bulkPostSecret := "BulkPostClear!Pwd#505"
	bulkPatchSecret := "BulkPatchClear!Pwd#606"
	asyncSecret := "AsyncClear!Pwd#707"

	allSecrets := []string{
		postSecret,
		putSecret,
		patchPathSecret,
		patchMapSecret,
		bulkPostSecret,
		bulkPatchSecret,
		asyncSecret,
	}

	assertBcryptHashInDB := func(userIDStr, expectedCleartext string) {
		t.Helper()
		uid, err := uuid.Parse(userIDStr)
		if err != nil {
			t.Fatalf("parse user UUID %q: %v", userIDStr, err)
		}
		var storedPw sql.NullString
		err = jdbc.QueryRowContext(env.ctx,
			`SELECT password FROM scim_users WHERE id = $1 AND workspace_id = $2`,
			uid, wsID).Scan(&storedPw)
		if err != nil {
			t.Fatalf("query scim_users.password for %s: %v", userIDStr, err)
		}
		if !storedPw.Valid || storedPw.String == "" {
			t.Fatalf("expected non-empty hashed password in scim_users for %s", userIDStr)
		}
		if storedPw.String == expectedCleartext || strings.Contains(storedPw.String, expectedCleartext) {
			t.Fatalf("RFC7643-9.2-287493: cleartext password stored in scim_users: %s", storedPw.String)
		}
		if !strings.HasPrefix(storedPw.String, "$2a$") && !strings.HasPrefix(storedPw.String, "$2b$") {
			t.Fatalf("RFC7643-4.1.1-6515f1: expected bcrypt $2a$/$2b$ prefix, got %q", storedPw.String)
		}
		if err := bcrypt.CompareHashAndPassword([]byte(storedPw.String), []byte(expectedCleartext)); err != nil {
			t.Fatalf("RFC7643-4.1.1-6515f1: stored bcrypt hash did not verify against submitted password: %v", err)
		}
	}

	// 1. POST /Users
	postResp := doRequest(t, http.MethodPost, scimURL(env.server.URL, wsID, "/Users"), token, fmt.Sprintf(`{
		"schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
		"userName": "g1.sync@example.com",
		"displayName": "Group1 Sync User",
		"password": %q
	}`, postSecret))
	postBody := readBody(t, postResp)
	if postResp.StatusCode != http.StatusCreated {
		t.Fatalf("POST /Users status = %d, want 201: %s", postResp.StatusCode, postBody)
	}
	var createdUser map[string]any
	_ = json.Unmarshal([]byte(postBody), &createdUser)
	userID := createdUser["id"].(string)
	assertBcryptHashInDB(userID, postSecret)

	// 2. PUT /Users/{id}
	putResp := doRequest(t, http.MethodPut, scimURL(env.server.URL, wsID, "/Users/"+userID), token, fmt.Sprintf(`{
		"schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
		"userName": "g1.sync@example.com",
		"displayName": "Group1 Sync User Updated",
		"password": %q
	}`, putSecret))
	putBody := readBody(t, putResp)
	if putResp.StatusCode != http.StatusOK {
		t.Fatalf("PUT /Users/{id} status = %d, want 200: %s", putResp.StatusCode, putBody)
	}
	assertBcryptHashInDB(userID, putSecret)

	// 3a. PATCH /Users/{id} (path: "password")
	patch1Resp := doRequest(t, http.MethodPatch, scimURL(env.server.URL, wsID, "/Users/"+userID), token, fmt.Sprintf(`{
		"schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
		"Operations": [{"op": "replace", "path": "password", "value": %q}]
	}`, patchPathSecret))
	patch1Body := readBody(t, patch1Resp)
	if patch1Resp.StatusCode != http.StatusOK {
		t.Fatalf("PATCH path=password status = %d, want 200: %s", patch1Resp.StatusCode, patch1Body)
	}
	assertBcryptHashInDB(userID, patchPathSecret)

	// 3b. PATCH /Users/{id} (pathless value map containing password)
	patch2Resp := doRequest(t, http.MethodPatch, scimURL(env.server.URL, wsID, "/Users/"+userID), token, fmt.Sprintf(`{
		"schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
		"Operations": [{"op": "add", "value": {"password": %q, "nickName": "G1Nick"}}]
	}`, patchMapSecret))
	patch2Body := readBody(t, patch2Resp)
	if patch2Resp.StatusCode != http.StatusOK {
		t.Fatalf("PATCH value map password status = %d, want 200: %s", patch2Resp.StatusCode, patch2Body)
	}
	assertBcryptHashInDB(userID, patchMapSecret)

	// 4. POST /Bulk (POST user with password + PATCH existing user password)
	bulkResp := doRequest(t, http.MethodPost, scimURL(env.server.URL, wsID, "/Bulk"), token, fmt.Sprintf(`{
		"schemas": ["urn:ietf:params:scim:api:messages:2.0:BulkRequest"],
		"Operations": [
			{
				"method": "POST",
				"path": "/Users",
				"bulkId": "b1",
				"data": {
					"schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
					"userName": "g1.bulk@example.com",
					"password": %q
				}
			},
			{
				"method": "PATCH",
				"path": "/Users/%s",
				"data": {
					"schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
					"Operations": [{"op": "replace", "path": "password", "value": %q}]
				}
			}
		]
	}`, bulkPostSecret, userID, bulkPatchSecret))
	bulkBody := readBody(t, bulkResp)
	if bulkResp.StatusCode != http.StatusOK {
		t.Fatalf("POST /Bulk status = %d, want 200: %s", bulkResp.StatusCode, bulkBody)
	}
	var bulkResult map[string]any
	_ = json.Unmarshal([]byte(bulkBody), &bulkResult)
	bulkOps := bulkResult["Operations"].([]any)
	bulkLoc := bulkOps[0].(map[string]any)["location"].(string)
	bulkUserID := bulkLoc[strings.LastIndex(bulkLoc, "/")+1:]
	assertBcryptHashInDB(bulkUserID, bulkPostSecret)
	assertBcryptHashInDB(userID, bulkPatchSecret)

	// 5. Async Prefer: respond-async POST /Users
	asyncResp := doRequestWithHeaders(t, http.MethodPost, scimURL(env.server.URL, wsID, "/Users"), token, fmt.Sprintf(`{
		"schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
		"userName": "g1.async@example.com",
		"displayName": "Group1 Async User",
		"password": %q
	}`, asyncSecret), map[string]string{"Prefer": "respond-async"})
	asyncBody := readBody(t, asyncResp)
	if asyncResp.StatusCode != http.StatusAccepted {
		t.Fatalf("async POST /Users status = %d, want 202: %s", asyncResp.StatusCode, asyncBody)
	}
	txnIDStr := asyncResp.Header.Get("Set-Txn")
	if txnIDStr == "" {
		t.Fatal("missing Set-Txn header on 202 response")
	}

	var eventJSON string
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		evResp := doRequest(t, http.MethodGet, scimURL(env.server.URL, wsID, "/Events/"+txnIDStr), token, "")
		evBody := readBody(t, evResp)
		if evResp.StatusCode == http.StatusOK {
			eventJSON = evBody
			break
		}
		time.Sleep(15 * time.Millisecond)
	}
	if eventJSON == "" {
		t.Fatalf("async event %s did not reach COMPLETED within timeout", txnIDStr)
	}
	var asyncUserID uuid.UUID
	if err := jdbc.QueryRowContext(env.ctx,
		`SELECT id FROM scim_users WHERE workspace_id = $1 AND user_name = $2`,
		wsID, "g1.async@example.com").Scan(&asyncUserID); err != nil {
		t.Fatalf("lookup async created user: %v", err)
	}
	assertBcryptHashInDB(asyncUserID.String(), asyncSecret)

	// 6. White-box PostgreSQL inspection: zero cleartext in scim_users, scim_request_logs, scim_async_events
	userRows, err := jdbc.QueryContext(env.ctx,
		`SELECT COALESCE(password, ''), user_name, COALESCE(display_name, '') FROM scim_users WHERE workspace_id = $1`, wsID)
	if err != nil {
		t.Fatalf("query scim_users: %v", err)
	}
	defer userRows.Close()
	for userRows.Next() {
		var pw, un, dn string
		if err := userRows.Scan(&pw, &un, &dn); err != nil {
			t.Fatalf("scan scim_users: %v", err)
		}
		for _, secret := range allSecrets {
			if strings.Contains(pw, secret) || strings.Contains(un, secret) || strings.Contains(dn, secret) {
				t.Fatalf("RFC7643-9.2-287493: cleartext secret %q found in scim_users", secret)
			}
		}
	}

	logRows, err := jdbc.QueryContext(env.ctx,
		`SELECT http_method, request_path, COALESCE(request_body, ''), COALESCE(response_body, '')
		 FROM scim_request_logs WHERE workspace_id = $1`, wsID)
	if err != nil {
		t.Fatalf("query scim_request_logs: %v", err)
	}
	defer logRows.Close()
	logCount := 0
	redactedCount := 0
	for logRows.Next() {
		logCount++
		var method, path, reqB, respB string
		if err := logRows.Scan(&method, &path, &reqB, &respB); err != nil {
			t.Fatalf("scan scim_request_logs: %v", err)
		}
		if strings.Contains(reqB, "[REDACTED]") {
			redactedCount++
		}
		for _, secret := range allSecrets {
			if strings.Contains(reqB, secret) {
				t.Fatalf("RFC7643-9.2-e4d59c / RFC7644-7.7-f11467: cleartext password %q leaked in scim_request_logs.request_body (%s %s): %s",
					secret, method, path, reqB)
			}
			if strings.Contains(respB, secret) {
				t.Fatalf("RFC7643-9.2-e4d59c / RFC7644-7.7-f11467: cleartext password %q leaked in scim_request_logs.response_body (%s %s): %s",
					secret, method, path, respB)
			}
		}
	}
	if logCount < 6 || redactedCount < 6 {
		t.Fatalf("expected >= 6 logged password requests with [REDACTED], got logCount=%d redactedCount=%d", logCount, redactedCount)
	}

	evRows, err := jdbc.QueryContext(env.ctx,
		`SELECT COALESCE(set_payload, '') FROM scim_async_events WHERE workspace_id = $1`, wsID)
	if err != nil {
		t.Fatalf("query scim_async_events: %v", err)
	}
	defer evRows.Close()
	evCount := 0
	for evRows.Next() {
		evCount++
		var payload string
		if err := evRows.Scan(&payload); err != nil {
			t.Fatalf("scan scim_async_events: %v", err)
		}
		for _, secret := range allSecrets {
			if strings.Contains(payload, secret) {
				t.Fatalf("RFC7643-9.2-287493: cleartext password %q leaked in scim_async_events.set_payload: %s", secret, payload)
			}
		}
	}
	if evCount == 0 {
		t.Fatal("expected at least 1 row in scim_async_events")
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// Group 2 — immutable Attribute Semantics on PUT & PATCH
// Traced IDs:
//   - RFC7643-7-031493: Immutable attribute SHALL NOT be updated.
//   - RFC7644-3.5.1-2e5206: On PUT, if values are already set for an immutable attribute, input values MUST match.
//   - RFC7644-3.5.1-019f75: On PUT mismatch, return 400 with scimType: "mutability".
//   - RFC7644-3.5.2-0cc87d: On PATCH, client MAY add a value to an immutable attribute if it had no previous value.
// ─────────────────────────────────────────────────────────────────────────────

func TestNACompliance_Group2_ImmutableGroupMemberSemantics(t *testing.T) {
	env := setupTestEnv(t)

	wsID := uuid.New()
	token := generateToken()
	seedWorkspaceAndToken(t, env.ctx, wsID, token)

	userA := uuid.New()
	userB := uuid.New()
	childGroup := uuid.New()
	seedUser(t, env.ctx, wsID, userA, "g2.usera@example.com", "User A")
	seedUser(t, env.ctx, wsID, userB, "g2.userb@example.com", "User B")
	seedGroup(t, env.ctx, wsID, childGroup, "Child Group")

	// Create parent Group with userA (type: "User")
	createResp := doRequest(t, http.MethodPost, scimURL(env.server.URL, wsID, "/Groups"), token, fmt.Sprintf(`{
		"schemas": ["urn:ietf:params:scim:schemas:core:2.0:Group"],
		"displayName": "Immutable Parent Group",
		"members": [{"value": %q, "type": "User"}]
	}`, userA.String()))
	createBody := readBody(t, createResp)
	if createResp.StatusCode != http.StatusCreated {
		t.Fatalf("POST /Groups status = %d, want 201: %s", createResp.StatusCode, createBody)
	}
	var createdGroup map[string]any
	_ = json.Unmarshal([]byte(createBody), &createdGroup)
	groupID := createdGroup["id"].(string)

	// 1a. PUT keeping existing member with identical value and type -> 200 (RFC7644-3.5.1-2e5206)
	putMatchResp := doRequest(t, http.MethodPut, scimURL(env.server.URL, wsID, "/Groups/"+groupID), token, fmt.Sprintf(`{
		"schemas": ["urn:ietf:params:scim:schemas:core:2.0:Group"],
		"displayName": "Immutable Parent Group",
		"members": [{"value": %q, "type": "User"}]
	}`, userA.String()))
	putMatchBody := readBody(t, putMatchResp)
	if putMatchResp.StatusCode != http.StatusOK {
		t.Fatalf("PUT matching member type status = %d, want 200: %s", putMatchResp.StatusCode, putMatchBody)
	}

	// 1b. PUT keeping existing member with omitted type -> 200 (RFC7644-3.5.1-2e5206)
	putOmittedResp := doRequest(t, http.MethodPut, scimURL(env.server.URL, wsID, "/Groups/"+groupID), token, fmt.Sprintf(`{
		"schemas": ["urn:ietf:params:scim:schemas:core:2.0:Group"],
		"displayName": "Immutable Parent Group",
		"members": [{"value": %q}]
	}`, userA.String()))
	putOmittedBody := readBody(t, putOmittedResp)
	if putOmittedResp.StatusCode != http.StatusOK {
		t.Fatalf("PUT omitted member type status = %d, want 200: %s", putOmittedResp.StatusCode, putOmittedBody)
	}

	// 1c. PUT changing existing member's type ("User" -> "Group") -> 400 mutability (RFC7643-7-031493, RFC7644-3.5.1-2e5206, RFC7644-3.5.1-019f75)
	putMismatchResp := doRequest(t, http.MethodPut, scimURL(env.server.URL, wsID, "/Groups/"+groupID), token, fmt.Sprintf(`{
		"schemas": ["urn:ietf:params:scim:schemas:core:2.0:Group"],
		"displayName": "Immutable Parent Group",
		"members": [{"value": %q, "type": "Group"}]
	}`, userA.String()))
	putMismatchBody := readBody(t, putMismatchResp)
	assertScimErrorJSON(t, putMismatchResp.StatusCode, putMismatchBody, http.StatusBadRequest, "mutability")

	// 2a. PATCH replace and remove targeting members[value eq "<id>"].type, .value, .$ref -> 400 mutability (RFC7643-7-031493)
	for _, op := range []string{"replace", "remove"} {
		for _, sub := range []string{".type", ".value", ".$ref"} {
			var patchPayload string
			if op == "replace" {
				patchPayload = fmt.Sprintf(`{
					"schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
					"Operations": [{"op": "replace", "path": "members[value eq \"%s\"]%s", "value": "Group"}]
				}`, userA.String(), sub)
			} else {
				patchPayload = fmt.Sprintf(`{
					"schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
					"Operations": [{"op": "remove", "path": "members[value eq \"%s\"]%s"}]
				}`, userA.String(), sub)
			}
			pResp := doRequest(t, http.MethodPatch, scimURL(env.server.URL, wsID, "/Groups/"+groupID), token, patchPayload)
			pBody := readBody(t, pResp)
			assertScimErrorJSON(t, pResp.StatusCode, pBody, http.StatusBadRequest, "mutability")
		}
	}

	// 2b. PATCH add of a new member object -> 200 OK
	addMemberResp := doRequest(t, http.MethodPatch, scimURL(env.server.URL, wsID, "/Groups/"+groupID), token, fmt.Sprintf(`{
		"schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
		"Operations": [{"op": "add", "path": "members", "value": [{"value": %q, "type": "Group"}]}]
	}`, childGroup.String()))
	addMemberBody := readBody(t, addMemberResp)
	if addMemberResp.StatusCode != http.StatusOK {
		t.Fatalf("PATCH add new member status = %d, want 200: %s", addMemberResp.StatusCode, addMemberBody)
	}

	// 2c. RFC7644-3.5.2-0cc87d: Seed a member row with member_type = '' (no previous value for immutable 'type';
	// scim_group_memberships.member_type is VARCHAR(255) NOT NULL in V1__init_common_schema.sql).
	// PATCH add targeting members[value eq "<userB>"].type sets type (200), whereas subsequent add to a different type returns 400 mutability.
	_, err := jdbc.ExecContext(env.ctx,
		`INSERT INTO scim_group_memberships (id, group_id, workspace_id, member_value, member_type, display)
		 VALUES ($1, $2, $3, $4, '', $5)`,
		uuid.New(), uuid.MustParse(groupID), wsID, userB, "User B")
	if err != nil {
		t.Fatalf("seed untyped membership: %v", err)
	}

	addUnsetTypeResp := doRequest(t, http.MethodPatch, scimURL(env.server.URL, wsID, "/Groups/"+groupID), token, fmt.Sprintf(`{
		"schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
		"Operations": [{"op": "add", "path": "members[value eq \"%s\"].type", "value": "User"}]
	}`, userB.String()))
	addUnsetTypeBody := readBody(t, addUnsetTypeResp)
	if addUnsetTypeResp.StatusCode != http.StatusOK {
		t.Fatalf("RFC7644-3.5.2-0cc87d: PATCH add .type when previously unset returned %d, want 200: %s",
			addUnsetTypeResp.StatusCode, addUnsetTypeBody)
	}

	var persistedType sql.NullString
	if err := jdbc.QueryRowContext(env.ctx,
		`SELECT member_type FROM scim_group_memberships WHERE group_id = $1 AND member_value = $2`,
		uuid.MustParse(groupID), userB).Scan(&persistedType); err != nil {
		t.Fatalf("query persisted member_type: %v", err)
	}
	if !persistedType.Valid || persistedType.String != "User" {
		t.Fatalf("persisted member_type = %v, want 'User'", persistedType)
	}

	addAlreadySetDiffTypeResp := doRequest(t, http.MethodPatch, scimURL(env.server.URL, wsID, "/Groups/"+groupID), token, fmt.Sprintf(`{
		"schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
		"Operations": [{"op": "add", "path": "members[value eq \"%s\"].type", "value": "Group"}]
	}`, userB.String()))
	addAlreadySetDiffTypeBody := readBody(t, addAlreadySetDiffTypeResp)
	assertScimErrorJSON(t, addAlreadySetDiffTypeResp.StatusCode, addAlreadySetDiffTypeBody, http.StatusBadRequest, "mutability")
}

// ─────────────────────────────────────────────────────────────────────────────
// Group 3 — Subject Mapping, Multi-Tenant Isolation & Token Lifetime/Storage
// Traced IDs:
//   - RFC7644-2-fccd30: Map unique client to security subject.
//   - RFC7644-2-d8fe6f: Authorize action against subject and affected resource.
//   - RFC7644-6.1-26ac86: Infer associated tenant from authenticated client identity.
//   - RFC7644-7.4-66599e: Bearer tokens MUST have a determinable limited lifetime (expires_at enforced).
//   - RFC7644-7.4-cb7a78: High-entropy bearer tokens hashed with SHA-256.
// ─────────────────────────────────────────────────────────────────────────────

func TestNACompliance_Group3_MultiTenantIsolationAndTokenLifetime(t *testing.T) {
	env := setupTestEnv(t)

	wsA := uuid.New()
	wsB := uuid.New()
	tokenA := generateToken()
	tokenB := generateToken()

	seedWorkspaceAndToken(t, env.ctx, wsA, tokenA)
	seedWorkspaceAndToken(t, env.ctx, wsB, tokenB)

	// Verify SHA-256 hashed token storage in PostgreSQL (RFC7644-7.4-cb7a78)
	var storedHashes []string
	rows, err := jdbc.QueryContext(env.ctx,
		`SELECT token_hash FROM workspace_tokens WHERE workspace_id IN ($1, $2)`, wsA, wsB)
	if err != nil {
		t.Fatalf("query workspace_tokens: %v", err)
	}
	defer rows.Close()
	for rows.Next() {
		var th string
		if err := rows.Scan(&th); err != nil {
			t.Fatalf("scan token_hash: %v", err)
		}
		if th == tokenA || th == tokenB || len(th) != 64 {
			t.Fatalf("RFC7644-7.4-cb7a78: expected 64-char SHA-256 digest in DB, got %q", th)
		}
		storedHashes = append(storedHashes, th)
	}
	if len(storedHashes) != 2 {
		t.Fatalf("expected 2 token rows, got %d", len(storedHashes))
	}

	// Create User, Group, and Async Event in Workspace B using Token B
	userB := uuid.New()
	groupB := uuid.New()
	seedUser(t, env.ctx, wsB, userB, "tenantb.user@example.com", "Tenant B User")
	seedGroup(t, env.ctx, wsB, groupB, "Tenant B Group")

	asyncBResp := doRequestWithHeaders(t, http.MethodPost, scimURL(env.server.URL, wsB, "/Users"), tokenB, `{
		"schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
		"userName": "tenantb.async@example.com"
	}`, map[string]string{"Prefer": "respond-async"})
	asyncBBody := readBody(t, asyncBResp)
	if asyncBResp.StatusCode != http.StatusAccepted {
		t.Fatalf("async POST in wsB status = %d, want 202: %s", asyncBResp.StatusCode, asyncBBody)
	}
	txnB := asyncBResp.Header.Get("Set-Txn")

	// 1. Presenting Token A against Workspace B endpoints -> 401 (RFC7644-2-fccd30, RFC7644-2-d8fe6f, RFC7644-6.1-26ac86)
	crossWorkspaceChecks := []struct {
		method string
		path   string
		body   string
	}{
		{http.MethodGet, "/Users", ""},
		{http.MethodGet, "/Groups", ""},
		{http.MethodPost, "/.search", `{"schemas":["urn:ietf:params:scim:api:messages:2.0:SearchRequest"]}`},
		{http.MethodPost, "/Bulk", `{"schemas":["urn:ietf:params:scim:api:messages:2.0:BulkRequest"],"Operations":[]}`},
		{http.MethodGet, "/Events/" + txnB, ""},
	}
	for _, chk := range crossWorkspaceChecks {
		resp := doRequest(t, chk.method, scimURL(env.server.URL, wsB, chk.path), tokenA, chk.body)
		body := readBody(t, resp)
		if resp.StatusCode != http.StatusUnauthorized && resp.StatusCode != http.StatusForbidden {
			t.Fatalf("Token A on wsB %s %s: got %d, want 401/403: %s", chk.method, chk.path, resp.StatusCode, body)
		}
	}

	// 2. Workspace B resource IDs accessed via Workspace A URL + Token A -> 404 Not Found
	crossResourceChecks := []struct {
		method string
		path   string
		body   string
	}{
		{http.MethodGet, "/Users/" + userB.String(), ""},
		{http.MethodPut, "/Users/" + userB.String(), `{"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],"userName":"hijack@example.com"}`},
		{http.MethodPatch, "/Users/" + userB.String(), `{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],"Operations":[{"op":"replace","path":"displayName","value":"Hijack"}]}`},
		{http.MethodDelete, "/Users/" + userB.String(), ""},
		{http.MethodGet, "/Groups/" + groupB.String(), ""},
		{http.MethodPut, "/Groups/" + groupB.String(), `{"schemas":["urn:ietf:params:scim:schemas:core:2.0:Group"],"displayName":"Hijack"}`},
		{http.MethodPatch, "/Groups/" + groupB.String(), `{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],"Operations":[{"op":"replace","path":"displayName","value":"Hijack"}]}`},
		{http.MethodDelete, "/Groups/" + groupB.String(), ""},
		{http.MethodGet, "/Events/" + txnB, ""},
	}
	for _, chk := range crossResourceChecks {
		resp := doRequest(t, chk.method, scimURL(env.server.URL, wsA, chk.path), tokenA, chk.body)
		body := readBody(t, resp)
		assertScimErrorJSON(t, resp.StatusCode, body, http.StatusNotFound, "")
	}

	// 3. Token lifetime enforcement: expired -> 401, revoked -> 401, future expires_at -> 200 (RFC7644-7.4-66599e)
	now := time.Now().UTC()
	pastExp := now.Add(-10 * time.Minute)
	futureExp := now.Add(30 * time.Minute)

	expiredToken := generateToken()
	revokedToken := generateToken()
	futureToken := generateToken()

	for _, td := range []struct {
		raw     string
		exp     time.Time
		revoked bool
	}{
		{expiredToken, pastExp, false},
		{revokedToken, futureExp, true},
		{futureToken, futureExp, false},
	} {
		_, err := jdbc.ExecContext(env.ctx,
			`INSERT INTO workspace_tokens (id, workspace_id, token_hash, name, description, expires_at, revoked, created_at, updated_at)
			 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`,
			uuid.New(), wsA, hashToken(td.raw), "lifetime-test", "test", td.exp, td.revoked, now, now)
		if err != nil {
			t.Fatalf("seed lifetime token: %v", err)
		}
	}

	expResp := doRequest(t, http.MethodGet, scimURL(env.server.URL, wsA, "/Users"), expiredToken, "")
	expBody := readBody(t, expResp)
	assertScimErrorJSON(t, expResp.StatusCode, expBody, http.StatusUnauthorized, "")

	revResp := doRequest(t, http.MethodGet, scimURL(env.server.URL, wsA, "/Users"), revokedToken, "")
	revBody := readBody(t, revResp)
	assertScimErrorJSON(t, revResp.StatusCode, revBody, http.StatusUnauthorized, "")

	futResp := doRequest(t, http.MethodGet, scimURL(env.server.URL, wsA, "/Users"), futureToken, "")
	futBody := readBody(t, futResp)
	if futResp.StatusCode != http.StatusOK {
		t.Fatalf("future expires_at token status = %d, want 200: %s", futResp.StatusCode, futBody)
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// Group 4 — Cursor Pagination Security: Confinement, Revocation & Zero Sensitive-Data Leak
// Traced IDs:
//   - RFC9865-5.2-230645: Pagination strictly confined to authorized actor's data, even if cursor was generated by another actor.
//   - RFC9865-5.2-535e56: Immediately deny cursors after actor permission loss/revocation.
//   - RFC9865-5.2-826018: Handle cursor error scenarios without exposing sensitive data.
// ─────────────────────────────────────────────────────────────────────────────

func TestNACompliance_Group4_CursorConfinementAcrossWorkspaces(t *testing.T) {
	// RFC9865-5.2-230645
	env := setupTestEnv(t)

	wsA := uuid.New()
	wsB := uuid.New()
	tokenA := generateToken()
	tokenB := generateToken()
	seedWorkspaceAndToken(t, env.ctx, wsA, tokenA)
	seedWorkspaceAndToken(t, env.ctx, wsB, tokenB)

	wsAUsers := make(map[string]bool)
	for i := 1; i <= 3; i++ {
		uid := uuid.New()
		wsAUsers[uid.String()] = true
		seedUser(t, env.ctx, wsA, uid, fmt.Sprintf("wsa.cursor.%d@example.com", i), fmt.Sprintf("WSA User %d", i))
	}
	wsBUser := uuid.New()
	seedUser(t, env.ctx, wsB, wsBUser, "wsb.cursor.1@example.com", "WSB User 1")

	// Generate valid nextCursor in Workspace A
	p1Resp := doRequest(t, http.MethodGet, scimURL(env.server.URL, wsA, "/Users?cursor=&count=1"), tokenA, "")
	p1Body := readBody(t, p1Resp)
	if p1Resp.StatusCode != http.StatusOK {
		t.Fatalf("wsA cursor page 1 status = %d, want 200: %s", p1Resp.StatusCode, p1Body)
	}
	var p1Map map[string]any
	_ = json.Unmarshal([]byte(p1Body), &p1Map)
	cursorA, _ := p1Map["nextCursor"].(string)
	if cursorA == "" {
		t.Fatalf("expected non-empty nextCursor in wsA page 1: %s", p1Body)
	}

	// Present cursorA on Workspace B with valid Token B -> 400 invalidCursor, zero Workspace A data leaked
	crossResp := doRequest(t, http.MethodGet, scimURL(env.server.URL, wsB, "/Users?cursor="+url.QueryEscape(cursorA)+"&count=1"), tokenB, "")
	crossBody := readBody(t, crossResp)
	errObj := assertScimErrorJSON(t, crossResp.StatusCode, crossBody, http.StatusBadRequest, "invalidCursor")
	if _, hasRes := errObj["Resources"]; hasRes {
		t.Fatalf("RFC9865-5.2-230645: cross-workspace cursor error response must not contain Resources: %s", crossBody)
	}
	for uid := range wsAUsers {
		if strings.Contains(crossBody, uid) || strings.Contains(crossBody, "wsa.cursor.") {
			t.Fatalf("RFC9865-5.2-230645: Workspace A data leaked in Workspace B response: %s", crossBody)
		}
	}

	// Normal cursor pagination in Workspace B returns ONLY Workspace B resources
	wsBResp := doRequest(t, http.MethodGet, scimURL(env.server.URL, wsB, "/Users?cursor=&count=10"), tokenB, "")
	wsBBody := readBody(t, wsBResp)
	if wsBResp.StatusCode != http.StatusOK {
		t.Fatalf("wsB cursor query status = %d, want 200: %s", wsBResp.StatusCode, wsBBody)
	}
	var wsBList map[string]any
	_ = json.Unmarshal([]byte(wsBBody), &wsBList)
	resList, _ := wsBList["Resources"].([]any)
	if len(resList) != 1 || resList[0].(map[string]any)["id"] != wsBUser.String() {
		t.Fatalf("RFC9865-5.2-230645: expected only wsBUser %s, got %v", wsBUser, resList)
	}
}

func TestNACompliance_Group4_ImmediateCursorDenialAfterRevocationOrExpiry(t *testing.T) {
	// RFC9865-5.2-535e56
	env := setupTestEnv(t)

	wsA := uuid.New()
	tokenRevoke := generateToken()
	seedWorkspaceAndToken(t, env.ctx, wsA, tokenRevoke)

	now := time.Now().UTC()
	tokenExpire := generateToken()
	future := now.Add(time.Hour)
	_, err := jdbc.ExecContext(env.ctx,
		`INSERT INTO workspace_tokens (id, workspace_id, token_hash, name, description, expires_at, revoked, created_at, updated_at)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`,
		uuid.New(), wsA, hashToken(tokenExpire), "expire-mid-cursor", "test", future, false, now, now)
	if err != nil {
		t.Fatalf("seed tokenExpire: %v", err)
	}

	for i := 1; i <= 3; i++ {
		seedUser(t, env.ctx, wsA, uuid.New(), fmt.Sprintf("revoke.cur.%d@example.com", i), fmt.Sprintf("Revoke User %d", i))
	}

	// Subtest 1: Mid-pagination token revocation (revoked = true)
	p1RevResp := doRequest(t, http.MethodGet, scimURL(env.server.URL, wsA, "/Users?cursor=&count=1"), tokenRevoke, "")
	p1RevBody := readBody(t, p1RevResp)
	if p1RevResp.StatusCode != http.StatusOK {
		t.Fatalf("page 1 before revocation status = %d: %s", p1RevResp.StatusCode, p1RevBody)
	}
	var p1RevMap map[string]any
	_ = json.Unmarshal([]byte(p1RevBody), &p1RevMap)
	nextCursor1 := p1RevMap["nextCursor"].(string)

	if _, err := jdbc.ExecContext(env.ctx,
		`UPDATE workspace_tokens SET revoked = true WHERE token_hash = $1`, hashToken(tokenRevoke)); err != nil {
		t.Fatalf("revoke token in DB: %v", err)
	}

	p2RevResp := doRequest(t, http.MethodGet, scimURL(env.server.URL, wsA, "/Users?cursor="+url.QueryEscape(nextCursor1)+"&count=1"), tokenRevoke, "")
	p2RevBody := readBody(t, p2RevResp)
	errMap1 := assertScimErrorJSON(t, p2RevResp.StatusCode, p2RevBody, http.StatusUnauthorized, "")
	if res, ok := errMap1["Resources"].([]any); ok && len(res) > 0 {
		t.Fatalf("RFC9865-5.2-535e56: resources returned after token revocation: %s", p2RevBody)
	}

	// Subtest 2: Mid-pagination token expiration (expires_at = past)
	p1ExpResp := doRequest(t, http.MethodGet, scimURL(env.server.URL, wsA, "/Users?cursor=&count=1"), tokenExpire, "")
	p1ExpBody := readBody(t, p1ExpResp)
	if p1ExpResp.StatusCode != http.StatusOK {
		t.Fatalf("page 1 before expiry status = %d: %s", p1ExpResp.StatusCode, p1ExpBody)
	}
	var p1ExpMap map[string]any
	_ = json.Unmarshal([]byte(p1ExpBody), &p1ExpMap)
	nextCursor2 := p1ExpMap["nextCursor"].(string)

	if _, err := jdbc.ExecContext(env.ctx,
		`UPDATE workspace_tokens SET expires_at = $1 WHERE token_hash = $2`,
		time.Now().UTC().Add(-5*time.Minute), hashToken(tokenExpire)); err != nil {
		t.Fatalf("expire token in DB: %v", err)
	}

	p2ExpResp := doRequest(t, http.MethodGet, scimURL(env.server.URL, wsA, "/Users?cursor="+url.QueryEscape(nextCursor2)+"&count=1"), tokenExpire, "")
	p2ExpBody := readBody(t, p2ExpResp)
	errMap2 := assertScimErrorJSON(t, p2ExpResp.StatusCode, p2ExpBody, http.StatusUnauthorized, "")
	if res, ok := errMap2["Resources"].([]any); ok && len(res) > 0 {
		t.Fatalf("RFC9865-5.2-535e56: resources returned after token expiration: %s", p2ExpBody)
	}
}

func assertNoSensitiveMarkers(t *testing.T, caseName, rawBody string, secrets []string) {
	t.Helper()
	internalMarkers := []string{
		"goroutine",
		"panic",
		"Exception",
		"select ",
		"SELECT ",
		"insert ",
		"INSERT ",
		".go:",
		".java:",
	}
	for _, s := range secrets {
		if s != "" && strings.Contains(rawBody, s) {
			t.Fatalf("RFC9865-5.2-826018 [%s]: sensitive secret %q leaked in response: %s", caseName, s, rawBody)
		}
	}
	for _, m := range internalMarkers {
		if strings.Contains(rawBody, m) {
			t.Fatalf("RFC9865-5.2-826018 [%s]: internal stack/SQL marker %q leaked in response: %s", caseName, m, rawBody)
		}
	}
}

func TestNACompliance_Group4_CursorErrorZeroSensitiveDataLeak_Unit(t *testing.T) {
	// RFC9865-5.2-826018 (pure unit handler check)
	wsA := uuid.New()
	wsB := uuid.New()
	tokenA := "tok_secret_alpha_99887766"
	tokenB := "tok_secret_bravo_55443322"
	hashA := middleware.HashToken(tokenA)
	hashB := middleware.HashToken(tokenB)
	dbPass := "SuperSecretPgPassword!42"
	seededUserID := uuid.New().String()
	seededUserName := "confidential.actor@example.com"
	seededUserPass := "ConfidentialUserPass!88"

	secrets := []string{
		tokenA, tokenB, hashA, hashB,
		wsA.String(), wsB.String(),
		dbPass, seededUserID, seededUserName, seededUserPass,
	}

	validCursorA, _ := scim.EncodeCursor(wsA, 1, 3600)
	expiredCursorB := scim.CursorPrefix + base64.RawURLEncoding.EncodeToString(
		[]byte(fmt.Sprintf(`{"w":%q,"o":1,"exp":%d}`, wsB.String(), time.Now().Add(-time.Hour).Unix())),
	)
	tamperedNegOffset := scim.CursorPrefix + base64.RawURLEncoding.EncodeToString(
		[]byte(fmt.Sprintf(`{"w":%q,"o":-10,"exp":%d}`, wsB.String(), time.Now().Add(time.Hour).Unix())),
	)
	tamperedMissingOffset := scim.CursorPrefix + base64.RawURLEncoding.EncodeToString(
		[]byte(fmt.Sprintf(`{"w":%q,"exp":%d}`, wsB.String(), time.Now().Add(time.Hour).Unix())),
	)

	uh := &UserHandler{}
	errorProbes := []struct {
		name         string
		query        string
		wantScimType string
	}{
		{"truncated_cursor", "cursor=" + validCursorA[:14] + "&count=1", "invalidCursor"},
		{"invalid_base64", "cursor=scim_cur_***not-base64***&count=1", "invalidCursor"},
		{"malformed_json", "cursor=" + scim.CursorPrefix + base64.RawURLEncoding.EncodeToString([]byte(`{"w":`)) + "&count=1", "invalidCursor"},
		{"tampered_negative_offset", "cursor=" + tamperedNegOffset + "&count=1", "invalidCursor"},
		{"tampered_missing_offset", "cursor=" + tamperedMissingOffset + "&count=1", "invalidCursor"},
		{"expired_cursor", "cursor=" + expiredCursorB + "&count=1", "invalidCursor"},
		{"workspace_a_cursor_in_workspace_b", "cursor=" + validCursorA + "&count=1", "invalidCursor"},
		{"non_integer_count", "cursor=&count=notanint", "invalidValue"},
		{"count_exceeds_max_page_size", "cursor=&count=500", "tooMany"},
	}

	for _, tc := range errorProbes {
		t.Run(tc.name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodGet, "/Users?"+tc.query, nil)
			req = req.WithContext(context.WithValue(req.Context(), middleware.WorkspaceIDKey, wsB))
			uh.ListUsers(rec, req)

			raw := rec.Body.String()
			assertScimErrorJSON(t, rec.Code, raw, http.StatusBadRequest, tc.wantScimType)
			assertNoSensitiveMarkers(t, tc.name, raw, secrets)
		})
	}
}

func TestNACompliance_Group4_CursorErrorZeroSensitiveDataLeak(t *testing.T) {
	// RFC9865-5.2-826018 (end-to-end PostgreSQL white-box check)
	env := setupTestEnv(t)

	wsA := uuid.New()
	wsB := uuid.New()
	tokenA := generateToken()
	tokenB := generateToken()
	seedWorkspaceAndToken(t, env.ctx, wsA, tokenA)
	seedWorkspaceAndToken(t, env.ctx, wsB, tokenB)

	userA := uuid.New()
	userB := uuid.New()
	userPass := "HiddenCursorUserSecret!91"
	postResp := doRequest(t, http.MethodPost, scimURL(env.server.URL, wsA, "/Users"), tokenA, fmt.Sprintf(`{
		"schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
		"userName": "secret.wsa.user@example.com",
		"password": %q
	}`, userPass))
	postBody := readBody(t, postResp)
	if postResp.StatusCode != http.StatusCreated {
		t.Fatalf("setup POST user in wsA: %d %s", postResp.StatusCode, postBody)
	}
	var createdA map[string]any
	_ = json.Unmarshal([]byte(postBody), &createdA)
	createdAID := createdA["id"].(string)
	seedUser(t, env.ctx, wsA, userA, "secret.wsa.user2@example.com", "Secret A2")
	seedUser(t, env.ctx, wsB, userB, "secret.wsb.user@example.com", "Secret B1")

	secrets := []string{
		tokenA, tokenB,
		hashToken(tokenA), hashToken(tokenB),
		wsA.String(), wsB.String(),
		"postgres", // DB password in test container
		createdAID, userA.String(), userB.String(),
		"secret.wsa.user@example.com", "secret.wsa.user2@example.com", "secret.wsb.user@example.com",
		userPass,
	}

	p1Resp := doRequest(t, http.MethodGet, scimURL(env.server.URL, wsA, "/Users?cursor=&count=1"), tokenA, "")
	p1Body := readBody(t, p1Resp)
	var p1Map map[string]any
	_ = json.Unmarshal([]byte(p1Body), &p1Map)
	cursorA := p1Map["nextCursor"].(string)

	expiredCursorB := scim.CursorPrefix + base64.RawURLEncoding.EncodeToString(
		[]byte(fmt.Sprintf(`{"w":%q,"o":1,"exp":%d}`, wsB.String(), time.Now().Add(-time.Hour).Unix())),
	)
	tamperedCursorB := scim.CursorPrefix + base64.RawURLEncoding.EncodeToString(
		[]byte(fmt.Sprintf(`{"w":%q,"o":-3,"exp":%d}`, wsB.String(), time.Now().Add(time.Hour).Unix())),
	)

	fourXXCases := []struct {
		name         string
		path         string
		wantScimType string
	}{
		{"truncated_cursor", "/Users?cursor=" + url.QueryEscape(cursorA[:12]) + "&count=1", "invalidCursor"},
		{"invalid_base64", "/Users?cursor=scim_cur_@@@bad@@@&count=1", "invalidCursor"},
		{"malformed_json", "/Users?cursor=" + url.QueryEscape(scim.CursorPrefix+base64.RawURLEncoding.EncodeToString([]byte("{not-json"))) + "&count=1", "invalidCursor"},
		{"tampered_json", "/Users?cursor=" + url.QueryEscape(tamperedCursorB) + "&count=1", "invalidCursor"},
		{"expired_cursor", "/Users?cursor=" + url.QueryEscape(expiredCursorB) + "&count=1", "invalidCursor"},
		{"cross_workspace_cursor", "/Users?cursor=" + url.QueryEscape(cursorA) + "&count=1", "invalidCursor"},
		{"count_gt_maxPageSize", "/Users?cursor=&count=250", "tooMany"},
	}

	for _, tc := range fourXXCases {
		t.Run(tc.name, func(t *testing.T) {
			resp := doRequest(t, http.MethodGet, scimURL(env.server.URL, wsB, tc.path), tokenB, "")
			body := readBody(t, resp)
			assertScimErrorJSON(t, resp.StatusCode, body, http.StatusBadRequest, tc.wantScimType)
			assertNoSensitiveMarkers(t, tc.name, body, secrets)
		})
	}

	// Negative count per RFC 9865 §2 (interpreted as 0 -> empty Resources, zero secrets leaked)
	negResp := doRequest(t, http.MethodGet, scimURL(env.server.URL, wsB, "/Users?cursor=&count=-5"), tokenB, "")
	negBody := readBody(t, negResp)
	if negResp.StatusCode != http.StatusOK {
		t.Fatalf("negative count status = %d, want 200: %s", negResp.StatusCode, negBody)
	}
	assertNoSensitiveMarkers(t, "negative_count_clamped_zero", negBody, secrets)
}

// ─────────────────────────────────────────────────────────────────────────────
// Group 5 — Result Size Cap, Sanitized 500 Errors & Version-Agnostic $ref
// Traced IDs:
//   - RFC7644-3.4.2.1-145a1a: maxResults cap (200) clamped on index pagination.
//   - RFC7644-3.12-40cb84: 400 tooMany on excessive cursor count (> maxPageSize).
//   - RFC7644-3.12-991537: 500 Internal Server Error returns descriptive SCIM Error JSON without leaking SQL/exception internals.
//   - RFC7643-2.4-63934b: $ref URIs with different or omitted API versions are accepted and normalized consistently on Group.members / enterprise.manager.
// ─────────────────────────────────────────────────────────────────────────────

func TestNACompliance_Group5_Sanitized500ErrorResponse_Unit(t *testing.T) {
	// RFC7644-3.12-991537
	rawDriverErr := errors.New(`ERROR: relation "scim_users" does not exist (SQLSTATE 42P01) — query: SELECT * FROM scim_users WHERE workspace_id='secret-ws' dsn=postgres://postgres:TopSecretDB@127.0.0.1:5432/scim`)
	rec := httptest.NewRecorder()
	scim.WriteErrorFromAny(rec, rawDriverErr)

	rawBody := rec.Body.String()
	errObj := assertScimErrorJSON(t, rec.Code, rawBody, http.StatusInternalServerError, "")
	if errObj["detail"] != "Internal server error" {
		t.Fatalf("500 detail = %v, want \"Internal server error\"", errObj["detail"])
	}
	for _, leak := range []string{"SQLSTATE", "42P01", "scim_users", "TopSecretDB", "SELECT *", "secret-ws"} {
		if strings.Contains(rawBody, leak) {
			t.Fatalf("RFC7644-3.12-991537: internal SQL/JDBC detail %q leaked in 500 response: %s", leak, rawBody)
		}
	}
}

func TestNACompliance_Group5_MaxResultsAndCursorTooMany(t *testing.T) {
	// RFC7644-3.4.2.1-145a1a & RFC7644-3.12-40cb84
	env := setupTestEnv(t)

	wsID := uuid.New()
	token := generateToken()
	seedWorkspaceAndToken(t, env.ctx, wsID, token)

	for i := 1; i <= 205; i++ {
		seedUser(t, env.ctx, wsID, uuid.New(), fmt.Sprintf("cap.user.%03d@example.com", i), fmt.Sprintf("Cap User %03d", i))
	}

	// 1. Index pagination with count=500 -> clamped to <= 200 (RFC7644-3.4.2.1-145a1a)
	idxResp := doRequest(t, http.MethodGet, scimURL(env.server.URL, wsID, "/Users?count=500"), token, "")
	idxBody := readBody(t, idxResp)
	if idxResp.StatusCode != http.StatusOK {
		t.Fatalf("index count=500 status = %d, want 200: %s", idxResp.StatusCode, idxBody)
	}
	var idxMap map[string]any
	_ = json.Unmarshal([]byte(idxBody), &idxMap)
	resources, _ := idxMap["Resources"].([]any)
	itemsPerPage := int(idxMap["itemsPerPage"].(float64))
	totalResults := int(idxMap["totalResults"].(float64))
	if len(resources) != 200 || itemsPerPage != 200 {
		t.Fatalf("RFC7644-3.4.2.1-145a1a: expected count=500 clamped to 200 items, got len=%d itemsPerPage=%d", len(resources), itemsPerPage)
	}
	if totalResults != 205 {
		t.Fatalf("expected totalResults=205, got %d", totalResults)
	}

	// 2. Cursor pagination with count=500 (> maxPageSize 200) -> 400 tooMany (RFC7644-3.12-40cb84)
	curResp := doRequest(t, http.MethodGet, scimURL(env.server.URL, wsID, "/Users?cursor=&count=500"), token, "")
	curBody := readBody(t, curResp)
	assertScimErrorJSON(t, curResp.StatusCode, curBody, http.StatusBadRequest, "tooMany")

	// 3. POST /.search cursor pagination with count=201 -> 400 tooMany (RFC7644-3.12-40cb84)
	searchBuf, _ := json.Marshal(map[string]any{
		"schemas": []string{"urn:ietf:params:scim:api:messages:2.0:SearchRequest"},
		"cursor":  "",
		"count":   201,
	})
	postCurResp := doRequest(t, http.MethodPost, scimURL(env.server.URL, wsID, "/Users/.search"), token, string(bytes.TrimSpace(searchBuf)))
	postCurBody := readBody(t, postCurResp)
	assertScimErrorJSON(t, postCurResp.StatusCode, postCurBody, http.StatusBadRequest, "tooMany")
}

func TestNACompliance_Group5_VersionAgnosticRefCanonicalization(t *testing.T) {
	// RFC7643-2.4-63934b: Version-agnostic $ref resolution, deduplication, conflict rejection,
	// filtering, and PATCH removal across omitted-version, v1, and v2 SCIM URIs.
	env := setupTestEnv(t)

	wsID := uuid.New()
	token := generateToken()
	seedWorkspaceAndToken(t, env.ctx, wsID, token)

	user1 := uuid.New()
	user2 := uuid.New()
	mgr := uuid.New()
	seedUser(t, env.ctx, wsID, user1, "ref.user1@example.com", "Ref User 1")
	seedUser(t, env.ctx, wsID, user2, "ref.user2@example.com", "Ref User 2")
	seedUser(t, env.ctx, wsID, mgr, "ref.manager@example.com", "Ref Manager")

	expectedBase := scimURL(env.server.URL, wsID, "")
	expectedUser1Ref := expectedBase + "/Users/" + user1.String()
	expectedUser2Ref := expectedBase + "/Users/" + user2.String()
	expectedMgrRef := expectedBase + "/Users/" + mgr.String()

	// 1. $ref-only Group.members creation (value omitted) + deduplication when user1 is supplied
	// via BOTH omitted-version ("/Users/{id}") and v1 ("https://legacy.idp.example/scim/v1/Users/{id}") URIs.
	grpResp := doRequest(t, http.MethodPost, scimURL(env.server.URL, wsID, "/Groups"), token, fmt.Sprintf(`{
		"schemas": ["urn:ietf:params:scim:schemas:core:2.0:Group"],
		"displayName": "Version Agnostic Ref Group",
		"members": [
			{"$ref": "/Users/%s"},
			{"$ref": "https://legacy.idp.example/scim/v1/Users/%s"},
			{"$ref": "https://legacy.idp.example/scim/v1/Users/%s"}
		]
	}`, user1.String(), user1.String(), user2.String()))
	grpBody := readBody(t, grpResp)
	if grpResp.StatusCode != http.StatusCreated {
		t.Fatalf("POST /Groups with $ref-only version-different members returned %d, want 201: %s", grpResp.StatusCode, grpBody)
	}
	var grpMap map[string]any
	_ = json.Unmarshal([]byte(grpBody), &grpMap)
	groupID := grpMap["id"].(string)
	expectedGroupRef := expectedBase + "/Groups/" + groupID
	members, _ := grpMap["members"].([]any)
	if len(members) != 2 {
		t.Fatalf("expected 2 deduplicated members from 3 $ref entries, got %d: %s", len(members), grpBody)
	}
	refByValue := make(map[string]string)
	for _, m := range members {
		mm := m.(map[string]any)
		refByValue[mm["value"].(string)] = mm["$ref"].(string)
	}
	if refByValue[user1.String()] != expectedUser1Ref {
		t.Errorf("RFC7643-2.4-63934b: member1 $ref = %q, want canonical %q", refByValue[user1.String()], expectedUser1Ref)
	}
	if refByValue[user2.String()] != expectedUser2Ref {
		t.Errorf("RFC7643-2.4-63934b: member2 $ref = %q, want canonical %q", refByValue[user2.String()], expectedUser2Ref)
	}

	// 2. $ref-only EnterpriseUser manager creation (value omitted) + PATCH manager.$ref across unversioned and v1 URIs
	empResp := doRequest(t, http.MethodPost, scimURL(env.server.URL, wsID, "/Users"), token, fmt.Sprintf(`{
		"schemas": [
			"urn:ietf:params:scim:schemas:core:2.0:User",
			"urn:ietf:params:scim:schemas:extension:enterprise:2.0:User"
		],
		"userName": "ref.employee@example.com",
		"urn:ietf:params:scim:schemas:extension:enterprise:2.0:User": {
			"manager": {
				"$ref": "https://legacy.idp.example/scim/v1/Users/%s"
			}
		}
	}`, mgr.String()))
	empBody := readBody(t, empResp)
	if empResp.StatusCode != http.StatusCreated {
		t.Fatalf("POST /Users with $ref-only v1 manager returned %d, want 201: %s", empResp.StatusCode, empBody)
	}
	var empMap map[string]any
	_ = json.Unmarshal([]byte(empBody), &empMap)
	empID := empMap["id"].(string)
	entExt, _ := empMap["urn:ietf:params:scim:schemas:extension:enterprise:2.0:User"].(map[string]any)
	mgrMap, _ := entExt["manager"].(map[string]any)
	if mgrMap["value"] != mgr.String() || mgrMap["$ref"] != expectedMgrRef || mgrMap["displayName"] != "Ref Manager" {
		t.Fatalf("RFC7643-2.4-63934b: $ref-only manager = %v, want value=%s $ref=%s displayName=Ref Manager",
			mgrMap, mgr.String(), expectedMgrRef)
	}

	// PATCH manager.$ref directly with unversioned "/Users/{user1}" -> updates manager.value, canonical $ref, and displayName
	patchMgrRefResp := doRequest(t, http.MethodPatch, scimURL(env.server.URL, wsID, "/Users/"+empID), token, fmt.Sprintf(`{
		"schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
		"Operations": [{
			"op": "replace",
			"path": "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User:manager.$ref",
			"value": "/Users/%s"
		}]
	}`, user1.String()))
	patchMgrRefBody := readBody(t, patchMgrRefResp)
	if patchMgrRefResp.StatusCode != http.StatusOK {
		t.Fatalf("PATCH manager.$ref with unversioned URI returned %d, want 200: %s", patchMgrRefResp.StatusCode, patchMgrRefBody)
	}
	var patchedEmp map[string]any
	_ = json.Unmarshal([]byte(patchMgrRefBody), &patchedEmp)
	patchedMgr := patchedEmp["urn:ietf:params:scim:schemas:extension:enterprise:2.0:User"].(map[string]any)["manager"].(map[string]any)
	if patchedMgr["value"] != user1.String() || patchedMgr["$ref"] != expectedUser1Ref || patchedMgr["displayName"] != "Ref User 1" {
		t.Fatalf("PATCH manager.$ref result = %v, want value=%s $ref=%s displayName=Ref User 1",
			patchedMgr, user1.String(), expectedUser1Ref)
	}

	// Restore manager to mgr via PATCH manager object with $ref-only v1 URI
	restoreMgrResp := doRequest(t, http.MethodPatch, scimURL(env.server.URL, wsID, "/Users/"+empID), token, fmt.Sprintf(`{
		"schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
		"Operations": [{
			"op": "replace",
			"path": "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User:manager",
			"value": {"$ref": "https://legacy.idp.example/scim/v1/Users/%s"}
		}]
	}`, mgr.String()))
	restoreMgrBody := readBody(t, restoreMgrResp)
	if restoreMgrResp.StatusCode != http.StatusOK {
		t.Fatalf("PATCH manager $ref-only object returned %d, want 200: %s", restoreMgrResp.StatusCode, restoreMgrBody)
	}

	// 3. Conflicting value vs $ref UUID -> 400 invalidValue on Group.members and EnterpriseUser.manager
	badGroupResp := doRequest(t, http.MethodPost, scimURL(env.server.URL, wsID, "/Groups"), token, fmt.Sprintf(`{
		"schemas": ["urn:ietf:params:scim:schemas:core:2.0:Group"],
		"displayName": "Conflicting Member Ref Group",
		"members": [{"value": %q, "$ref": "/Users/%s"}]
	}`, user1.String(), user2.String()))
	assertScimErrorJSON(t, badGroupResp.StatusCode, readBody(t, badGroupResp), http.StatusBadRequest, "invalidValue")

	badPatchGroupResp := doRequest(t, http.MethodPatch, scimURL(env.server.URL, wsID, "/Groups/"+groupID), token, fmt.Sprintf(`{
		"schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
		"Operations": [{"op": "add", "path": "members", "value": [{"value": %q, "$ref": "https://legacy.idp.example/scim/v1/Users/%s"}]}]
	}`, user1.String(), user2.String()))
	assertScimErrorJSON(t, badPatchGroupResp.StatusCode, readBody(t, badPatchGroupResp), http.StatusBadRequest, "invalidValue")

	badMgrPostResp := doRequest(t, http.MethodPost, scimURL(env.server.URL, wsID, "/Users"), token, fmt.Sprintf(`{
		"schemas": [
			"urn:ietf:params:scim:schemas:core:2.0:User",
			"urn:ietf:params:scim:schemas:extension:enterprise:2.0:User"
		],
		"userName": "conflict.mgr@example.com",
		"urn:ietf:params:scim:schemas:extension:enterprise:2.0:User": {
			"manager": {"value": %q, "$ref": "/Users/%s"}
		}
	}`, mgr.String(), user1.String()))
	assertScimErrorJSON(t, badMgrPostResp.StatusCode, readBody(t, badMgrPostResp), http.StatusBadRequest, "invalidValue")

	badMgrPatchResp := doRequest(t, http.MethodPatch, scimURL(env.server.URL, wsID, "/Users/"+empID), token, fmt.Sprintf(`{
		"schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
		"Operations": [{
			"op": "replace",
			"path": "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User:manager",
			"value": {"value": %q, "$ref": "https://legacy.idp.example/scim/v1/Users/%s"}
		}]
	}`, mgr.String(), user1.String()))
	assertScimErrorJSON(t, badMgrPatchResp.StatusCode, readBody(t, badMgrPatchResp), http.StatusBadRequest, "invalidValue")

	// 4. Version-agnostic $ref filter queries across unversioned, v1, and v2 URIs
	for _, refVariant := range []string{
		"/Users/" + user1.String(),
		"https://legacy.idp.example/scim/v1/Users/" + user1.String(),
		expectedUser1Ref,
	} {
		q := "/Groups?filter=" + url.QueryEscape(fmt.Sprintf(`members.$ref eq %q`, refVariant))
		fResp := doRequest(t, http.MethodGet, scimURL(env.server.URL, wsID, q), token, "")
		fBody := readBody(t, fResp)
		if fResp.StatusCode != http.StatusOK {
			t.Fatalf("GET %s returned %d: %s", q, fResp.StatusCode, fBody)
		}
		var listMap map[string]any
		_ = json.Unmarshal([]byte(fBody), &listMap)
		if int(listMap["totalResults"].(float64)) != 1 {
			t.Fatalf("RFC7643-2.4-63934b: filter members.$ref eq %q matched %v groups, want 1: %s",
				refVariant, listMap["totalResults"], fBody)
		}
	}

	for _, mgrRefVariant := range []string{
		"/Users/" + mgr.String(),
		"https://legacy.idp.example/scim/v1/Users/" + mgr.String(),
		expectedMgrRef,
	} {
		q := "/Users?filter=" + url.QueryEscape(fmt.Sprintf(`urn:ietf:params:scim:schemas:extension:enterprise:2.0:User:manager.$ref eq %q`, mgrRefVariant))
		fResp := doRequest(t, http.MethodGet, scimURL(env.server.URL, wsID, q), token, "")
		fBody := readBody(t, fResp)
		if fResp.StatusCode != http.StatusOK {
			t.Fatalf("GET %s returned %d: %s", q, fResp.StatusCode, fBody)
		}
		var listMap map[string]any
		_ = json.Unmarshal([]byte(fBody), &listMap)
		if int(listMap["totalResults"].(float64)) != 1 {
			t.Fatalf("RFC7643-2.4-63934b: filter manager.$ref eq %q matched %v users, want 1: %s",
				mgrRefVariant, listMap["totalResults"], fBody)
		}
	}

	for _, grpRefVariant := range []string{
		"/Groups/" + groupID,
		"https://legacy.idp.example/scim/v1/Groups/" + groupID,
		expectedGroupRef,
	} {
		q := "/Users?filter=" + url.QueryEscape(fmt.Sprintf(`groups.$ref eq %q`, grpRefVariant))
		fResp := doRequest(t, http.MethodGet, scimURL(env.server.URL, wsID, q), token, "")
		fBody := readBody(t, fResp)
		if fResp.StatusCode != http.StatusOK {
			t.Fatalf("GET %s returned %d: %s", q, fResp.StatusCode, fBody)
		}
		var listMap map[string]any
		_ = json.Unmarshal([]byte(fBody), &listMap)
		if int(listMap["totalResults"].(float64)) != 2 {
			t.Fatalf("RFC7643-2.4-63934b: filter groups.$ref eq %q matched %v users, want 2: %s",
				grpRefVariant, listMap["totalResults"], fBody)
		}
	}

	// 5. PATCH member removal using unversioned valuePath $ref and v1 $ref object list
	rmPathResp := doRequest(t, http.MethodPatch, scimURL(env.server.URL, wsID, "/Groups/"+groupID), token, fmt.Sprintf(`{
		"schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
		"Operations": [{"op": "remove", "path": "members[$ref eq \"/Users/%s\"]"}]
	}`, user1.String()))
	rmPathBody := readBody(t, rmPathResp)
	if rmPathResp.StatusCode != http.StatusOK {
		t.Fatalf("PATCH remove members[$ref eq \"/Users/...\"] returned %d, want 200: %s", rmPathResp.StatusCode, rmPathBody)
	}
	var afterRm1 map[string]any
	_ = json.Unmarshal([]byte(rmPathBody), &afterRm1)
	remMembers1, _ := afterRm1["members"].([]any)
	if len(remMembers1) != 1 || remMembers1[0].(map[string]any)["value"] != user2.String() {
		t.Fatalf("expected only user2 remaining after unversioned $ref path removal, got %v", remMembers1)
	}

	rmListResp := doRequest(t, http.MethodPatch, scimURL(env.server.URL, wsID, "/Groups/"+groupID), token, fmt.Sprintf(`{
		"schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
		"Operations": [{"op": "remove", "path": "members", "value": [{"$ref": "https://legacy.idp.example/scim/v1/Users/%s"}]}]
	}`, user2.String()))
	rmListBody := readBody(t, rmListResp)
	if rmListResp.StatusCode != http.StatusOK {
		t.Fatalf("PATCH remove members via v1 $ref list returned %d, want 200: %s", rmListResp.StatusCode, rmListBody)
	}
	var afterRm2 map[string]any
	_ = json.Unmarshal([]byte(rmListBody), &afterRm2)
	if remMembers2, _ := afterRm2["members"].([]any); len(remMembers2) != 0 {
		t.Fatalf("expected 0 members remaining after v1 $ref list removal, got %v", remMembers2)
	}
}
