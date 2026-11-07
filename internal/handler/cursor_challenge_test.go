package handler

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/scimsandbox/scim-server-impl-go/internal/middleware"
	"github.com/scimsandbox/scim-server-impl-go/internal/scim"
)

// Helper to make base64url unpadded token
func makeCursorToken(payload string) string {
	b64 := base64.RawURLEncoding.EncodeToString([]byte(payload))
	return scim.CursorPrefix + b64
}

func verifyScimError(t *testing.T, rec *httptest.ResponseRecorder, expectedScimType string, caseName string) {
	t.Helper()
	if rec.Code != http.StatusBadRequest {
		t.Errorf("[%s] HTTP status = %d, want 400", caseName, rec.Code)
	}

	ct := rec.Header().Get("Content-Type")
	if !strings.HasPrefix(ct, "application/scim+json") {
		t.Errorf("[%s] Content-Type = %q, want application/scim+json prefix", caseName, ct)
	}

	var resp map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("[%s] failed to unmarshal response body JSON: %v, raw: %s", caseName, err, rec.Body.String())
	}

	if statusVal, ok := resp["status"].(string); !ok || statusVal != "400" {
		t.Errorf("[%s] response status = %v, want \"400\"", caseName, resp["status"])
	}

	scimType, _ := resp["scimType"].(string)
	if expectedScimType == "invalidValueOrInvalidCursor" {
		if scimType != "invalidValue" && scimType != "invalidCursor" {
			t.Errorf("[%s] scimType = %q, want invalidValue or invalidCursor", caseName, scimType)
		}
	} else {
		if scimType != expectedScimType {
			t.Errorf("[%s] scimType = %q, want %q", caseName, scimType, expectedScimType)
		}
	}
}

func TestCursorAdversarial_Cases_Go(t *testing.T) {
	wsID := uuid.New()
	wsOther := uuid.New()
	futureExp := time.Now().UTC().Add(time.Hour).Unix()
	pastExp := time.Now().UTC().Add(-time.Hour).Unix()

	validToken, err := scim.EncodeCursor(wsID, 10, 3600)
	if err != nil {
		t.Fatalf("failed to encode valid cursor: %v", err)
	}

	uh := &UserHandler{}
	gh := &GroupHandler{}
	dh := &DiscoveryHandler{}

	// Adversarial test cases mapping
	testCases := []struct {
		name         string
		token        string
		expectedType string
	}{
		{
			name:         "Case 1: Malformed token prefix",
			token:        "badprefix_eyJ3Ijoi" + base64.RawURLEncoding.EncodeToString([]byte(fmt.Sprintf(`{"w":"%s","o":10,"exp":%d}`, wsID, futureExp))),
			expectedType: "invalidCursor",
		},
		{
			name:         "Case 2: Corrupted Base64",
			token:        "scim_cur_!!!not_base64!!!",
			expectedType: "invalidCursor",
		},
		{
			name:         "Case 3: Corrupted JSON payload",
			token:        makeCursorToken("{corrupted:json"),
			expectedType: "invalidCursor",
		},
		{
			name:         "Case 4a: Missing required payload fields - missing workspace w (o only)",
			token:        makeCursorToken(`{"o": 10}`),
			expectedType: "invalidCursor",
		},
		{
			name:         "Case 4b: Missing required payload fields - missing workspace w (o and exp)",
			token:        makeCursorToken(fmt.Sprintf(`{"o": 10, "exp": %d}`, futureExp)),
			expectedType: "invalidCursor",
		},
		{
			name:         "Case 4c: Missing required payload fields - literal missing offset o",
			token:        makeCursorToken(`{"w": "..."}`),
			expectedType: "invalidCursor",
		},
		{
			name:         "Case 4d: Missing required payload fields - valid ws but missing offset o and exp",
			token:        makeCursorToken(fmt.Sprintf(`{"w": "%s"}`, wsID)),
			expectedType: "invalidCursor",
		},
		{
			name:         "Case 4e: Missing required payload fields - missing offset o with future exp",
			token:        makeCursorToken(fmt.Sprintf(`{"w": "%s", "exp": %d}`, wsID, futureExp)),
			expectedType: "invalidCursor",
		},
		{
			name:         "Case 5: Workspace mismatch",
			token:        makeCursorToken(fmt.Sprintf(`{"w":"%s","o":10,"exp":%d}`, wsOther, futureExp)),
			expectedType: "invalidCursor",
		},
		{
			name:         "Case 6: Negative offset",
			token:        makeCursorToken(fmt.Sprintf(`{"w":"%s","o":-5,"exp":%d}`, wsID, futureExp)),
			expectedType: "invalidCursor",
		},
		{
			name:         "Case 7: Expired token",
			token:        makeCursorToken(fmt.Sprintf(`{"w":"%s","o":10,"exp":%d}`, wsID, pastExp)),
			expectedType: "invalidCursor",
		},
	}

	for _, tc := range testCases {
		t.Run("GET_Users_"+tc.name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodGet, "/Users?cursor="+tc.token, nil)
			req = req.WithContext(context.WithValue(req.Context(), middleware.WorkspaceIDKey, wsID))

			uh.ListUsers(rec, req)
			verifyScimError(t, rec, tc.expectedType, tc.name)
		})

		t.Run("POST_UsersSearch_"+tc.name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			bodyBytes, _ := json.Marshal(map[string]any{"cursor": tc.token})
			req := httptest.NewRequest(http.MethodPost, "/Users/.search", bytes.NewReader(bodyBytes))
			req.Header.Set("Content-Type", "application/scim+json")
			req = req.WithContext(context.WithValue(req.Context(), middleware.WorkspaceIDKey, wsID))

			uh.SearchUsers(rec, req)
			verifyScimError(t, rec, tc.expectedType, tc.name)
		})

		t.Run("GET_Groups_"+tc.name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodGet, "/Groups?cursor="+tc.token, nil)
			req = req.WithContext(context.WithValue(req.Context(), middleware.WorkspaceIDKey, wsID))

			gh.ListGroups(rec, req)
			verifyScimError(t, rec, tc.expectedType, tc.name)
		})

		t.Run("POST_GroupsSearch_"+tc.name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			bodyBytes, _ := json.Marshal(map[string]any{"cursor": tc.token})
			req := httptest.NewRequest(http.MethodPost, "/Groups/.search", bytes.NewReader(bodyBytes))
			req.Header.Set("Content-Type", "application/scim+json")
			req = req.WithContext(context.WithValue(req.Context(), middleware.WorkspaceIDKey, wsID))

			gh.SearchGroups(rec, req)
			verifyScimError(t, rec, tc.expectedType, tc.name)
		})

		t.Run("GET_Root_"+tc.name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodGet, "/?cursor="+tc.token, nil)
			req = req.WithContext(context.WithValue(req.Context(), middleware.WorkspaceIDKey, wsID))

			dh.RootSearch(rec, req)
			verifyScimError(t, rec, tc.expectedType, tc.name)
		})

		t.Run("POST_RootSearch_"+tc.name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			bodyBytes, _ := json.Marshal(map[string]any{"cursor": tc.token})
			req := httptest.NewRequest(http.MethodPost, "/.search", bytes.NewReader(bodyBytes))
			req.Header.Set("Content-Type", "application/scim+json")
			req = req.WithContext(context.WithValue(req.Context(), middleware.WorkspaceIDKey, wsID))

			dh.RootSearch(rec, req)
			verifyScimError(t, rec, tc.expectedType, tc.name)
		})
	}

	// Case 8: Mutual exclusivity
	mutualExclusivityCases := []struct {
		name    string
		handler func(w http.ResponseWriter, r *http.Request)
		method  string
		url     string
		body    map[string]any
	}{
		{
			name:    "8a_GET_Users_query_cursor_and_startIndex",
			handler: uh.ListUsers,
			method:  http.MethodGet,
			url:     "/Users?cursor=" + validToken + "&startIndex=1",
		},
		{
			name:    "8b_POST_Users_body_cursor_and_startIndex",
			handler: uh.SearchUsers,
			method:  http.MethodPost,
			url:     "/Users/.search",
			body:    map[string]any{"cursor": validToken, "startIndex": 1},
		},
		{
			name:    "8c_GET_Groups_query_cursor_and_startIndex",
			handler: gh.ListGroups,
			method:  http.MethodGet,
			url:     "/Groups?cursor=" + validToken + "&startIndex=1",
		},
		{
			name:    "8d_POST_Groups_body_cursor_and_startIndex",
			handler: gh.SearchGroups,
			method:  http.MethodPost,
			url:     "/Groups/.search",
			body:    map[string]any{"cursor": validToken, "startIndex": 1},
		},
		{
			name:    "8e_GET_Root_query_cursor_and_startIndex",
			handler: dh.RootSearch,
			method:  http.MethodGet,
			url:     "/?cursor=" + validToken + "&startIndex=1",
		},
		{
			name:    "8f_POST_RootSearch_body_cursor_and_startIndex",
			handler: dh.RootSearch,
			method:  http.MethodPost,
			url:     "/.search",
			body:    map[string]any{"cursor": validToken, "startIndex": 1},
		},
		{
			name:    "8g_POST_Users_body_cursor_and_query_startIndex",
			handler: uh.SearchUsers,
			method:  http.MethodPost,
			url:     "/Users/.search?startIndex=1",
			body:    map[string]any{"cursor": validToken},
		},
		{
			name:    "8h_POST_RootSearch_body_cursor_and_query_startIndex",
			handler: dh.RootSearch,
			method:  http.MethodPost,
			url:     "/.search?startIndex=1",
			body:    map[string]any{"cursor": validToken},
		},
	}

	for _, mc := range mutualExclusivityCases {
		t.Run(mc.name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			var req *http.Request
			if mc.body != nil {
				b, _ := json.Marshal(mc.body)
				req = httptest.NewRequest(mc.method, mc.url, bytes.NewReader(b))
				req.Header.Set("Content-Type", "application/scim+json")
			} else {
				req = httptest.NewRequest(mc.method, mc.url, nil)
			}
			req = req.WithContext(context.WithValue(req.Context(), middleware.WorkspaceIDKey, wsID))

			mc.handler(rec, req)
			verifyScimError(t, rec, "invalidValueOrInvalidCursor", mc.name)
		})
	}
}

// TestCursorAdversarial_MissingOffsetWithFutureExp_Finding verifies that when a token has valid workspace and future exp,
// but omits "o", DecodeCursor correctly rejects it with 400 invalidCursor (missing offset parameter).
func TestCursorAdversarial_MissingOffsetWithFutureExp_Finding(t *testing.T) {
	wsID := uuid.New()
	futureExp := time.Now().UTC().Add(time.Hour).Unix()
	token := makeCursorToken(fmt.Sprintf(`{"w": "%s", "exp": %d}`, wsID, futureExp))

	offset, err := scim.DecodeCursor(token, wsID)
	if err == nil {
		t.Fatalf("expected error for missing offset 'o' with future exp, got nil (offset=%d)", offset)
	}
	scimErr, ok := err.(*scim.ScimError)
	if !ok || scimErr.Status != http.StatusBadRequest || scimErr.ScimType != "invalidCursor" {
		t.Fatalf("expected 400 invalidCursor, got: %v", err)
	}
	if !strings.Contains(scimErr.Detail, "missing offset parameter") {
		t.Errorf("detail = %q, want 'missing offset parameter'", scimErr.Detail)
	}
}

// ─── Empirical Challenger Verification Suite for RFC 9865 Multi-Page Cursor Traversal ───

func TestCursorTraversalEmpiricalChallenger_InitialPageProbe(t *testing.T) {
	wsID := uuid.New()
	pag := &PaginationRequest{
		IsCursor: true,
		Offset:   0,
		Count:    1,
	}
	resources := []map[string]any{{"id": "user-1", "userName": "alice"}}

	resp := buildListResponse(pag, wsID, 3, resources)

	// 1. In cursor mode, startIndex MUST be omitted
	if _, exists := resp["startIndex"]; exists {
		t.Errorf("startIndex MUST be omitted from map in cursor mode")
	}

	// 2. previousCursor MUST be omitted on the initial page
	if _, exists := resp["previousCursor"]; exists {
		t.Errorf("previousCursor MUST be omitted on initial page")
	}

	// 3. nextCursor MUST be present when totalResults > count
	nextCur, ok := resp["nextCursor"].(string)
	if !ok || nextCur == "" {
		t.Fatalf("expected nextCursor to be present and non-empty")
	}
	if !strings.HasPrefix(nextCur, scim.CursorPrefix) {
		t.Errorf("nextCursor %q must have prefix %q", nextCur, scim.CursorPrefix)
	}

	decodedOffset, err := scim.DecodeCursor(nextCur, wsID)
	if err != nil {
		t.Fatalf("failed to decode nextCursor: %v", err)
	}
	if decodedOffset != 1 {
		t.Errorf("decoded nextCursor offset = %d, want 1", decodedOffset)
	}

	// 4. Verify serialized JSON representation
	jsonBytes, err := json.Marshal(resp)
	if err != nil {
		t.Fatalf("failed to marshal JSON: %v", err)
	}
	jsonStr := string(jsonBytes)
	if strings.Contains(jsonStr, `"startIndex"`) {
		t.Errorf("startIndex MUST be absent from JSON: %s", jsonStr)
	}
	if strings.Contains(jsonStr, `"previousCursor"`) {
		t.Errorf("previousCursor MUST be absent from JSON on initial page: %s", jsonStr)
	}
	if !strings.Contains(jsonStr, `"nextCursor"`) {
		t.Errorf("nextCursor MUST be present in JSON: %s", jsonStr)
	}
}

func TestCursorTraversalEmpiricalChallenger_MultiPageForwardAndBackward(t *testing.T) {
	wsID := uuid.New()

	// Step 1: Probe Page 1 (offset 0, count 1, total 3)
	p1Pag := &PaginationRequest{IsCursor: true, Offset: 0, Count: 1}
	p1Resp := buildListResponse(p1Pag, wsID, 3, []map[string]any{{"userName": "alice"}})
	nextCursor1, ok := p1Resp["nextCursor"].(string)
	if !ok || nextCursor1 == "" {
		t.Fatalf("page 1 missing nextCursor")
	}

	// Step 2: Request Page 2 with cursor=nextCursor1
	q2 := url.Values{"cursor": []string{nextCursor1}, "count": []string{"1"}}
	p2Pag, scimErr := parsePagination(q2, nil, wsID, 10)
	if scimErr != nil {
		t.Fatalf("failed to parse pagination for page 2: %v", scimErr)
	}
	if p2Pag.Offset != 1 {
		t.Fatalf("page 2 offset = %d, want 1", p2Pag.Offset)
	}

	p2Resp := buildListResponse(p2Pag, wsID, 3, []map[string]any{{"userName": "bob"}})
	if _, exists := p2Resp["startIndex"]; exists {
		t.Errorf("page 2 must omit startIndex")
	}

	prevCursor2, hasPrev := p2Resp["previousCursor"].(string)
	if !hasPrev || prevCursor2 == "" {
		t.Fatalf("page 2 must have previousCursor")
	}
	nextCursor2, hasNext := p2Resp["nextCursor"].(string)
	if !hasNext || nextCursor2 == "" {
		t.Fatalf("page 2 must have nextCursor when results remain")
	}

	decodedPrev2, _ := scim.DecodeCursor(prevCursor2, wsID)
	if decodedPrev2 != 0 {
		t.Errorf("page 2 previousCursor offset = %d, want 0", decodedPrev2)
	}
	decodedNext2, _ := scim.DecodeCursor(nextCursor2, wsID)
	if decodedNext2 != 2 {
		t.Errorf("page 2 nextCursor offset = %d, want 2", decodedNext2)
	}

	// Step 3: Backward navigation to Page 1 using prevCursor2
	qBack := url.Values{"cursor": []string{prevCursor2}, "count": []string{"1"}}
	backPag, scimErr := parsePagination(qBack, nil, wsID, 10)
	if scimErr != nil {
		t.Fatalf("failed to parse pagination for backward nav: %v", scimErr)
	}
	if backPag.Offset != 0 {
		t.Fatalf("backward nav offset = %d, want 0", backPag.Offset)
	}

	backResp := buildListResponse(backPag, wsID, 3, []map[string]any{{"userName": "alice"}})
	if _, exists := backResp["previousCursor"]; exists {
		t.Errorf("navigating back to page 1 must omit previousCursor")
	}
	if _, exists := backResp["nextCursor"]; !exists {
		t.Errorf("navigating back to page 1 must have nextCursor")
	}
	resBack := backResp["Resources"].([]map[string]any)
	if len(resBack) != 1 || resBack[0]["userName"] != "alice" {
		t.Errorf("backward navigation must return page 1 resources (alice), got %v", resBack)
	}
}

func TestCursorTraversalEmpiricalChallenger_FinalPage(t *testing.T) {
	wsID := uuid.New()
	tokenPage3, err := scim.EncodeCursor(wsID, 2, 3600)
	if err != nil {
		t.Fatalf("failed to encode page 3 cursor: %v", err)
	}

	q := url.Values{"cursor": []string{tokenPage3}, "count": []string{"1"}}
	pag, scimErr := parsePagination(q, nil, wsID, 10)
	if scimErr != nil {
		t.Fatalf("failed to parse page 3 pagination: %v", scimErr)
	}

	resp := buildListResponse(pag, wsID, 3, []map[string]any{{"userName": "carol"}})

	if _, exists := resp["startIndex"]; exists {
		t.Errorf("final page must omit startIndex")
	}
	if _, exists := resp["previousCursor"]; !exists {
		t.Errorf("final page must have previousCursor")
	}
	if _, exists := resp["nextCursor"]; exists {
		t.Errorf("final page MUST omit nextCursor")
	}

	jsonBytes, _ := json.Marshal(resp)
	jsonStr := string(jsonBytes)
	if strings.Contains(jsonStr, `"nextCursor"`) {
		t.Errorf("nextCursor MUST be absent from JSON on final page: %s", jsonStr)
	}
	if !strings.Contains(jsonStr, `"previousCursor"`) {
		t.Errorf("previousCursor MUST be present in JSON on final page: %s", jsonStr)
	}
}

func TestCursorTraversalEmpiricalChallenger_EmptyResultSet(t *testing.T) {
	wsID := uuid.New()
	pag := &PaginationRequest{
		IsCursor: true,
		Offset:   0,
		Count:    10,
	}

	resp := buildListResponse(pag, wsID, 0, []map[string]any{})

	if _, exists := resp["startIndex"]; exists {
		t.Errorf("startIndex must be omitted on empty result set")
	}
	if _, exists := resp["previousCursor"]; exists {
		t.Errorf("previousCursor must be omitted on empty result set")
	}
	if _, exists := resp["nextCursor"]; exists {
		t.Errorf("nextCursor must be omitted on empty result set")
	}

	jsonBytes, _ := json.Marshal(resp)
	jsonStr := string(jsonBytes)
	if strings.Contains(jsonStr, `"startIndex"`) {
		t.Errorf("startIndex must be absent from JSON on empty result set")
	}
	if strings.Contains(jsonStr, `"previousCursor"`) {
		t.Errorf("previousCursor must be absent from JSON on empty result set")
	}
	if strings.Contains(jsonStr, `"nextCursor"`) {
		t.Errorf("nextCursor must be absent from JSON on empty result set")
	}

	// End-to-end check on RootSearch handler (GET and POST with 0 resources)
	dh := NewDiscoveryHandler()

	// GET /?cursor=
	recGet := httptest.NewRecorder()
	reqGet := httptest.NewRequest(http.MethodGet, "/?cursor=&count=10", nil)
	reqGet = reqGet.WithContext(context.WithValue(reqGet.Context(), middleware.WorkspaceIDKey, wsID))
	dh.RootSearch(recGet, reqGet)
	if recGet.Code != http.StatusOK {
		t.Fatalf("GET /?cursor= expected 200, got %d: %s", recGet.Code, recGet.Body.String())
	}
	getStr := recGet.Body.String()
	if strings.Contains(getStr, `"startIndex"`) || strings.Contains(getStr, `"previousCursor"`) || strings.Contains(getStr, `"nextCursor"`) {
		t.Errorf("GET /?cursor= empty result set leaked cursor/startIndex fields: %s", getStr)
	}

	// POST /.search with cursor
	recPost := httptest.NewRecorder()
	reqPost := httptest.NewRequest(http.MethodPost, "/.search", strings.NewReader(`{"cursor":"","count":10}`))
	reqPost.Header.Set("Content-Type", "application/scim+json")
	reqPost = reqPost.WithContext(context.WithValue(reqPost.Context(), middleware.WorkspaceIDKey, wsID))
	dh.RootSearch(recPost, reqPost)
	if recPost.Code != http.StatusOK {
		t.Fatalf("POST /.search expected 200, got %d: %s", recPost.Code, recPost.Body.String())
	}
	postStr := recPost.Body.String()
	if strings.Contains(postStr, `"startIndex"`) || strings.Contains(postStr, `"previousCursor"`) || strings.Contains(postStr, `"nextCursor"`) {
		t.Errorf("POST /.search empty result set leaked cursor/startIndex fields: %s", postStr)
	}
}

func TestCursorTraversalEmpiricalChallenger_SingleItemResultSet(t *testing.T) {
	wsID := uuid.New()
	pag := &PaginationRequest{
		IsCursor: true,
		Offset:   0,
		Count:    1,
	}

	resp := buildListResponse(pag, wsID, 1, []map[string]any{{"userName": "solo"}})

	if _, exists := resp["startIndex"]; exists {
		t.Errorf("startIndex must be omitted")
	}
	if _, exists := resp["previousCursor"]; exists {
		t.Errorf("previousCursor must be omitted when offset == 0")
	}
	if _, exists := resp["nextCursor"]; exists {
		t.Errorf("nextCursor must be omitted when single item is final page")
	}

	jsonBytes, _ := json.Marshal(resp)
	jsonStr := string(jsonBytes)
	if strings.Contains(jsonStr, `"previousCursor"`) || strings.Contains(jsonStr, `"nextCursor"`) {
		t.Errorf("both cursors must be absent from JSON on single item page: %s", jsonStr)
	}
}

func TestCursorTraversalEmpiricalChallenger_EndpointParity(t *testing.T) {
	wsID := uuid.New()

	endpoints := []struct {
		name      string
		query     url.Values
		body      map[string]any
		expectCur bool
	}{
		{"GET /Users", url.Values{"cursor": []string{""}}, nil, true},
		{"POST /Users/.search", url.Values{}, map[string]any{"cursor": ""}, true},
		{"GET /Groups", url.Values{"cursor": []string{""}}, nil, true},
		{"POST /Groups/.search", url.Values{}, map[string]any{"cursor": ""}, true},
		{"GET / (RootSearch)", url.Values{"cursor": []string{""}}, nil, true},
		{"POST /.search", url.Values{}, map[string]any{"cursor": ""}, true},
	}

	for _, ep := range endpoints {
		t.Run(ep.name, func(t *testing.T) {
			pag, err := parsePagination(ep.query, ep.body, wsID, 10)
			if err != nil {
				t.Fatalf("unexpected error parsing pagination for %s: %v", ep.name, err)
			}
			if pag.IsCursor != ep.expectCur {
				t.Errorf("%s: IsCursor = %v, want %v", ep.name, pag.IsCursor, ep.expectCur)
			}
			if pag.Offset != 0 {
				t.Errorf("%s: Offset = %d, want 0", ep.name, pag.Offset)
			}

			// Verify mutual exclusivity rejection
			qExcl := make(url.Values)
			for k, v := range ep.query {
				qExcl[k] = v
			}
			bodyExcl := make(map[string]any)
			for k, v := range ep.body {
				bodyExcl[k] = v
			}
			if ep.body != nil {
				bodyExcl["startIndex"] = float64(1)
			} else {
				qExcl.Set("startIndex", "1")
			}
			_, scimErr := parsePagination(qExcl, bodyExcl, wsID, 10)
			if scimErr == nil {
				t.Errorf("%s: expected mutual exclusivity error, got nil", ep.name)
			}
			if scimErr != nil && scimErr.Status != http.StatusBadRequest {
				t.Errorf("%s: error status = %d, want 400", ep.name, scimErr.Status)
			}
		})
	}
}


