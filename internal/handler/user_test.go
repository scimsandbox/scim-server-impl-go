package handler

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/scimsandbox/scim-server-impl-go/internal/middleware"
	"github.com/scimsandbox/scim-server-impl-go/internal/scim"
)

func TestUserHandler_ListUsers_MissingWorkspace(t *testing.T) {
	uh := &UserHandler{}
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/Users", nil)

	uh.ListUsers(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", rec.Code)
	}
}

func TestUserHandler_ListUsers_MutualExclusion_CUR01_Validation(t *testing.T) {
	uh := &UserHandler{}
	rec := httptest.NewRecorder()
	wsID := uuid.New()
	req := httptest.NewRequest(http.MethodGet, "/Users?cursor=&startIndex=1", nil)
	req = req.WithContext(context.WithValue(req.Context(), middleware.WorkspaceIDKey, wsID))

	uh.ListUsers(rec, req)
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

func TestUserHandler_ListUsers_InvalidCursor_CUR04(t *testing.T) {
	uh := &UserHandler{}
	rec := httptest.NewRecorder()
	wsID := uuid.New()
	req := httptest.NewRequest(http.MethodGet, "/Users?cursor=invalid-opaque-cursor-999", nil)
	req = req.WithContext(context.WithValue(req.Context(), middleware.WorkspaceIDKey, wsID))

	uh.ListUsers(rec, req)
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

func TestUserHandler_ListUsers_WorkspaceMismatch(t *testing.T) {
	uh := &UserHandler{}
	rec := httptest.NewRecorder()
	wsA := uuid.New()
	wsB := uuid.New()

	token, err := scim.EncodeCursor(wsA, 10, 3600)
	if err != nil {
		t.Fatalf("failed to encode cursor: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/Users?cursor="+token, nil)
	req = req.WithContext(context.WithValue(req.Context(), middleware.WorkspaceIDKey, wsB))

	uh.ListUsers(rec, req)
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

func TestUserHandler_SearchUsers_MutualExclusion_CUR01(t *testing.T) {
	uh := &UserHandler{}
	rec := httptest.NewRecorder()
	wsID := uuid.New()
	body := `{"schemas":["urn:ietf:params:scim:api:messages:2.0:SearchRequest"],"cursor":"","startIndex":1}`
	req := httptest.NewRequest(http.MethodPost, "/Users/.search", strings.NewReader(body))
	req = req.WithContext(context.WithValue(req.Context(), middleware.WorkspaceIDKey, wsID))

	uh.SearchUsers(rec, req)
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

func TestUserHandler_SearchUsers_InvalidCursor(t *testing.T) {
	uh := &UserHandler{}
	rec := httptest.NewRecorder()
	wsID := uuid.New()
	body := `{"schemas":["urn:ietf:params:scim:api:messages:2.0:SearchRequest"],"cursor":"bad-cursor"}`
	req := httptest.NewRequest(http.MethodPost, "/Users/.search", strings.NewReader(body))
	req = req.WithContext(context.WithValue(req.Context(), middleware.WorkspaceIDKey, wsID))

	uh.SearchUsers(rec, req)
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

func TestUserHandler_SearchUsers_NonStringCursor(t *testing.T) {
	uh := &UserHandler{}
	rec := httptest.NewRecorder()
	wsID := uuid.New()
	body := `{"schemas":["urn:ietf:params:scim:api:messages:2.0:SearchRequest"],"cursor":12345}`
	req := httptest.NewRequest(http.MethodPost, "/Users/.search", strings.NewReader(body))
	req = req.WithContext(context.WithValue(req.Context(), middleware.WorkspaceIDKey, wsID))

	uh.SearchUsers(rec, req)
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

func TestNonBulkEndpoints_RejectBodyOver1MiBWith413ScimError(t *testing.T) {
	t.Parallel()

	wsID := uuid.New()
	resID := uuid.New().String()
	oversizedJSON := `{"userName":"` + strings.Repeat("a", (1<<20)+1024) + `"}`

	uh := &UserHandler{}
	gh := &GroupHandler{}
	dh := NewDiscoveryHandler(uh, gh)
	bh := &BulkHandler{}

	withParams := func(req *http.Request, id string) *http.Request {
		ctx := context.WithValue(req.Context(), middleware.WorkspaceIDKey, wsID)
		rctx := chi.NewRouteContext()
		rctx.URLParams.Add("workspaceId", wsID.String())
		if id != "" {
			rctx.URLParams.Add("id", id)
		}
		return req.WithContext(context.WithValue(ctx, chi.RouteCtxKey, rctx))
	}

	endpoints := []struct {
		name   string
		method string
		path   string
		id     string
		invoke func(http.ResponseWriter, *http.Request)
	}{
		{"POST /Users", http.MethodPost, "/Users", "", uh.CreateUser},
		{"PUT /Users/{id}", http.MethodPut, "/Users/" + resID, resID, uh.ReplaceUser},
		{"PATCH /Users/{id}", http.MethodPatch, "/Users/" + resID, resID, uh.PatchUser},
		{"POST /Users/.search", http.MethodPost, "/Users/.search", "", uh.SearchUsers},
		{"POST /Groups", http.MethodPost, "/Groups", "", gh.CreateGroup},
		{"PUT /Groups/{id}", http.MethodPut, "/Groups/" + resID, resID, gh.ReplaceGroup},
		{"PATCH /Groups/{id}", http.MethodPatch, "/Groups/" + resID, resID, gh.PatchGroup},
		{"POST /Groups/.search", http.MethodPost, "/Groups/.search", "", gh.SearchGroups},
		{"POST /.search", http.MethodPost, "/.search", "", dh.RootSearch},
	}

	for _, ep := range endpoints {
		for _, chunked := range []bool{false, true} {
			mode := "content-length"
			if chunked {
				mode = "chunked-stream"
			}
			t.Run(ep.name+"/"+mode, func(t *testing.T) {
				rec := httptest.NewRecorder()
				var bodyReader io.Reader = strings.NewReader(oversizedJSON)
				if chunked {
					bodyReader = io.NopCloser(strings.NewReader(oversizedJSON))
				}
				req := httptest.NewRequest(ep.method, ep.path, bodyReader)
				if chunked {
					req.ContentLength = -1
				}
				req = withParams(req, ep.id)

				ep.invoke(rec, req)

				if rec.Code != http.StatusRequestEntityTooLarge {
					t.Fatalf("%s (%s): status = %d, want 413; body=%s", ep.name, mode, rec.Code, rec.Body.String())
				}
				if ct := rec.Header().Get("Content-Type"); ct != "application/scim+json" {
					t.Fatalf("%s (%s): Content-Type = %q, want application/scim+json", ep.name, mode, ct)
				}
				var scimResp map[string]any
				if err := json.Unmarshal(rec.Body.Bytes(), &scimResp); err != nil {
					t.Fatalf("%s (%s): invalid JSON response: %v", ep.name, mode, err)
				}
				if scimResp["status"] != "413" {
					t.Fatalf("%s (%s): body status = %v, want \"413\"", ep.name, mode, scimResp["status"])
				}
				schemas, ok := scimResp["schemas"].([]any)
				if !ok || len(schemas) != 1 || schemas[0] != "urn:ietf:params:scim:api:messages:2.0:Error" {
					t.Fatalf("%s (%s): unexpected schemas = %v", ep.name, mode, scimResp["schemas"])
				}
			})
		}
	}

	// Verify Bulk's dedicated maxPayloadSize 413 message remains intact.
	t.Run("POST /Bulk preserves maxPayloadSize detail", func(t *testing.T) {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/Bulk", io.NopCloser(strings.NewReader(oversizedJSON)))
		req.ContentLength = -1
		req = withParams(req, "")
		bh.ProcessBulk(rec, req)

		if rec.Code != http.StatusRequestEntityTooLarge {
			t.Fatalf("Bulk status = %d, want 413", rec.Code)
		}
		if !strings.Contains(rec.Body.String(), "maxPayloadSize") {
			t.Fatalf("Bulk 413 body missing maxPayloadSize detail: %s", rec.Body.String())
		}
	})
}

func TestUserHandler_CreateUser_PasswordOver72UTF8BytesReturns400InvalidValue(t *testing.T) {
	t.Parallel()

	uh := &UserHandler{}
	wsID := uuid.New()

	for _, pw := range []string{
		strings.Repeat("x", 73),
		strings.Repeat("€", 25), // 75 UTF-8 bytes
	} {
		payload, _ := json.Marshal(map[string]any{
			"schemas":  []string{scim.UserSchemaURN},
			"userName": "alice@example.com",
			"password": pw,
		})
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/Users", strings.NewReader(string(payload)))
		req = req.WithContext(context.WithValue(req.Context(), middleware.WorkspaceIDKey, wsID))

		uh.CreateUser(rec, req)

		if rec.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, want 400; body=%s", rec.Code, rec.Body.String())
		}
		var resp map[string]any
		if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
			t.Fatalf("invalid JSON: %v", err)
		}
		if resp["status"] != "400" || resp["scimType"] != "invalidValue" {
			t.Fatalf("got status=%v scimType=%v, want 400 invalidValue", resp["status"], resp["scimType"])
		}
	}
}

func TestUserHandler_ReplaceUser_InvalidPasswordReturns400BeforeAsyncDispatch(t *testing.T) {
	t.Parallel()

	wsID := uuid.New()
	userID := uuid.New()

	invalidPayloads := []struct {
		name string
		body map[string]any
	}{
		{
			name: "over 72 ASCII bytes",
			body: map[string]any{
				"schemas":  []string{scim.UserSchemaURN},
				"userName": "alice@example.com",
				"password": strings.Repeat("x", 73),
			},
		},
		{
			name: "empty password",
			body: map[string]any{
				"schemas":  []string{scim.UserSchemaURN},
				"userName": "alice@example.com",
				"password": "",
			},
		},
		{
			name: "non-string password",
			body: map[string]any{
				"schemas":  []string{scim.UserSchemaURN},
				"userName": "alice@example.com",
				"password": 12345,
			},
		},
		{
			name: "mixed valid password and invalid Password sibling",
			body: map[string]any{
				"schemas":  []string{scim.UserSchemaURN},
				"userName": "alice@example.com",
				"password": "ValidPassword!1",
				"Password": 12345,
			},
		},
	}

	for _, tc := range invalidPayloads {
		for _, asyncMode := range []bool{false, true} {
			mode := "sync"
			if asyncMode {
				mode = "respond-async"
			}
			t.Run(tc.name+"/"+mode, func(t *testing.T) {
				asyncRepo := newMockAsyncEventRepo()
				uh := NewUserHandler(nil, nil, nil, asyncRepo)

				rawBody, _ := json.Marshal(tc.body)
				rec := httptest.NewRecorder()
				req := httptest.NewRequest(http.MethodPut, "/Users/"+userID.String(), strings.NewReader(string(rawBody)))
				if asyncMode {
					req.Header.Set("Prefer", "respond-async")
				}
				ctx := context.WithValue(req.Context(), middleware.WorkspaceIDKey, wsID)
				rctx := chi.NewRouteContext()
				rctx.URLParams.Add("workspaceId", wsID.String())
				rctx.URLParams.Add("id", userID.String())
				req = req.WithContext(context.WithValue(ctx, chi.RouteCtxKey, rctx))

				uh.ReplaceUser(rec, req)

				if rec.Code != http.StatusBadRequest {
					t.Fatalf("status = %d, want 400 (not 202 Accepted); body=%s", rec.Code, rec.Body.String())
				}
				var resp map[string]any
				if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
					t.Fatalf("invalid JSON: %v", err)
				}
				if resp["status"] != "400" || resp["scimType"] != "invalidValue" {
					t.Fatalf("got status=%v scimType=%v, want 400 invalidValue", resp["status"], resp["scimType"])
				}
				asyncRepo.mu.Lock()
				eventCount := len(asyncRepo.events)
				asyncRepo.mu.Unlock()
				if eventCount != 0 {
					t.Fatalf("expected 0 async events queued for invalid password, got %d", eventCount)
				}
			})
		}
	}
}

func TestUserHandler_OversizedAndDeepFilter_Returns400InvalidFilter(t *testing.T) {
	t.Parallel()

	uh := &UserHandler{}
	wsID := uuid.New()

	deepFilter := strings.Repeat("(", scim.MaxFilterDepth+3) + `userName eq "alice"` + strings.Repeat(")", scim.MaxFilterDepth+3)
	searchBody, _ := json.Marshal(map[string]any{
		"schemas": []string{"urn:ietf:params:scim:api:messages:2.0:SearchRequest"},
		"filter":  deepFilter,
	})
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/Users/.search", strings.NewReader(string(searchBody)))
	req = req.WithContext(context.WithValue(req.Context(), middleware.WorkspaceIDKey, wsID))

	uh.SearchUsers(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", rec.Code, rec.Body.String())
	}
	var resp map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	if resp["status"] != "400" || resp["scimType"] != "invalidFilter" {
		t.Fatalf("got status=%v scimType=%v, want 400 invalidFilter", resp["status"], resp["scimType"])
	}

	// Also verify nil body and malformed JSON (<1 MiB) return 400 invalidSyntax via readJSON/writeReadJSONError.
	nilBodyRec := httptest.NewRecorder()
	nilBodyReq, _ := http.NewRequest(http.MethodPost, "/Users", nil)
	nilBodyReq = nilBodyReq.WithContext(context.WithValue(nilBodyReq.Context(), middleware.WorkspaceIDKey, wsID))
	uh.CreateUser(nilBodyRec, nilBodyReq)
	if nilBodyRec.Code != http.StatusBadRequest {
		t.Fatalf("nil body status = %d, want 400", nilBodyRec.Code)
	}

	badJSONRec := httptest.NewRecorder()
	badJSONReq := httptest.NewRequest(http.MethodPost, "/Users", strings.NewReader("{bad-json"))
	badJSONReq = badJSONReq.WithContext(context.WithValue(badJSONReq.Context(), middleware.WorkspaceIDKey, wsID))
	uh.CreateUser(badJSONRec, badJSONReq)
	if badJSONRec.Code != http.StatusBadRequest || !strings.Contains(badJSONRec.Body.String(), "invalidSyntax") {
		t.Fatalf("malformed JSON got status=%d body=%s, want 400 invalidSyntax", badJSONRec.Code, badJSONRec.Body.String())
	}
}

func TestUserHandler_SearchUsers_EmptyBodyAllowed(t *testing.T) {
	t.Parallel()

	uh := &UserHandler{}
	wsID := uuid.New()

	for _, tc := range []struct {
		name string
		body io.Reader
	}{
		{"nil body", nil},
		{"empty reader", strings.NewReader("")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// Without workspace in context, an empty POST /Users/.search body must NOT fail
			// with 400 invalidSyntax; it must delegate cleanly to ListUsers (returning 404 Workspace not found).
			rec := httptest.NewRecorder()
			req, _ := http.NewRequest(http.MethodPost, "/Users/.search", tc.body)
			uh.SearchUsers(rec, req)
			if rec.Code != http.StatusNotFound {
				t.Fatalf("%s (no workspace): status = %d, want 404 (not 400 invalidSyntax); body=%s", tc.name, rec.Code, rec.Body.String())
			}

			// With workspace in context and a query filter error, empty body proceeds into ListUsers filter parsing.
			recFilter := httptest.NewRecorder()
			var bodyReader io.Reader
			if tc.body != nil {
				bodyReader = strings.NewReader("")
			}
			reqFilter, _ := http.NewRequest(http.MethodPost, "/Users/.search?filter=userName+unknownOp+%22x%22", bodyReader)
			reqFilter = reqFilter.WithContext(context.WithValue(reqFilter.Context(), middleware.WorkspaceIDKey, wsID))
			uh.SearchUsers(recFilter, reqFilter)
			if recFilter.Code != http.StatusBadRequest || !strings.Contains(recFilter.Body.String(), "invalidFilter") {
				t.Fatalf("%s (with filter): status = %d, body = %s, want 400 invalidFilter from ListUsers", tc.name, recFilter.Code, recFilter.Body.String())
			}
		})
	}
}
