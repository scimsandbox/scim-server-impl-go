package handler

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/scimsandbox/scim-server-impl-go/internal/middleware"
)

// RFC 7644 §3.4.3 requires 501 from the root .search endpoint when cross-resource search is not
// supported, so the status is part of the contract rather than an implementation detail.
func TestGlobalSearchNotImplemented(t *testing.T) {
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/ws/24fb7ccb-3458-44da-b5c8-92b97e2ad702/scim/v2/.search", nil)

	NewDiscoveryHandler().GlobalSearchNotImplemented(rec, req)

	if rec.Code != http.StatusNotImplemented {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusNotImplemented)
	}
	if ct := rec.Header().Get("Content-Type"); ct != ScimContentType {
		t.Fatalf("Content-Type = %q, want %q", ct, ScimContentType)
	}

	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("response body is not JSON: %v", err)
	}
	if got := body["status"]; got != "501" {
		t.Errorf("body status = %v, want \"501\"", got)
	}
	schemas, ok := body["schemas"].([]any)
	if !ok || len(schemas) != 1 || schemas[0] != "urn:ietf:params:scim:api:messages:2.0:Error" {
		t.Errorf("schemas = %v, want the SCIM Error schema URN", body["schemas"])
	}
	if detail, _ := body["detail"].(string); detail == "" {
		t.Error("detail is empty, want an explanation of the unsupported operation")
	}
}

func TestRootSearch_MissingWorkspace(t *testing.T) {
	dh := NewDiscoveryHandler()
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)

	dh.RootSearch(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("expected 404 for missing workspace, got %d", rec.Code)
	}
}

func TestRootSearch_EmptyHandlersReturnsEmptyList(t *testing.T) {
	dh := NewDiscoveryHandler()
	rec := httptest.NewRecorder()
	wsID := uuid.New()
	req := httptest.NewRequest(http.MethodGet, "/?startIndex=1&count=10", nil)
	req = req.WithContext(context.WithValue(req.Context(), middleware.WorkspaceIDKey, wsID))

	dh.RootSearch(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}

	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("failed to unmarshal JSON: %v", err)
	}
	if body["totalResults"] != float64(0) {
		t.Fatalf("expected totalResults 0, got %v", body["totalResults"])
	}
	resources, ok := body["Resources"].([]any)
	if !ok || len(resources) != 0 {
		t.Fatalf("expected empty Resources array, got %v", body["Resources"])
	}
}

func TestRootSearch_PostInvalidJSON(t *testing.T) {
	dh := NewDiscoveryHandler()
	rec := httptest.NewRecorder()
	wsID := uuid.New()
	req := httptest.NewRequest(http.MethodPost, "/.search", strings.NewReader("{invalid-json"))
	req = req.WithContext(context.WithValue(req.Context(), middleware.WorkspaceIDKey, wsID))

	dh.RootSearch(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for invalid JSON, got %d", rec.Code)
	}
}

func TestRootSearch_InvalidFilterSyntax(t *testing.T) {
	// Initialize with handlers so filter parsing is actually invoked
	dh := NewDiscoveryHandler(&UserHandler{}, &GroupHandler{})
	wsID := uuid.New()

	testCases := []struct {
		name   string
		filter string
	}{
		{"missing value on user attribute", "userName eq"},
		{"missing value on common attribute", "displayName eq"},
		{"trailing operator", "userName eq \"alice\" and"},
		{"unclosed parenthesis", "(userName eq \"alice\""},
		{"invalid operator", "userName xx \"alice\""},
		{"trailing closing parenthesis", `userName eq "alice")`},
		{"nested trailing closing parenthesis", `(userName eq "alice"))`},
		{"trailing token", `userName eq "alice" extra`},
		{"trailing closing parenthesis on common attribute", `displayName eq "Engineering")`},
		{"trailing token on common attribute", `displayName eq "Engineering" extra`},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodGet, "/?filter="+url.QueryEscape(tc.filter), nil)
			req = req.WithContext(context.WithValue(req.Context(), middleware.WorkspaceIDKey, wsID))

			dh.RootSearch(rec, req)
			if rec.Code != http.StatusBadRequest {
				t.Fatalf("expected 400 for invalid filter syntax (%s), got %d: %s", tc.filter, rec.Code, rec.Body.String())
			}

			var body map[string]any
			if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
				t.Fatalf("failed to parse JSON error: %v", err)
			}
			if body["scimType"] != "invalidFilter" {
				t.Fatalf("expected scimType 'invalidFilter', got %v", body["scimType"])
			}
			if detail, _ := body["detail"].(string); detail == "" {
				t.Errorf("expected non-empty detail explaining invalid filter")
			} else if strings.Contains(detail, "SCIM error") {
				t.Errorf("expected clean detail without SCIM error prefix, got %q", detail)
			}
		})
	}
}

func TestRootSearch_PostInvalidFilterSyntax(t *testing.T) {
	dh := NewDiscoveryHandler(&UserHandler{}, &GroupHandler{})
	wsID := uuid.New()

	testCases := []struct {
		name   string
		filter string
	}{
		{"trailing closing parenthesis", `userName eq "alice")`},
		{"nested trailing closing parenthesis", `(userName eq "alice"))`},
		{"trailing extra token", `userName eq "alice" extra`},
		{"consecutive filters without op", `userName eq "alice" userName eq "bob"`},
		{"trailing operator", `userName eq "alice" and`},
		{"unclosed parenthesis", `(userName eq "alice"`},
		{"missing value", `userName eq`},
		{"invalid operator", `userName xx "alice"`},
		{"trailing closing parenthesis on common attribute", `displayName eq "Engineering")`},
		{"trailing extra token on common attribute", `displayName eq "Engineering" extra`},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			payload, _ := json.Marshal(map[string]any{"filter": tc.filter})
			req := httptest.NewRequest(http.MethodPost, "/.search", bytes.NewReader(payload))
			req.Header.Set("Content-Type", "application/scim+json")
			req = req.WithContext(context.WithValue(req.Context(), middleware.WorkspaceIDKey, wsID))

			dh.RootSearch(rec, req)
			if rec.Code != http.StatusBadRequest {
				t.Fatalf("expected 400 for POST invalid filter (%s), got %d: %s", tc.filter, rec.Code, rec.Body.String())
			}

			if ct := rec.Header().Get("Content-Type"); ct != ScimContentType {
				t.Fatalf("expected Content-Type %s, got %s", ScimContentType, ct)
			}

			var body map[string]any
			if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
				t.Fatalf("failed to parse JSON error: %v", err)
			}
			if body["scimType"] != "invalidFilter" {
				t.Fatalf("expected scimType 'invalidFilter', got %v", body["scimType"])
			}
			if detail, _ := body["detail"].(string); detail == "" {
				t.Errorf("expected non-empty detail explaining invalid filter")
			} else if strings.Contains(detail, "SCIM error") {
				t.Errorf("expected clean detail without SCIM error prefix, got %q", detail)
			}
		})
	}
}

func TestRootSearch_InvalidCompatMode(t *testing.T) {
	dh := NewDiscoveryHandler(&UserHandler{}, &GroupHandler{})
	wsID := uuid.New().String()

	// Invalid compat mode returns 404
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/ws/"+wsID+"/scim/v2/invalid", nil)
	routeCtx := chi.NewRouteContext()
	routeCtx.URLParams.Add("workspaceId", wsID)
	routeCtx.URLParams.Add("compat", "invalid")
	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, routeCtx))
	req = req.WithContext(context.WithValue(req.Context(), middleware.WorkspaceIDKey, uuid.MustParse(wsID)))

	dh.RootSearch(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("expected 404 for invalid compat mode, got %d: %s", rec.Code, rec.Body.String())
	}

	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("failed to parse JSON: %v", err)
	}
	if body["status"] != "404" {
		t.Fatalf("expected status '404', got %v", body["status"])
	}
}

func TestRootSearch_MethodNotAllowed(t *testing.T) {
	dh := NewDiscoveryHandler()
	r := chi.NewRouter()
	r.MethodNotAllowed(MethodNotAllowed)
	r.Get("/", dh.RootSearch)
	r.Post("/", MethodNotAllowed)
	r.Put("/", MethodNotAllowed)
	r.Patch("/", MethodNotAllowed)
	r.Delete("/", MethodNotAllowed)

	const searchPath = "/.search"
	r.Post(searchPath, dh.RootSearch)
	r.Get(searchPath, MethodNotAllowed)
	r.Put(searchPath, MethodNotAllowed)
	r.Patch(searchPath, MethodNotAllowed)
	r.Delete(searchPath, MethodNotAllowed)

	disallowedRequests := []struct {
		method string
		path   string
	}{
		{http.MethodGet, "/.search"},
		{http.MethodPut, "/.search"},
		{http.MethodPatch, "/.search"},
		{http.MethodDelete, "/.search"},
		{http.MethodPost, "/"},
		{http.MethodPut, "/"},
		{http.MethodPatch, "/"},
		{http.MethodDelete, "/"},
	}

	for _, tc := range disallowedRequests {
		t.Run(tc.method+" "+tc.path, func(t *testing.T) {
			rec := httptest.NewRecorder()
			req := httptest.NewRequest(tc.method, tc.path, nil)
			r.ServeHTTP(rec, req)

			if rec.Code != http.StatusMethodNotAllowed {
				t.Fatalf("expected 405 Method Not Allowed for %s %s, got %d", tc.method, tc.path, rec.Code)
			}
			if ct := rec.Header().Get("Content-Type"); ct != ScimContentType {
				t.Fatalf("expected Content-Type %s, got %s", ScimContentType, ct)
			}

			var body map[string]any
			if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
				t.Fatalf("failed to parse JSON: %v", err)
			}
			if body["status"] != "405" {
				t.Fatalf("expected body status '405', got %v", body["status"])
			}
		})
	}
}

func TestDiscovery_MethodNotAllowed_AllowHeader_DSC11_DSC12(t *testing.T) {
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/Schemas", nil)
	MethodNotAllowed(rec, req)

	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("expected 405 Method Not Allowed, got %d", rec.Code)
	}
	allow := rec.Header().Get("Allow")
	if allow != "GET" {
		t.Fatalf("expected Allow: GET, got %q", allow)
	}

	recPost := httptest.NewRecorder()
	reqPost := httptest.NewRequest(http.MethodGet, "/.search", nil)
	MethodNotAllowedWithAllow("POST")(recPost, reqPost)
	if recPost.Code != http.StatusMethodNotAllowed {
		t.Fatalf("expected 405 Method Not Allowed, got %d", recPost.Code)
	}
	allowPost := recPost.Header().Get("Allow")
	if allowPost != "POST" {
		t.Fatalf("expected Allow: POST, got %q", allowPost)
	}
}

func TestRouter_MethodNotAllowed_DynamicAndScopedAllowHeader(t *testing.T) {
	noop := func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}

	// 1. Verify standalone router using r.MethodNotAllowed(MethodNotAllowed) dynamically computes Allow header
	standalone := chi.NewRouter()
	standalone.MethodNotAllowed(MethodNotAllowed)
	standalone.Get("/Users", noop)
	standalone.Post("/Users", noop)
	standalone.Get("/Users/{id}", noop)
	standalone.Put("/Users/{id}", noop)
	standalone.Patch("/Users/{id}", noop)
	standalone.Delete("/Users/{id}", noop)
	standalone.Post("/Bulk", noop)
	standalone.Get("/Schemas", noop)
	standalone.Get("/ServiceProviderConfig", noop)

	standaloneCases := []struct {
		method    string
		path      string
		wantAllow string
	}{
		{http.MethodDelete, "/Users", "GET, POST"},
		{http.MethodPut, "/Users", "GET, POST"},
		{http.MethodPatch, "/Users", "GET, POST"},
		{http.MethodPost, "/Users/123", "GET, PUT, PATCH, DELETE"},
		{http.MethodGet, "/Bulk", "POST"},
		{http.MethodDelete, "/Bulk", "POST"},
		{http.MethodDelete, "/Schemas", "GET"},
		{http.MethodPost, "/ServiceProviderConfig", "GET"},
	}

	for _, tc := range standaloneCases {
		t.Run("standalone_"+tc.method+"_"+tc.path, func(t *testing.T) {
			rec := httptest.NewRecorder()
			req := httptest.NewRequest(tc.method, tc.path, nil)
			standalone.ServeHTTP(rec, req)
			if rec.Code != http.StatusMethodNotAllowed {
				t.Fatalf("expected 405 for %s %s, got %d", tc.method, tc.path, rec.Code)
			}
			if got := rec.Header().Get("Allow"); got != tc.wantAllow {
				t.Fatalf("Allow header for %s %s = %q, want %q", tc.method, tc.path, got, tc.wantAllow)
			}
		})
	}

	// 2. Verify full SCIM router layout (with /{compat} subrouter) returns accurate Allow headers without falling through
	scimRouter := chi.NewRouter()
	registerEndpoints := func(r chi.Router) {
		r.Post("/Users", noop)
		r.Get("/Users", noop)
		r.Put("/Users", MethodNotAllowedWithAllow("GET, POST"))
		r.Patch("/Users", MethodNotAllowedWithAllow("GET, POST"))
		r.Delete("/Users", MethodNotAllowedWithAllow("GET, POST"))

		r.Get("/Users/{id}", noop)
		r.Put("/Users/{id}", noop)
		r.Patch("/Users/{id}", noop)
		r.Delete("/Users/{id}", noop)
		r.Post("/Users/{id}", MethodNotAllowedWithAllow("GET, PUT, PATCH, DELETE"))

		r.Post("/Users/.search", noop)
		r.Get("/Users/.search", MethodNotAllowedWithAllow("POST"))
		r.Put("/Users/.search", MethodNotAllowedWithAllow("POST"))
		r.Patch("/Users/.search", MethodNotAllowedWithAllow("POST"))
		r.Delete("/Users/.search", MethodNotAllowedWithAllow("POST"))

		r.Post("/Groups", noop)
		r.Get("/Groups", noop)
		r.Put("/Groups", MethodNotAllowedWithAllow("GET, POST"))
		r.Patch("/Groups", MethodNotAllowedWithAllow("GET, POST"))
		r.Delete("/Groups", MethodNotAllowedWithAllow("GET, POST"))

		r.Get("/Groups/{id}", noop)
		r.Put("/Groups/{id}", noop)
		r.Patch("/Groups/{id}", noop)
		r.Delete("/Groups/{id}", noop)
		r.Post("/Groups/{id}", MethodNotAllowedWithAllow("GET, PUT, PATCH, DELETE"))

		r.Post("/Groups/.search", noop)
		r.Get("/Groups/.search", MethodNotAllowedWithAllow("POST"))
		r.Put("/Groups/.search", MethodNotAllowedWithAllow("POST"))
		r.Patch("/Groups/.search", MethodNotAllowedWithAllow("POST"))
		r.Delete("/Groups/.search", MethodNotAllowedWithAllow("POST"))

		r.Get("/", noop)
		r.Post("/", MethodNotAllowedWithAllow("GET"))
		r.Put("/", MethodNotAllowedWithAllow("GET"))
		r.Patch("/", MethodNotAllowedWithAllow("GET"))
		r.Delete("/", MethodNotAllowedWithAllow("GET"))

		r.Post("/Bulk", noop)
		r.Get("/Bulk", MethodNotAllowedWithAllow("POST"))
		r.Put("/Bulk", MethodNotAllowedWithAllow("POST"))
		r.Patch("/Bulk", MethodNotAllowedWithAllow("POST"))
		r.Delete("/Bulk", MethodNotAllowedWithAllow("POST"))

		r.Post("/.search", noop)
		r.Get("/.search", MethodNotAllowedWithAllow("POST"))
		r.Put("/.search", MethodNotAllowedWithAllow("POST"))
		r.Patch("/.search", MethodNotAllowedWithAllow("POST"))
		r.Delete("/.search", MethodNotAllowedWithAllow("POST"))

		r.Get("/ServiceProviderConfig", noop)
		r.Post("/ServiceProviderConfig", MethodNotAllowedWithAllow("GET"))
		r.Put("/ServiceProviderConfig", MethodNotAllowedWithAllow("GET"))
		r.Patch("/ServiceProviderConfig", MethodNotAllowedWithAllow("GET"))
		r.Delete("/ServiceProviderConfig", MethodNotAllowedWithAllow("GET"))

		r.Get("/Schemas", noop)
		r.Post("/Schemas", MethodNotAllowedWithAllow("GET"))
		r.Put("/Schemas", MethodNotAllowedWithAllow("GET"))
		r.Patch("/Schemas", MethodNotAllowedWithAllow("GET"))
		r.Delete("/Schemas", MethodNotAllowedWithAllow("GET"))

		r.Get("/ResourceTypes", noop)
		r.Post("/ResourceTypes", MethodNotAllowedWithAllow("GET"))
		r.Put("/ResourceTypes", MethodNotAllowedWithAllow("GET"))
		r.Patch("/ResourceTypes", MethodNotAllowedWithAllow("GET"))
		r.Delete("/ResourceTypes", MethodNotAllowedWithAllow("GET"))

		r.MethodNotAllowed(MethodNotAllowed)
	}
	scimRouter.Route("/ws/{workspaceId}/scim/v2", func(r chi.Router) {
		registerEndpoints(r)
		r.Route("/{compat}", func(r chi.Router) {
			registerEndpoints(r)
		})
	})

	wsPrefix := "/ws/24fb7ccb-3458-44da-b5c8-92b97e2ad702/scim/v2"
	fullRouterCases := []struct {
		method    string
		path      string
		wantAllow string
	}{
		{http.MethodDelete, wsPrefix + "/Users", "GET, POST"},
		{http.MethodPut, wsPrefix + "/Users", "GET, POST"},
		{http.MethodPost, wsPrefix + "/Users/123", "GET, PUT, PATCH, DELETE"},
		{http.MethodGet, wsPrefix + "/Users/.search", "POST"},
		{http.MethodDelete, wsPrefix + "/Groups", "GET, POST"},
		{http.MethodPost, wsPrefix + "/Groups/456", "GET, PUT, PATCH, DELETE"},
		{http.MethodGet, wsPrefix + "/Groups/.search", "POST"},
		{http.MethodGet, wsPrefix + "/Bulk", "POST"},
		{http.MethodDelete, wsPrefix + "/Bulk", "POST"},
		{http.MethodGet, wsPrefix + "/.search", "POST"},
		{http.MethodDelete, wsPrefix + "/Schemas", "GET"},
		{http.MethodPost, wsPrefix + "/ServiceProviderConfig", "GET"},
		{http.MethodDelete, wsPrefix + "/ResourceTypes", "GET"},
		{http.MethodDelete, wsPrefix + "/ms/Users", "GET, POST"},
		{http.MethodGet, wsPrefix + "/ms/Bulk", "POST"},
	}

	for _, tc := range fullRouterCases {
		t.Run("scim_"+tc.method+"_"+tc.path, func(t *testing.T) {
			rec := httptest.NewRecorder()
			req := httptest.NewRequest(tc.method, tc.path, nil)
			scimRouter.ServeHTTP(rec, req)
			if rec.Code != http.StatusMethodNotAllowed {
				t.Fatalf("expected 405 for %s %s, got %d", tc.method, tc.path, rec.Code)
			}
			if got := rec.Header().Get("Allow"); got != tc.wantAllow {
				t.Fatalf("Allow header for %s %s = %q, want %q", tc.method, tc.path, got, tc.wantAllow)
			}
		})
	}
}

func TestSortResources(t *testing.T) {
	items := []map[string]any{
		{"id": "3", "displayName": "Charlie"},
		{"id": "1", "displayName": "Alice"},
		{"id": "4", "displayName": nil},
		{"id": "2", "displayName": "Bob"},
	}

	// Ascending: nulls last
	sortResources(items, "displayName", "ascending")
	if items[0]["displayName"] != "Alice" || items[1]["displayName"] != "Bob" || items[2]["displayName"] != "Charlie" || items[3]["displayName"] != nil {
		t.Fatalf("unexpected asc sort order: %+v", items)
	}

	// Descending: nulls first
	sortResources(items, "displayName", "descending")
	if items[0]["displayName"] != nil || items[1]["displayName"] != "Charlie" || items[2]["displayName"] != "Bob" || items[3]["displayName"] != "Alice" {
		t.Fatalf("unexpected desc sort order: %+v", items)
	}

	// Mixed resource types sorted by meta.resourceType
	mixed := []map[string]any{
		{"id": "u1", "meta": map[string]any{"resourceType": "User"}},
		{"id": "g1", "meta": map[string]any{"resourceType": "Group"}},
	}
	sortResources(mixed, "meta.resourceType", "ascending")
	if mixed[0]["id"] != "g1" || mixed[1]["id"] != "u1" {
		t.Fatalf("expected Group before User on asc, got %+v", mixed)
	}
	sortResources(mixed, "meta.resourceType", "descending")
	if mixed[0]["id"] != "u1" || mixed[1]["id"] != "g1" {
		t.Fatalf("expected User before Group on desc, got %+v", mixed)
	}
}

func TestExtractSortAttr(t *testing.T) {
	res := map[string]any{
		"displayName": "Test",
		"meta": map[string]any{
			"resourceType": "User",
			"created":      "2026-01-01T00:00:00Z",
		},
	}

	val, ok := extractSortAttr(res, "displayName")
	if !ok || val != "Test" {
		t.Fatalf("expected Test, got %v (ok=%v)", val, ok)
	}

	// Case-insensitivity on key
	val, ok = extractSortAttr(res, "displayname")
	if !ok || val != "Test" {
		t.Fatalf("expected Test, got %v (ok=%v)", val, ok)
	}

	// Nested key
	val, ok = extractSortAttr(res, "meta.resourceType")
	if !ok || val != "User" {
		t.Fatalf("expected User, got %v (ok=%v)", val, ok)
	}

	// Missing key
	_, ok = extractSortAttr(res, "nonexistent")
	if ok {
		t.Fatalf("expected false for missing key")
	}

	// Nil map
	_, ok = extractSortAttr(nil, "displayName")
	if ok {
		t.Fatalf("expected false for nil map")
	}
}

func TestServiceProviderConfig_PaginationAdvertised_CUR06(t *testing.T) {
	dh := NewDiscoveryHandler()
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/ServiceProviderConfig", nil)

	dh.GetServiceProviderConfig(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}

	var spc map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &spc); err != nil {
		t.Fatalf("failed to unmarshal JSON: %v", err)
	}

	pag, ok := spc["pagination"].(map[string]any)
	if !ok {
		t.Fatalf("pagination attribute missing or not an object in ServiceProviderConfig")
	}

	if pag["cursor"] != true {
		t.Errorf("pagination.cursor = %v, want true", pag["cursor"])
	}
	if pag["index"] != true {
		t.Errorf("pagination.index = %v, want true", pag["index"])
	}
	if pag["defaultPaginationMode"] != "index" {
		t.Errorf("pagination.defaultPaginationMode = %v, want index", pag["defaultPaginationMode"])
	}
	if pag["cursorTimeout"] != float64(3600) {
		t.Errorf("pagination.cursorTimeout = %v, want 3600", pag["cursorTimeout"])
	}
}

func TestRootSearch_CursorPagination_CUR05(t *testing.T) {
	dh := NewDiscoveryHandler()
	rec := httptest.NewRecorder()
	wsID := uuid.New()
	body := `{"schemas":["urn:ietf:params:scim:api:messages:2.0:SearchRequest"],"cursor":"","count":1}`
	req := httptest.NewRequest(http.MethodPost, "/.search", strings.NewReader(body))
	req = req.WithContext(context.WithValue(req.Context(), middleware.WorkspaceIDKey, wsID))

	dh.RootSearch(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}

	var resp map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to unmarshal JSON: %v", err)
	}
	schemas, ok := resp["schemas"].([]any)
	if !ok || len(schemas) == 0 || schemas[0] != "urn:ietf:params:scim:api:messages:2.0:ListResponse" {
		t.Errorf("schemas = %v, want ListResponse", resp["schemas"])
	}
	if _, exists := resp["startIndex"]; exists {
		t.Errorf("startIndex should be omitted in cursor mode")
	}
}

func TestRootSearch_MutualExclusion(t *testing.T) {
	dh := NewDiscoveryHandler()
	rec := httptest.NewRecorder()
	wsID := uuid.New()
	req := httptest.NewRequest(http.MethodGet, "/?cursor=&startIndex=1", nil)
	req = req.WithContext(context.WithValue(req.Context(), middleware.WorkspaceIDKey, wsID))

	dh.RootSearch(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for mutual exclusivity violation, got %d", rec.Code)
	}

	var resp map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to unmarshal JSON: %v", err)
	}
	if resp["scimType"] != "invalidValue" && resp["scimType"] != "invalidCursor" {
		t.Errorf("scimType = %v, want invalidValue or invalidCursor", resp["scimType"])
	}
}

func TestRootSearch_InvalidCursor_CUR04(t *testing.T) {
	dh := NewDiscoveryHandler()
	rec := httptest.NewRecorder()
	wsID := uuid.New()
	req := httptest.NewRequest(http.MethodGet, "/?cursor=invalid-opaque-cursor-999", nil)
	req = req.WithContext(context.WithValue(req.Context(), middleware.WorkspaceIDKey, wsID))

	dh.RootSearch(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for invalid cursor, got %d", rec.Code)
	}

	var resp map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to unmarshal JSON: %v", err)
	}
	if resp["scimType"] != "invalidCursor" {
		t.Errorf("scimType = %v, want invalidCursor", resp["scimType"])
	}
}

