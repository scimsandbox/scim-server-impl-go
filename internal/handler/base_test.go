package handler

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-chi/chi/v5"
)

// The base URL built here becomes the authority of every meta.location and $ref in a SCIM response,
// so it must not be steerable by the caller. The edge in front of this service strips
// X-Forwarded-Host and X-Forwarded-Port, but that is dashboard configuration which any infrastructure
// rebuild can lose - these tests are the copy that cannot be lost.
func requestWithRoute(host string, headers map[string]string, workspaceID, compat string) *http.Request {
	r := httptest.NewRequest(http.MethodGet, "/ws/"+workspaceID+"/scim/v2/Users", nil)
	r.Host = host
	for k, v := range headers {
		r.Header.Set(k, v)
	}

	routeCtx := chi.NewRouteContext()
	routeCtx.URLParams.Add("workspaceId", workspaceID)
	if compat != "" {
		routeCtx.URLParams.Add("compat", compat)
	}
	return r.WithContext(context.WithValue(r.Context(), chi.RouteCtxKey, routeCtx))
}

func TestBuildBaseURLIgnoresSpoofedForwardedHostAndPort(t *testing.T) {
	const wsID = "24fb7ccb-3458-44da-b5c8-92b97e2ad702"
	r := requestWithRoute("api2.scimsandbox.net", map[string]string{
		"X-Forwarded-Proto": "https",
		"X-Forwarded-Host":  "evil.example",
		"X-Forwarded-Port":  "1337",
	}, wsID, "")

	want := "https://api2.scimsandbox.net/ws/" + wsID + "/scim/v2"
	if got := buildBaseURL(r); got != want {
		t.Fatalf("buildBaseURL() = %q, want %q", got, want)
	}
}

func TestBuildBaseURLUsesForwardedProtoForScheme(t *testing.T) {
	const wsID = "24fb7ccb-3458-44da-b5c8-92b97e2ad702"
	r := requestWithRoute("api2.scimsandbox.net", map[string]string{
		"X-Forwarded-Proto": "https",
	}, wsID, "")

	want := "https://api2.scimsandbox.net/ws/" + wsID + "/scim/v2"
	if got := buildBaseURL(r); got != want {
		t.Fatalf("buildBaseURL() = %q, want %q", got, want)
	}
}

func TestBuildBaseURLKeepsNonDefaultPortFromHost(t *testing.T) {
	const wsID = "24fb7ccb-3458-44da-b5c8-92b97e2ad702"
	r := requestWithRoute("localhost:18080", nil, wsID, "")

	want := "http://localhost:18080/ws/" + wsID + "/scim/v2"
	if got := buildBaseURL(r); got != want {
		t.Fatalf("buildBaseURL() = %q, want %q", got, want)
	}
}

func TestBuildBaseURLStripsDefaultPort(t *testing.T) {
	const wsID = "24fb7ccb-3458-44da-b5c8-92b97e2ad702"
	r := requestWithRoute("api2.scimsandbox.net:443", map[string]string{
		"X-Forwarded-Proto": "https",
	}, wsID, "")

	want := "https://api2.scimsandbox.net/ws/" + wsID + "/scim/v2"
	if got := buildBaseURL(r); got != want {
		t.Fatalf("buildBaseURL() = %q, want %q", got, want)
	}
}

func TestBuildBaseURLAppendsCompatSegment(t *testing.T) {
	const wsID = "24fb7ccb-3458-44da-b5c8-92b97e2ad702"
	r := requestWithRoute("api2.scimsandbox.net", map[string]string{
		"X-Forwarded-Proto": "https",
	}, wsID, "v2")

	want := "https://api2.scimsandbox.net/ws/" + wsID + "/scim/v2/v2"
	if got := buildBaseURL(r); got != want {
		t.Fatalf("buildBaseURL() = %q, want %q", got, want)
	}
}

func TestApplyAttributeProjection_SubAttributesAndURNPrefixes(t *testing.T) {
	sample := func() map[string]any {
		return map[string]any{
			"schemas":  []string{"urn:ietf:params:scim:schemas:core:2.0:User", "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User"},
			"id":       "11111111-1111-1111-1111-111111111111",
			"userName": "alice@example.com",
			"password": "secret",
			"name": map[string]any{
				"givenName":  "Alice",
				"familyName": "Smith",
			},
			"emails": []map[string]any{
				{"value": "alice@example.com", "type": "work", "primary": true},
			},
			"meta": map[string]any{"resourceType": "User"},
			"urn:ietf:params:scim:schemas:extension:enterprise:2.0:User": map[string]any{
				"department": "Engineering",
				"division":   "Platform",
			},
		}
	}

	t.Run("whitelist complex sub-attributes and multi-valued sub-attributes", func(t *testing.T) {
		res := applyAttributeProjection(sample(), "name.givenName,emails.value", "")
		if _, hasPW := res["password"]; hasPW {
			t.Fatal("password must never be returned")
		}
		if res["id"] == nil || res["schemas"] == nil || res["meta"] == nil {
			t.Fatal("schemas, id, and meta must remain present")
		}
		nameMap, ok := res["name"].(map[string]any)
		if !ok || nameMap["givenName"] != "Alice" || nameMap["familyName"] != nil {
			t.Fatalf("unexpected projected name map: %v", res["name"])
		}
		emails, ok := res["emails"].([]map[string]any)
		if !ok || len(emails) != 1 || emails[0]["value"] != "alice@example.com" || emails[0]["type"] != nil {
			t.Fatalf("unexpected projected emails: %v", res["emails"])
		}
		if _, hasUN := res["userName"]; hasUN {
			t.Fatal("userName was not requested and has returned:default, so it must be omitted")
		}
	})

	t.Run("blacklist excludedAttributes on sub-attributes and URN-prefixed enterprise attributes", func(t *testing.T) {
		res := applyAttributeProjection(sample(), "", "name.familyName,emails.type,urn:ietf:params:scim:schemas:extension:enterprise:2.0:User:division,id,schemas")
		if res["id"] == nil || res["schemas"] == nil {
			t.Fatal("returned:always attributes id and schemas must never be excluded")
		}
		nameMap := res["name"].(map[string]any)
		if nameMap["givenName"] != "Alice" || nameMap["familyName"] != nil {
			t.Fatalf("unexpected excluded name map: %v", nameMap)
		}
		entMap := res["urn:ietf:params:scim:schemas:extension:enterprise:2.0:User"].(map[string]any)
		if entMap["department"] != "Engineering" || entMap["division"] != nil {
			t.Fatalf("unexpected excluded enterprise map: %v", entMap)
		}
	})
}

