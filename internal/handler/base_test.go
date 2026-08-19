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
