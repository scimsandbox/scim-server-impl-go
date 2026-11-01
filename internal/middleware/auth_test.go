package middleware

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/scimsandbox/scim-server-impl-go/internal/model"
)

type stubTokenFinder struct {
	findByTokenHashNotRevoked func(ctx context.Context, tokenHash string) (*model.WorkspaceToken, error)
}

type stubWorkspaceFinder struct {
	findByID func(ctx context.Context, id uuid.UUID) (*model.Workspace, error)
}

func (s stubTokenFinder) FindByTokenHashNotRevoked(ctx context.Context, tokenHash string) (*model.WorkspaceToken, error) {
	return s.findByTokenHashNotRevoked(ctx, tokenHash)
}

func (s stubWorkspaceFinder) FindByID(ctx context.Context, id uuid.UUID) (*model.Workspace, error) {
	if s.findByID == nil {
		return nil, nil
	}

	return s.findByID(ctx, id)
}

func TestHashToken(t *testing.T) {
	token := "testToken123"
	hash := HashToken(token)

	if hash == "" {
		t.Fatalf("HashToken returned empty string")
	}
	if len(hash) != 64 {
		t.Fatalf("HashToken length = %d, want 64 (SHA-256 hex)", len(hash))
	}

	// Same input produces same hash
	hash2 := HashToken(token)
	if hash != hash2 {
		t.Fatalf("HashToken not deterministic: %q != %q", hash, hash2)
	}

	// Different input produces different hash
	hash3 := HashToken("differentToken")
	if hash == hash3 {
		t.Fatalf("HashToken collision: same hash for different inputs")
	}
}

func TestGenerateSecureToken(t *testing.T) {
	token, err := GenerateSecureToken()
	if err != nil {
		t.Fatalf("GenerateSecureToken() error = %v", err)
	}
	if token == "" {
		t.Fatalf("GenerateSecureToken() returned empty string")
	}

	// Should be URL-safe base64 encoded (86 chars for 64 bytes)
	decoded, err := base64.URLEncoding.DecodeString(token)
	if err != nil {
		// Try no-padding variant
		decoded, err = base64.RawURLEncoding.DecodeString(token)
		if err != nil {
			t.Fatalf("GenerateSecureToken() not valid base64: %v", err)
		}
	}
	if len(decoded) < 32 {
		t.Fatalf("GenerateSecureToken() decoded length = %d, want >= 32 bytes", len(decoded))
	}

	// Two tokens should be different
	token2, _ := GenerateSecureToken()
	if token == token2 {
		t.Fatalf("GenerateSecureToken() produced duplicate tokens")
	}
}

func TestBearerTokenAuth_MarksAuthenticationFailedWhenAuthorizationIsMissing(t *testing.T) {
	workspaceID := uuid.New()
	req := httptest.NewRequest(http.MethodGet, "/ws/"+workspaceID.String()+"/scim/v2/Users", nil)
	req = req.WithContext(context.WithValue(req.Context(), WorkspaceIDKey, workspaceID))
	req, state := withRequestMetricsState(req)
	rw := httptest.NewRecorder()

	handler := BearerTokenAuth(stubTokenFinder{}, nil)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	handler.ServeHTTP(rw, req)

	if rw.Code != http.StatusUnauthorized {
		t.Fatalf("response status = %d, want %d", rw.Code, http.StatusUnauthorized)
	}
	if state.Authentication != AuthenticationFailed {
		t.Fatalf("authentication state = %q, want %q", state.Authentication, AuthenticationFailed)
	}
	ct := rw.Header().Get("Content-Type")
	if !strings.HasPrefix(ct, "application/scim+json") {
		t.Fatalf("Content-Type = %q, want application/scim+json (RFC 7644 §3.12 / SEC_27)", ct)
	}
	var errBody map[string]any
	if err := json.Unmarshal(rw.Body.Bytes(), &errBody); err != nil {
		t.Fatalf("failed to parse SCIM error JSON: %v", err)
	}
	schemas, ok := errBody["schemas"].([]any)
	if !ok || len(schemas) == 0 || schemas[0] != "urn:ietf:params:scim:api:messages:2.0:Error" {
		t.Fatalf("schemas = %v, want [urn:ietf:params:scim:api:messages:2.0:Error]", errBody["schemas"])
	}
	if errBody["status"] != "401" {
		t.Fatalf("status = %v, want \"401\"", errBody["status"])
	}
}

func TestBearerTokenAuth_MarksAuthenticationOKForValidToken(t *testing.T) {
	workspaceID := uuid.New()
	req := httptest.NewRequest(http.MethodGet, "/ws/"+workspaceID.String()+"/scim/v2/Users", nil)
	req.Header.Set("Authorization", "Bearer valid-token")
	req = req.WithContext(context.WithValue(req.Context(), WorkspaceIDKey, workspaceID))
	req, state := withRequestMetricsState(req)
	rw := httptest.NewRecorder()

	handler := BearerTokenAuth(stubTokenFinder{
		findByTokenHashNotRevoked: func(ctx context.Context, tokenHash string) (*model.WorkspaceToken, error) {
			return &model.WorkspaceToken{
				WorkspaceID: workspaceID,
				ExpiresAt:   ptrTime(time.Now().Add(time.Hour)),
			}, nil
		},
	}, stubWorkspaceFinder{
		findByID: func(ctx context.Context, id uuid.UUID) (*model.Workspace, error) {
			userEmail := "alice@example.com"
			return &model.Workspace{ID: id, CreatedByUsername: &userEmail}, nil
		},
	})(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	handler.ServeHTTP(rw, req)

	if rw.Code != http.StatusNoContent {
		t.Fatalf("response status = %d, want %d", rw.Code, http.StatusNoContent)
	}
	if state.Authentication != AuthenticationOK {
		t.Fatalf("authentication state = %q, want %q", state.Authentication, AuthenticationOK)
	}
	if state.UserEmail != "alice@example.com" {
		t.Fatalf("user email = %q, want %q", state.UserEmail, "alice@example.com")
	}
}

func TestExtractWorkspaceID_MarksAuthenticationFailedForInvalidWorkspaceID(t *testing.T) {
	cases := []struct {
		name  string
		wsParam string
	}{
		{"invalid_uuid", "not-a-uuid"},
		{"empty_workspace_id", ""},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/ws/"+tc.wsParam+"/scim/v2/Users", nil)
			routeCtx := chi.NewRouteContext()
			if tc.wsParam != "" {
				routeCtx.URLParams.Add("workspaceId", tc.wsParam)
			}
			req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, routeCtx))
			req, state := withRequestMetricsState(req)
			rw := httptest.NewRecorder()

			handler := ExtractWorkspaceID(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusNoContent)
			}))
			handler.ServeHTTP(rw, req)

			if rw.Code != http.StatusNotFound {
				t.Fatalf("response status = %d, want %d", rw.Code, http.StatusNotFound)
			}
			if state.Authentication != AuthenticationFailed {
				t.Fatalf("authentication state = %q, want %q", state.Authentication, AuthenticationFailed)
			}
			ct := rw.Header().Get("Content-Type")
			if !strings.HasPrefix(ct, "application/scim+json") {
				t.Fatalf("Content-Type = %q, want application/scim+json (RFC 7644 §3.12)", ct)
			}
			var errBody map[string]any
			if err := json.Unmarshal(rw.Body.Bytes(), &errBody); err != nil {
				t.Fatalf("failed to parse SCIM error JSON: %v", err)
			}
			schemas, ok := errBody["schemas"].([]any)
			if !ok || len(schemas) == 0 || schemas[0] != "urn:ietf:params:scim:api:messages:2.0:Error" {
				t.Fatalf("schemas = %v, want [urn:ietf:params:scim:api:messages:2.0:Error]", errBody["schemas"])
			}
			if errBody["status"] != "404" {
				t.Fatalf("status = %v, want \"404\"", errBody["status"])
			}
		})
	}
}

// GenerateSecureToken generates a cryptographically secure URL-safe
// base64-encoded token (64 random bytes).
func GenerateSecureToken() (string, error) {
	b := make([]byte, 64)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func ptrTime(value time.Time) *time.Time {
	return &value
}
