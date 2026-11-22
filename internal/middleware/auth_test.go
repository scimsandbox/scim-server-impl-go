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
		gotWS, ok := AuthenticatedWorkspaceID(r.Context())
		if !ok || gotWS != workspaceID {
			t.Errorf("AuthenticatedWorkspaceID = (%v, %v), want (%v, true)", gotWS, ok, workspaceID)
		}
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

func TestBearerTokenAuth_AnonymousServiceProviderConfig(t *testing.T) {
	existingWS := uuid.New()
	missingWS := uuid.New()

	wsRepo := stubWorkspaceFinder{
		findByID: func(ctx context.Context, id uuid.UUID) (*model.Workspace, error) {
			if id == existingWS {
				return &model.Workspace{ID: id}, nil
			}
			return nil, nil
		},
	}
	tokenRepo := stubTokenFinder{
		findByTokenHashNotRevoked: func(ctx context.Context, tokenHash string) (*model.WorkspaceToken, error) {
			return nil, nil
		},
	}

	mw := BearerTokenAuth(tokenRepo, wsRepo)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	// 1. Anonymous GET /ServiceProviderConfig for existing workspace -> 200 OK
	req1 := httptest.NewRequest(http.MethodGet, "/ws/"+existingWS.String()+"/scim/v2/ServiceProviderConfig", nil)
	req1 = req1.WithContext(context.WithValue(req1.Context(), WorkspaceIDKey, existingWS))
	rec1 := httptest.NewRecorder()
	mw.ServeHTTP(rec1, req1)
	if rec1.Code != http.StatusOK {
		t.Fatalf("anonymous GET existing workspace = %d, want 200", rec1.Code)
	}

	// 2. Anonymous GET /ServiceProviderConfig for missing workspace -> 404 Not Found
	req2 := httptest.NewRequest(http.MethodGet, "/ws/"+missingWS.String()+"/scim/v2/ServiceProviderConfig", nil)
	req2 = req2.WithContext(context.WithValue(req2.Context(), WorkspaceIDKey, missingWS))
	rec2 := httptest.NewRecorder()
	mw.ServeHTTP(rec2, req2)
	if rec2.Code != http.StatusNotFound {
		t.Fatalf("anonymous GET missing workspace = %d, want 404", rec2.Code)
	}

	// 3. GET /ServiceProviderConfig WITH invalid Bearer token -> 401 Unauthorized
	req3 := httptest.NewRequest(http.MethodGet, "/ws/"+existingWS.String()+"/scim/v2/ServiceProviderConfig", nil)
	req3.Header.Set("Authorization", "Bearer invalid-token")
	req3 = req3.WithContext(context.WithValue(req3.Context(), WorkspaceIDKey, existingWS))
	rec3 := httptest.NewRecorder()
	mw.ServeHTTP(rec3, req3)
	if rec3.Code != http.StatusUnauthorized {
		t.Fatalf("invalid token GET /ServiceProviderConfig = %d, want 401", rec3.Code)
	}

	// 4. Verify anonymous GET /ServiceProviderConfig does NOT set AuthenticatedWorkspaceID in context
	var anonAuthWSSeen bool
	mwCheckCtx := BearerTokenAuth(tokenRepo, wsRepo)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, anonAuthWSSeen = AuthenticatedWorkspaceID(r.Context())
		w.WriteHeader(http.StatusOK)
	}))
	req4 := httptest.NewRequest(http.MethodGet, "/ws/"+existingWS.String()+"/scim/v2/ServiceProviderConfig", nil)
	req4 = req4.WithContext(context.WithValue(req4.Context(), WorkspaceIDKey, existingWS))
	mwCheckCtx.ServeHTTP(httptest.NewRecorder(), req4)
	if anonAuthWSSeen {
		t.Fatal("anonymous ServiceProviderConfig must not populate AuthenticatedWorkspaceID")
	}

	if _, ok := AuthenticatedWorkspaceID(nil); ok { //nolint:staticcheck // testing nil context safety
		t.Fatal("AuthenticatedWorkspaceID(nil) = true, want false")
	}
	if _, ok := AuthenticatedWorkspaceID(context.Background()); ok {
		t.Fatal("AuthenticatedWorkspaceID(background) = true, want false")
	}
	if _, ok := AuthenticatedWorkspaceID(WithAuthenticatedWorkspaceID(context.Background(), uuid.Nil)); ok {
		t.Fatal("AuthenticatedWorkspaceID(uuid.Nil) = true, want false")
	}
}

// Traced RFC requirements (Group 3):
//   - RFC7644-2-fccd30: Map unique client to security subject.
//   - RFC7644-2-d8fe6f: Authorize action against subject and affected resource.
//   - RFC7644-6.1-26ac86: Infer associated tenant from authenticated client identity.
//   - RFC7644-7.4-66599e: Bearer tokens MUST have a determinable limited lifetime (expires_at enforced).
//   - RFC7644-7.4-cb7a78: High-entropy bearer tokens hashed with SHA-256.
func TestBearerTokenAuth_Group3_SubjectTenantAndTokenLifetime(t *testing.T) {
	wsA := uuid.New()
	wsB := uuid.New()

	rawTokenA, err := GenerateSecureToken()
	if err != nil {
		t.Fatalf("GenerateSecureToken: %v", err)
	}
	hashA := HashToken(rawTokenA)
	if hashA == rawTokenA || len(hashA) != 64 {
		t.Fatalf("RFC7644-7.4-cb7a78: expected 64-char SHA-256 hex digest distinct from raw token")
	}

	rawExpiredToken, _ := GenerateSecureToken()
	hashExpired := HashToken(rawExpiredToken)

	rawRevokedToken, _ := GenerateSecureToken()

	tokenRepo := stubTokenFinder{
		findByTokenHashNotRevoked: func(_ context.Context, tokenHash string) (*model.WorkspaceToken, error) {
			switch tokenHash {
			case hashA:
				exp := time.Now().Add(30 * time.Minute)
				return &model.WorkspaceToken{
					WorkspaceID: wsA,
					TokenHash:   hashA,
					ExpiresAt:   &exp,
					Revoked:     false,
				}, nil
			case hashExpired:
				exp := time.Now().Add(-5 * time.Minute)
				return &model.WorkspaceToken{
					WorkspaceID: wsA,
					TokenHash:   hashExpired,
					ExpiresAt:   &exp,
					Revoked:     false,
				}, nil
			default:
				return nil, nil
			}
		},
	}
	wsRepo := stubWorkspaceFinder{
		findByID: func(_ context.Context, id uuid.UUID) (*model.Workspace, error) {
			if id == wsA {
				subject := "tenant-a-admin@example.com"
				return &model.Workspace{ID: wsA, CreatedByUsername: &subject}, nil
			}
			if id == wsB {
				subject := "tenant-b-admin@example.com"
				return &model.Workspace{ID: wsB, CreatedByUsername: &subject}, nil
			}
			return nil, nil
		},
	}

	mw := BearerTokenAuth(tokenRepo, wsRepo)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	// 1. Valid future expires_at token on matching workspace -> 200 OK + mapped security subject
	reqValid := httptest.NewRequest(http.MethodGet, "/ws/"+wsA.String()+"/scim/v2/Users", nil)
	reqValid.Header.Set("Authorization", "Bearer "+rawTokenA)
	reqValid = reqValid.WithContext(context.WithValue(reqValid.Context(), WorkspaceIDKey, wsA))
	reqValid, stateValid := withRequestMetricsState(reqValid)
	recValid := httptest.NewRecorder()
	mw.ServeHTTP(recValid, reqValid)
	if recValid.Code != http.StatusOK {
		t.Fatalf("valid future-expiry token status = %d, want 200", recValid.Code)
	}
	if stateValid.UserEmail != "tenant-a-admin@example.com" {
		t.Errorf("RFC7644-2-fccd30: mapped subject = %q, want tenant-a-admin@example.com", stateValid.UserEmail)
	}

	// 2. Cross-workspace presentation (Token A presented on Workspace B) -> 401 Unauthorized
	reqCross := httptest.NewRequest(http.MethodGet, "/ws/"+wsB.String()+"/scim/v2/Users", nil)
	reqCross.Header.Set("Authorization", "Bearer "+rawTokenA)
	reqCross = reqCross.WithContext(context.WithValue(reqCross.Context(), WorkspaceIDKey, wsB))
	recCross := httptest.NewRecorder()
	mw.ServeHTTP(recCross, reqCross)
	if recCross.Code != http.StatusUnauthorized {
		t.Fatalf("RFC7644-2-d8fe6f / RFC7644-6.1-26ac86: cross-workspace token status = %d, want 401", recCross.Code)
	}

	// 3. Expired token (expires_at in the past) -> 401 Unauthorized
	reqExpired := httptest.NewRequest(http.MethodGet, "/ws/"+wsA.String()+"/scim/v2/Users", nil)
	reqExpired.Header.Set("Authorization", "Bearer "+rawExpiredToken)
	reqExpired = reqExpired.WithContext(context.WithValue(reqExpired.Context(), WorkspaceIDKey, wsA))
	recExpired := httptest.NewRecorder()
	mw.ServeHTTP(recExpired, reqExpired)
	if recExpired.Code != http.StatusUnauthorized {
		t.Fatalf("RFC7644-7.4-66599e: expired token status = %d, want 401", recExpired.Code)
	}

	// 4. Revoked token -> 401 Unauthorized
	reqRevoked := httptest.NewRequest(http.MethodGet, "/ws/"+wsA.String()+"/scim/v2/Users", nil)
	reqRevoked.Header.Set("Authorization", "Bearer "+rawRevokedToken)
	reqRevoked = reqRevoked.WithContext(context.WithValue(reqRevoked.Context(), WorkspaceIDKey, wsA))
	recRevoked := httptest.NewRecorder()
	mw.ServeHTTP(recRevoked, reqRevoked)
	if recRevoked.Code != http.StatusUnauthorized {
		t.Fatalf("revoked token status = %d, want 401", recRevoked.Code)
	}
}

