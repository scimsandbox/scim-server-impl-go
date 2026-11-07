package middleware

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/google/uuid"
	"github.com/scimsandbox/scim-server-impl-go/internal/model"
	"github.com/scimsandbox/scim-server-impl-go/internal/scim"
)

type contextKey string

const WorkspaceIDKey contextKey = "workspaceID"

type tokenFinder interface {
	FindByTokenHashNotRevoked(ctx context.Context, tokenHash string) (*model.WorkspaceToken, error)
}

type workspaceFinder interface {
	FindByID(ctx context.Context, id uuid.UUID) (*model.Workspace, error)
}

// BearerTokenAuth validates the Bearer token against the workspace token store.
func BearerTokenAuth(tokenRepo tokenFinder, workspaceRepo workspaceFinder) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			wsID := r.Context().Value(WorkspaceIDKey)
			if wsID == nil {
				MarkAuthentication(r, AuthenticationFailed)
				w.Header().Set("WWW-Authenticate", "Bearer")
				scim.WriteScimError(w, scim.NewScimError(http.StatusUnauthorized, "", "Unauthorized"))
				return
			}

			authHeader := r.Header.Get("Authorization")
			trimmedPath := strings.TrimRight(r.URL.Path, "/")
			if r.Method == http.MethodGet &&
				strings.HasSuffix(trimmedPath, "/ServiceProviderConfig") &&
				strings.TrimSpace(authHeader) == "" {
				workspaceID, ok := wsID.(uuid.UUID)
				if !ok {
					scim.WriteScimError(w, scim.NewScimError(http.StatusNotFound, "", "Workspace not found"))
					return
				}
				if workspaceRepo != nil {
					ws, err := workspaceRepo.FindByID(r.Context(), workspaceID)
					if err != nil || ws == nil {
						scim.WriteScimError(w, scim.NewScimError(http.StatusNotFound, "", "Workspace not found"))
						return
					}
				}
				next.ServeHTTP(w, r)
				return
			}

			if authHeader == "" || !strings.HasPrefix(authHeader, "Bearer ") {
				MarkAuthentication(r, AuthenticationFailed)
				w.Header().Set("WWW-Authenticate", "Bearer")
				scim.WriteScimError(w, scim.NewScimError(http.StatusUnauthorized, "", "Unauthorized"))
				return
			}

			token := strings.TrimPrefix(authHeader, "Bearer ")
			tokenHash := HashToken(token)

			workspaceID := wsID.(uuid.UUID)
			wsToken, err := tokenRepo.FindByTokenHashNotRevoked(r.Context(), tokenHash)
			if err != nil || wsToken == nil {
				MarkAuthentication(r, AuthenticationFailed)
				w.Header().Set("WWW-Authenticate", "Bearer")
				scim.WriteScimError(w, scim.NewScimError(http.StatusUnauthorized, "", "Unauthorized"))
				return
			}

			if wsToken.WorkspaceID != workspaceID {
				MarkAuthentication(r, AuthenticationFailed)
				w.Header().Set("WWW-Authenticate", "Bearer")
				scim.WriteScimError(w, scim.NewScimError(http.StatusUnauthorized, "", "Unauthorized"))
				return
			}

			if wsToken.ExpiresAt != nil && wsToken.ExpiresAt.Before(time.Now()) {
				MarkAuthentication(r, AuthenticationFailed)
				w.Header().Set("WWW-Authenticate", "Bearer")
				scim.WriteScimError(w, scim.NewScimError(http.StatusUnauthorized, "", "Unauthorized"))
				return
			}

			markAuthenticatedPrincipal(r, workspaceRepo, workspaceID)
			MarkAuthentication(r, AuthenticationOK)
			next.ServeHTTP(w, r)
		})
	}
}

// ExtractWorkspaceID extracts the workspace UUID from chi URL params and puts it in context.
func ExtractWorkspaceID(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		wsIDStr := chi.URLParam(r, "workspaceId")
		if wsIDStr == "" {
			MarkWorkspaceID(r, "unknown")
			MarkAuthentication(r, AuthenticationFailed)
			scim.WriteScimError(w, scim.NewScimError(http.StatusNotFound, "", "Not Found"))
			return
		}
		wsID, err := uuid.Parse(wsIDStr)
		if err != nil {
			MarkWorkspaceID(r, "invalid")
			MarkAuthentication(r, AuthenticationFailed)
			scim.WriteScimError(w, scim.NewScimError(http.StatusNotFound, "", "Not Found"))
			return
		}
		MarkWorkspaceID(r, wsID.String())
		ctx := context.WithValue(r.Context(), WorkspaceIDKey, wsID)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func markAuthenticatedPrincipal(r *http.Request, workspaceRepo workspaceFinder, workspaceID uuid.UUID) {
	if workspaceRepo == nil {
		return
	}

	workspace, err := workspaceRepo.FindByID(r.Context(), workspaceID)
	if err != nil || workspace == nil || workspace.CreatedByUsername == nil {
		return
	}

	userEmail := strings.TrimSpace(*workspace.CreatedByUsername)
	if userEmail != "" {
		MarkUserEmail(r, userEmail)
	}
}

func HashToken(token string) string {
	h := sha256.Sum256([]byte(token))
	return hex.EncodeToString(h[:])
}
