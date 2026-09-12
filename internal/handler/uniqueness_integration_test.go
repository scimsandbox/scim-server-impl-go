package handler

import (
	"context"
	"errors"
	"testing"

	"github.com/google/uuid"

	"github.com/scimsandbox/scim-server-impl-go/internal/jdbc"
	"github.com/scimsandbox/scim-server-impl-go/internal/model"
	"github.com/scimsandbox/scim-server-impl-go/internal/repository"
)

// TestUserNameUniquenessIsEnforcedByTheDatabase pins the guarantee that closes the
// check-then-write race. The handlers pre-check uniqueness with LOWER(user_name), but that
// check and the write are separate statements, so concurrent requests can both pass it.
// Writing straight through the repository is the deterministic stand-in for that race: it
// skips the pre-check exactly as a losing racer effectively does.
//
// Before V3 the database accepted the case-variant, leaving two rows for one SCIM identity
// (RFC 7643 §7 gives userName caseExact:false). It must now reject it.
func TestUserNameUniquenessIsEnforcedByTheDatabase(t *testing.T) {
	env := setupTestEnv(t)

	wsID := uuid.New()
	token := generateToken()
	seedWorkspaceAndToken(t, env.ctx, wsID, token)

	repo := repository.NewUserRepository()
	ctx := context.Background()

	first := &model.ScimUser{WorkspaceID: wsID, UserName: "Alice@example.com", Active: true}
	if err := repo.Create(ctx, first); err != nil {
		t.Fatalf("create first user: %v", err)
	}

	variant := &model.ScimUser{WorkspaceID: wsID, UserName: "alice@example.com", Active: true}
	err := repo.Create(ctx, variant)
	if err == nil {
		t.Fatal("database accepted a userName differing only in case; " +
			"the case-insensitive unique index is missing or not enforced")
	}

	// The driver's SQLSTATE must reach callers as this package's own error, so handlers
	// can branch on it without importing pgx.
	if !errors.Is(err, jdbc.ErrUniqueViolation) {
		t.Fatalf("expected jdbc.ErrUniqueViolation, got %T: %v", err, err)
	}

	// And the constraint name must be one the handlers actually map to 409. This is the
	// assertion that fails loudly if the index is ever renamed in a migration.
	if !isUserNameConflict(err) {
		var uniqueErr jdbc.UniqueViolationError
		errors.As(err, &uniqueErr)
		t.Fatalf("unique violation on constraint %q is not recognised as a userName conflict; "+
			"userNameConstraints is out of sync with the schema", uniqueErr.Constraint)
	}
}

// TestIsUserNameConflictIgnoresUnrelatedConstraints guards the 409/500 split: a duplicate
// userName is the client's fault, but an id collision is ours and must not be reported as
// a SCIM uniqueness conflict.
func TestIsUserNameConflictIgnoresUnrelatedConstraints(t *testing.T) {
	cases := []struct {
		constraint string
		want       bool
	}{
		{"uk_scim_users_workspace_user_name", true},
		{"uk_scim_users_workspace_user_name_ci", true},
		{"uk_scim_users_id_workspace", false},
		{"scim_users_pkey", false},
		{"", false},
	}

	for _, tc := range cases {
		err := error(jdbc.UniqueViolationError{Constraint: tc.constraint})
		if got := isUserNameConflict(err); got != tc.want {
			t.Errorf("isUserNameConflict(%q) = %v, want %v", tc.constraint, got, tc.want)
		}
	}

	if isUserNameConflict(errors.New("some other failure")) {
		t.Error("a non-unique-violation error must not be treated as a userName conflict")
	}
}
