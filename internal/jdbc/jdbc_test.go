package jdbc

import (
	"errors"
	"testing"
	"time"
)

// --- OptimisticLockError ---

func TestOptimisticLockError_Error_WithResource(t *testing.T) {
	t.Parallel()

	err := OptimisticLockError{Resource: "user/abc"}
	got := err.Error()
	if got == "" {
		t.Fatal("OptimisticLockError.Error() returned empty string")
	}
	if !errors.Is(err, ErrOptimisticLockConflict) {
		t.Fatalf("OptimisticLockError does not wrap ErrOptimisticLockConflict")
	}
}

func TestOptimisticLockError_Error_WithoutResource(t *testing.T) {
	t.Parallel()

	err := OptimisticLockError{}
	if err.Error() != ErrOptimisticLockConflict.Error() {
		t.Fatalf("OptimisticLockError{}.Error() = %q, want %q", err.Error(), ErrOptimisticLockConflict.Error())
	}
}

func TestOptimisticLockError_Error_TrimsResource(t *testing.T) {
	t.Parallel()

	err := OptimisticLockError{Resource: "  "}
	// trimmed resource is empty, should fall back to base error
	if err.Error() != ErrOptimisticLockConflict.Error() {
		t.Fatalf("OptimisticLockError{Resource:\"  \"}.Error() = %q, want %q", err.Error(), ErrOptimisticLockConflict.Error())
	}
}

func TestOptimisticLockError_Unwrap(t *testing.T) {
	t.Parallel()

	err := OptimisticLockError{Resource: "group/xyz"}
	if !errors.Is(err, ErrOptimisticLockConflict) {
		t.Fatalf("errors.Is(OptimisticLockError, ErrOptimisticLockConflict) = false, want true")
	}
}

// --- CheckOptimisticLock ---

type mockResult struct {
	rows int64
	err  error
}

func (m mockResult) RowsAffected() (int64, error) {
	return m.rows, m.err
}

func TestCheckOptimisticLock_NilResult(t *testing.T) {
	t.Parallel()

	err := CheckOptimisticLock(nil, "user")
	if err == nil {
		t.Fatal("CheckOptimisticLock(nil, ...) = nil, want error")
	}
}

func TestCheckOptimisticLock_ZeroRows(t *testing.T) {
	t.Parallel()

	err := CheckOptimisticLock(mockResult{rows: 0}, "user/123")
	if !errors.Is(err, ErrOptimisticLockConflict) {
		t.Fatalf("CheckOptimisticLock(0 rows) error = %v, want ErrOptimisticLockConflict", err)
	}
}

func TestCheckOptimisticLock_OneRow(t *testing.T) {
	t.Parallel()

	err := CheckOptimisticLock(mockResult{rows: 1}, "user/123")
	if err != nil {
		t.Fatalf("CheckOptimisticLock(1 row) = %v, want nil", err)
	}
}

func TestCheckOptimisticLock_RowsAffectedError(t *testing.T) {
	t.Parallel()

	sentinel := errors.New("rows error")
	err := CheckOptimisticLock(mockResult{rows: 0, err: sentinel}, "user")
	if !errors.Is(err, sentinel) {
		t.Fatalf("CheckOptimisticLock() error = %v, want sentinel rows error", err)
	}
}

// --- lockTableStatement ---

func TestLockTableStatement_ValidTable(t *testing.T) {
	t.Parallel()

	stmt, err := lockTableStatement("scim_users")
	if err != nil {
		t.Fatalf("lockTableStatement(scim_users) error = %v", err)
	}
	if stmt != "LOCK TABLE scim_users IN EXCLUSIVE MODE" {
		t.Fatalf("lockTableStatement() = %q, want LOCK TABLE scim_users IN EXCLUSIVE MODE", stmt)
	}
}

func TestLockTableStatement_EmptyName(t *testing.T) {
	t.Parallel()

	_, err := lockTableStatement("")
	if !errors.Is(err, ErrTableNameRequired) {
		t.Fatalf("lockTableStatement(\"\") error = %v, want ErrTableNameRequired", err)
	}
}

func TestLockTableStatement_WhitespaceName(t *testing.T) {
	t.Parallel()

	_, err := lockTableStatement("   ")
	if !errors.Is(err, ErrTableNameRequired) {
		t.Fatalf("lockTableStatement(\"   \") error = %v, want ErrTableNameRequired", err)
	}
}

func TestLockTableStatement_InvalidCharacters(t *testing.T) {
	t.Parallel()

	_, err := lockTableStatement("users; DROP TABLE users")
	if err == nil {
		t.Fatal("lockTableStatement(sql injection) = nil, want error")
	}
}

func TestLockTableStatement_SchemaQualified(t *testing.T) {
	t.Parallel()

	stmt, err := lockTableStatement("public.scim_users")
	if err != nil {
		t.Fatalf("lockTableStatement(public.scim_users) error = %v", err)
	}
	if stmt != "LOCK TABLE public.scim_users IN EXCLUSIVE MODE" {
		t.Fatalf("lockTableStatement() = %q", stmt)
	}
}

// --- isValidIdentifier ---

func TestIsValidIdentifier(t *testing.T) {
	t.Parallel()

	valid := []string{"users", "scim_users", "public.users", "Users123", "a"}
	for _, name := range valid {
		if !isValidIdentifier(name) {
			t.Errorf("isValidIdentifier(%q) = false, want true", name)
		}
	}

	invalid := []string{"users;", "drop table", "users--", "us$ers", "us@ers", "us-ers"}
	for _, name := range invalid {
		if isValidIdentifier(name) {
			t.Errorf("isValidIdentifier(%q) = true, want false", name)
		}
	}
}

// --- buildPoolConfig ---

func TestBuildPoolConfig_EmptyDSN(t *testing.T) {
	t.Parallel()

	_, err := buildPoolConfig(Config{DSN: ""})
	if !errors.Is(err, ErrDSNRequired) {
		t.Fatalf("buildPoolConfig(empty DSN) error = %v, want ErrDSNRequired", err)
	}
}

func TestBuildPoolConfig_WhitespaceDSN(t *testing.T) {
	t.Parallel()

	_, err := buildPoolConfig(Config{DSN: "   "})
	if !errors.Is(err, ErrDSNRequired) {
		t.Fatalf("buildPoolConfig(whitespace DSN) error = %v, want ErrDSNRequired", err)
	}
}

func TestBuildPoolConfig_ValidDSN(t *testing.T) {
	t.Parallel()

	cfg, err := buildPoolConfig(Config{DSN: "postgres://user:pass@localhost:5432/testdb"})
	if err != nil {
		t.Fatalf("buildPoolConfig(valid DSN) error = %v", err)
	}
	if cfg == nil {
		t.Fatal("buildPoolConfig(valid DSN) = nil, want non-nil pool config")
	}
}

func TestBuildPoolConfig_AppliesConnLimits(t *testing.T) {
	t.Parallel()

	cfg, err := buildPoolConfig(Config{
		DSN:               "postgres://user:pass@localhost:5432/testdb",
		MaxConns:          20,
		MinConns:          5,
		MaxConnLifetime:   30 * time.Minute,
		MaxConnIdleTime:   10 * time.Minute,
		HealthCheckPeriod: 1 * time.Minute,
	})
	if err != nil {
		t.Fatalf("buildPoolConfig() error = %v", err)
	}
	if cfg.MaxConns != 20 {
		t.Errorf("MaxConns = %d, want 20", cfg.MaxConns)
	}
	if cfg.MinConns != 5 {
		t.Errorf("MinConns = %d, want 5", cfg.MinConns)
	}
	if cfg.MaxConnLifetime != 30*time.Minute {
		t.Errorf("MaxConnLifetime = %v, want 30m", cfg.MaxConnLifetime)
	}
	if cfg.MaxConnIdleTime != 10*time.Minute {
		t.Errorf("MaxConnIdleTime = %v, want 10m", cfg.MaxConnIdleTime)
	}
	if cfg.HealthCheckPeriod != 1*time.Minute {
		t.Errorf("HealthCheckPeriod = %v, want 1m", cfg.HealthCheckPeriod)
	}
}

func TestBuildPoolConfig_ZeroValuesNotOverridden(t *testing.T) {
	t.Parallel()

	cfg, err := buildPoolConfig(Config{
		DSN:      "postgres://user:pass@localhost:5432/testdb",
		MaxConns: 0, // should not override pool default
	})
	if err != nil {
		t.Fatalf("buildPoolConfig() error = %v", err)
	}
	// pgxpool default MaxConns is 4; 0 means "don't override"
	if cfg.MaxConns == 0 {
		t.Error("MaxConns should not be zero after buildPoolConfig with zero override")
	}
}
