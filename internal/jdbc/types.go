package jdbc

import (
	"context"
	"errors"
	"time"
)

type Config struct {
	DSN               string
	MaxConns          int32
	MinConns          int32
	MaxConnLifetime   time.Duration
	MaxConnIdleTime   time.Duration
	HealthCheckPeriod time.Duration
}

type Result interface {
	RowsAffected() (int64, error)
}

type Rows interface {
	Close()
	Err() error
	Next() bool
	Scan(dest ...any) error
}

type Row interface {
	Scan(dest ...any) error
}

type Executor interface {
	ExecContext(ctx context.Context, query string, args ...any) (Result, error)
	QueryContext(ctx context.Context, query string, args ...any) (Rows, error)
	QueryRowContext(ctx context.Context, query string, args ...any) Row
}

type Tx interface {
	Executor
	LockTable(ctx context.Context, table string) error
}

var (
	ErrDSNRequired             = errors.New("jdbc postgres dsn is required")
	ErrNotInitialized          = errors.New("jdbc pool is not initialized")
	ErrAlreadyInitialized      = errors.New("jdbc pool is already initialized")
	ErrNoRows                  = errors.New("jdbc no rows")
	ErrTableNameRequired       = errors.New("jdbc table name is required")
	ErrOptimisticLockConflict  = errors.New("jdbc optimistic lock conflict")
	errNilOptimisticLockResult = errors.New("jdbc optimistic lock result is nil")
)

type OptimisticLockError struct {
	Resource string
}
