package jdbc

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

type databaseBackend interface {
	Executor
	BeginTx(ctx context.Context) (transactionBackend, error)
	Close() error
}

type transactionBackend interface {
	Executor
	Commit(ctx context.Context) error
	Rollback(ctx context.Context) error
}

type backendState struct {
	mu      sync.RWMutex
	backend databaseBackend
}

type transaction struct {
	backend transactionBackend
}

type pgxDatabaseBackend struct {
	pool *pgxpool.Pool
}

type pgxTransactionBackend struct {
	tx pgx.Tx
}

type pgxRow struct {
	row pgx.Row
}

type commandTagResult struct {
	tag pgconn.CommandTag
}

type errorRow struct {
	err error
}

var defaultBackendState backendState

var parsePoolConfig = pgxpool.ParseConfig

var newDatabaseBackend = func(ctx context.Context, config *pgxpool.Config) (databaseBackend, error) {
	pool, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		return nil, err
	}
	return pgxDatabaseBackend{pool: pool}, nil
}

func initBackend(ctx context.Context, config Config) error {
	poolConfig, err := buildPoolConfig(config)
	if err != nil {
		return err
	}

	backend, err := newDatabaseBackend(ctx, poolConfig)
	if err != nil {
		return err
	}

	defaultBackendState.mu.Lock()
	defer defaultBackendState.mu.Unlock()

	if defaultBackendState.backend != nil {
		_ = backend.Close()
		return ErrAlreadyInitialized
	}

	defaultBackendState.backend = backend
	return nil
}

func closeBackend() error {
	defaultBackendState.mu.Lock()
	backend := defaultBackendState.backend
	defaultBackendState.backend = nil
	defaultBackendState.mu.Unlock()

	if backend == nil {
		return nil
	}

	return backend.Close()
}

func currentBackend() (databaseBackend, error) {
	defaultBackendState.mu.RLock()
	backend := defaultBackendState.backend
	defaultBackendState.mu.RUnlock()

	if backend == nil {
		return nil, ErrNotInitialized
	}

	return backend, nil
}

func buildPoolConfig(config Config) (*pgxpool.Config, error) {
	dsn := strings.TrimSpace(config.DSN)
	if dsn == "" {
		return nil, ErrDSNRequired
	}

	poolConfig, err := parsePoolConfig(dsn)
	if err != nil {
		return nil, err
	}

	if config.MaxConns > 0 {
		poolConfig.MaxConns = config.MaxConns
	}
	if config.MinConns > 0 {
		poolConfig.MinConns = config.MinConns
	}
	if config.MaxConnLifetime > 0 {
		poolConfig.MaxConnLifetime = config.MaxConnLifetime
	}
	if config.MaxConnIdleTime > 0 {
		poolConfig.MaxConnIdleTime = config.MaxConnIdleTime
	}
	if config.HealthCheckPeriod > 0 {
		poolConfig.HealthCheckPeriod = config.HealthCheckPeriod
	}

	poolConfig.ConnConfig.DefaultQueryExecMode = pgx.QueryExecModeCacheStatement
	return poolConfig, nil
}

func runInTransaction(ctx context.Context, backend databaseBackend, table string, withLock bool, fn func(Tx) error) (err error) {
	txBackend, err := backend.BeginTx(ctx)
	if err != nil {
		return err
	}

	tx := &transaction{backend: txBackend}

	defer func() {
		if recovered := recover(); recovered != nil {
			_ = txBackend.Rollback(ctx)
			panic(recovered)
		}
		if err != nil {
			_ = txBackend.Rollback(ctx)
			return
		}
		err = txBackend.Commit(ctx)
	}()

	if withLock {
		if err = tx.LockTable(ctx, table); err != nil {
			return err
		}
	}

	err = fn(tx)
	return err
}

func (t *transaction) ExecContext(ctx context.Context, query string, args ...any) (Result, error) {
	return t.backend.ExecContext(ctx, query, args...)
}

func (t *transaction) QueryContext(ctx context.Context, query string, args ...any) (Rows, error) {
	return t.backend.QueryContext(ctx, query, args...)
}

func (t *transaction) QueryRowContext(ctx context.Context, query string, args ...any) Row {
	return t.backend.QueryRowContext(ctx, query, args...)
}

func (t *transaction) LockTable(ctx context.Context, table string) error {
	statement, err := lockTableStatement(table)
	if err != nil {
		return err
	}
	_, err = t.backend.ExecContext(ctx, statement)
	return err
}

func (r commandTagResult) RowsAffected() (int64, error) {
	return r.tag.RowsAffected(), nil
}

func (r errorRow) Scan(dest ...any) error {
	return r.err
}

func (r pgxRow) Scan(dest ...any) error {
	err := r.row.Scan(dest...)
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrNoRows
	}
	return err
}

func (b pgxDatabaseBackend) ExecContext(ctx context.Context, query string, args ...any) (Result, error) {
	tag, err := b.pool.Exec(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	return commandTagResult{tag: tag}, nil
}

func (b pgxDatabaseBackend) QueryContext(ctx context.Context, query string, args ...any) (Rows, error) {
	return b.pool.Query(ctx, query, args...)
}

func (b pgxDatabaseBackend) QueryRowContext(ctx context.Context, query string, args ...any) Row {
	return pgxRow{row: b.pool.QueryRow(ctx, query, args...)}
}

func (b pgxDatabaseBackend) BeginTx(ctx context.Context) (transactionBackend, error) {
	tx, err := b.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return nil, err
	}
	return pgxTransactionBackend{tx: tx}, nil
}

func (b pgxDatabaseBackend) Close() error {
	b.pool.Close()
	return nil
}

func (b pgxTransactionBackend) ExecContext(ctx context.Context, query string, args ...any) (Result, error) {
	tag, err := b.tx.Exec(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	return commandTagResult{tag: tag}, nil
}

func (b pgxTransactionBackend) QueryContext(ctx context.Context, query string, args ...any) (Rows, error) {
	return b.tx.Query(ctx, query, args...)
}

func (b pgxTransactionBackend) QueryRowContext(ctx context.Context, query string, args ...any) Row {
	return pgxRow{row: b.tx.QueryRow(ctx, query, args...)}
}

func (b pgxTransactionBackend) Commit(ctx context.Context) error {
	return b.tx.Commit(ctx)
}

func (b pgxTransactionBackend) Rollback(ctx context.Context) error {
	return b.tx.Rollback(ctx)
}

func lockTableStatement(table string) (string, error) {
	name := strings.TrimSpace(table)
	if name == "" {
		return "", ErrTableNameRequired
	}
	if !isValidIdentifier(name) {
		return "", fmt.Errorf("jdbc invalid table name: %q", name)
	}

	return fmt.Sprintf("LOCK TABLE %s IN EXCLUSIVE MODE", name), nil
}

func isValidIdentifier(name string) bool {
	for _, r := range name {
		if !(r >= 'a' && r <= 'z') && !(r >= 'A' && r <= 'Z') && !(r >= '0' && r <= '9') && r != '_' && r != '.' {
			return false
		}
	}
	return true
}
