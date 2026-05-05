package jdbc

import (
	"context"
	"fmt"
	"strings"
)

func (e OptimisticLockError) Error() string {
	resource := strings.TrimSpace(e.Resource)
	if resource == "" {
		return ErrOptimisticLockConflict.Error()
	}
	return fmt.Sprintf("%s: %s", ErrOptimisticLockConflict.Error(), resource)
}

func (e OptimisticLockError) Unwrap() error {
	return ErrOptimisticLockConflict
}

func Init(ctx context.Context, config Config) error {
	return initBackend(ctx, config)
}

func Close() error {
	return closeBackend()
}

func ExecContext(ctx context.Context, query string, args ...any) (Result, error) {
	backend, err := currentBackend()
	if err != nil {
		return nil, err
	}
	return backend.ExecContext(ctx, query, args...)
}

func QueryContext(ctx context.Context, query string, args ...any) (Rows, error) {
	backend, err := currentBackend()
	if err != nil {
		return nil, err
	}
	return backend.QueryContext(ctx, query, args...)
}

func QueryRowContext(ctx context.Context, query string, args ...any) Row {
	backend, err := currentBackend()
	if err != nil {
		return errorRow{err: err}
	}
	return backend.QueryRowContext(ctx, query, args...)
}

func InTransaction(ctx context.Context, fn func(Tx) error) error {
	backend, err := currentBackend()
	if err != nil {
		return err
	}
	return runInTransaction(ctx, backend, "", false, fn)
}

func InTransactionWithLock(ctx context.Context, table string, fn func(Tx) error) error {
	backend, err := currentBackend()
	if err != nil {
		return err
	}
	return runInTransaction(ctx, backend, table, true, fn)
}

func ExecOptimisticContext(ctx context.Context, executor Executor, resource string, query string, args ...any) (Result, error) {
	result, err := executor.ExecContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	if err := CheckOptimisticLock(result, resource); err != nil {
		return result, err
	}
	return result, nil
}

func CheckOptimisticLock(result Result, resource string) error {
	if result == nil {
		return errNilOptimisticLockResult
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if rowsAffected == 0 {
		return OptimisticLockError{Resource: resource}
	}
	return nil
}
