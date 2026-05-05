// Package jdbc provides a connection-pooled PostgreSQL backend using pgx.
//
// Initialize the global pool with Init and close it with Close:
//
//	err := jdbc.Init(ctx, jdbc.Config{DSN: dsn})
//	defer jdbc.Close()
//
// Use ExecContext, QueryContext, QueryRowContext for non-transactional queries.
// Use InTransaction for transactional operations.
package jdbc
