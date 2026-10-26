package repository

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/scimsandbox/scim-server-impl-go/internal/jdbc"
	"github.com/scimsandbox/scim-server-impl-go/internal/model"
)

// AsyncEventRepo defines the interface for persisting and querying RFC 9967 async events.
type AsyncEventRepo interface {
	Create(ctx context.Context, e *model.ScimAsyncEvent) error
	FindByTxnIDAndWorkspaceID(ctx context.Context, txnID, workspaceID uuid.UUID) (*model.ScimAsyncEvent, error)
	UpdateStatusAndPayload(ctx context.Context, txnID uuid.UUID, status string, resourceID *uuid.UUID, payload *string, completedAt time.Time) error
}

// AsyncEventRepository provides PostgreSQL persistence for SCIM asynchronous events.
type AsyncEventRepository struct{}

// NewAsyncEventRepository constructs a new AsyncEventRepository.
func NewAsyncEventRepository() *AsyncEventRepository {
	return &AsyncEventRepository{}
}

const asyncEventColumns = `txn_id, workspace_id, operation, resource_type, resource_id, status, set_payload, created_at, completed_at`

func scanAsyncEvent(row rowScanner) (*model.ScimAsyncEvent, error) {
	var e model.ScimAsyncEvent
	err := row.Scan(
		&e.TxnID,
		&e.WorkspaceID,
		&e.Operation,
		&e.ResourceType,
		&e.ResourceID,
		&e.Status,
		&e.SetPayload,
		&e.CreatedAt,
		&e.CompletedAt,
	)
	if err != nil {
		return nil, err
	}
	return &e, nil
}

// Create persists a new asynchronous event row.
func (r *AsyncEventRepository) Create(ctx context.Context, e *model.ScimAsyncEvent) error {
	if e.TxnID == uuid.Nil {
		e.TxnID = uuid.New()
	}
	if e.CreatedAt.IsZero() {
		e.CreatedAt = time.Now().UTC()
	}
	if e.Status == "" {
		e.Status = model.AsyncStatusPending
	}

	query := `INSERT INTO scim_async_events (` + asyncEventColumns + `)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`

	_, err := jdbc.ExecContext(ctx, query,
		e.TxnID,
		e.WorkspaceID,
		e.Operation,
		e.ResourceType,
		e.ResourceID,
		e.Status,
		e.SetPayload,
		e.CreatedAt,
		e.CompletedAt,
	)
	return err
}

// FindByTxnIDAndWorkspaceID fetches an async event by transaction ID within a workspace tenant.
func (r *AsyncEventRepository) FindByTxnIDAndWorkspaceID(ctx context.Context, txnID, workspaceID uuid.UUID) (*model.ScimAsyncEvent, error) {
	query := `SELECT ` + asyncEventColumns + ` FROM scim_async_events WHERE txn_id = $1 AND workspace_id = $2`
	row := jdbc.QueryRowContext(ctx, query, txnID, workspaceID)
	e, err := scanAsyncEvent(row)
	if errors.Is(err, jdbc.ErrNoRows) {
		return nil, nil
	}
	return e, err
}

// UpdateStatusAndPayload updates the status, resource_id, set_payload, and completed_at for an async event.
func (r *AsyncEventRepository) UpdateStatusAndPayload(
	ctx context.Context,
	txnID uuid.UUID,
	status string,
	resourceID *uuid.UUID,
	payload *string,
	completedAt time.Time,
) error {
	query := `UPDATE scim_async_events
		SET status = $2, resource_id = COALESCE($3, resource_id), set_payload = $4, completed_at = $5
		WHERE txn_id = $1`

	_, err := jdbc.ExecContext(ctx, query, txnID, status, resourceID, payload, completedAt)
	return err
}
