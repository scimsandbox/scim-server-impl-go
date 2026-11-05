package repository

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/scimsandbox/scim-server-impl-go/internal/jdbc"
	"github.com/scimsandbox/scim-server-impl-go/internal/model"
)

// DefaultEventPruneBatchSize is the number of terminal events deleted per batch.
const DefaultEventPruneBatchSize = 5000

// AsyncEventRepo defines the interface for persisting and querying RFC 9967 async events.
type AsyncEventRepo interface {
	Create(ctx context.Context, e *model.ScimAsyncEvent) error
	FindByTxnIDAndWorkspaceID(ctx context.Context, txnID, workspaceID uuid.UUID) (*model.ScimAsyncEvent, error)
	UpdateStatusAndPayload(ctx context.Context, txnID uuid.UUID, status string, resourceID *uuid.UUID, payload *string, completedAt time.Time) error
	ListWorkspaceIDsExceedingEventCount(ctx context.Context, maxCount int) ([]uuid.UUID, error)
	DeleteOldEventsForWorkspace(ctx context.Context, workspaceID uuid.UUID, maxCount int) (int64, error)
	FindStalePendingEvents(ctx context.Context, olderThan time.Time, limit int) ([]*model.ScimAsyncEvent, error)
	TransitionPendingToFailed(ctx context.Context, txnID uuid.UUID, payload string, completedAt time.Time) (bool, error)
}

// AsyncEventRepository provides PostgreSQL persistence for SCIM asynchronous events.
type AsyncEventRepository struct{}

var _ AsyncEventRepo = (*AsyncEventRepository)(nil)

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

// ListWorkspaceIDsExceedingEventCount returns the IDs of all workspaces having more than maxCount terminal events.
// maxCount must be greater than 0; passing <= 0 returns an error.
func (r *AsyncEventRepository) ListWorkspaceIDsExceedingEventCount(ctx context.Context, maxCount int) ([]uuid.UUID, error) {
	if maxCount <= 0 {
		return nil, fmt.Errorf("maxCount must be greater than 0: %d", maxCount)
	}

	rows, err := jdbc.QueryContext(ctx,
		`SELECT workspace_id
		 FROM scim_async_events
		 WHERE status IN ('COMPLETED', 'FAILED')
		 GROUP BY workspace_id
		 HAVING count(*) > $1`, maxCount)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var ids []uuid.UUID
	for rows.Next() {
		var id uuid.UUID
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		ids = append(ids, id)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return ids, nil
}

// DeleteOldEventsForWorkspace deletes terminal events (COMPLETED, FAILED) for a workspace, retaining the latest maxCount.
// It loops in batches of DefaultEventPruneBatchSize until all excess events are removed.
func (r *AsyncEventRepository) DeleteOldEventsForWorkspace(ctx context.Context, workspaceID uuid.UUID, maxCount int) (int64, error) {
	if maxCount < 0 {
		return 0, fmt.Errorf("maxCount must be non-negative: %d", maxCount)
	}

	var totalDeleted int64
	for {
		if err := ctx.Err(); err != nil {
			return totalDeleted, err
		}

		tag, err := jdbc.ExecContext(ctx,
			`DELETE FROM scim_async_events
			 WHERE workspace_id = $1
			   AND txn_id IN (
			     SELECT txn_id FROM scim_async_events
			     WHERE workspace_id = $1
			       AND status IN ('COMPLETED', 'FAILED')
			     ORDER BY created_at DESC, txn_id DESC
			     OFFSET $2
			     LIMIT $3
			   )`,
			workspaceID, maxCount, DefaultEventPruneBatchSize)
		if err != nil {
			return totalDeleted, err
		}

		rows, err := tag.RowsAffected()
		if err != nil {
			return totalDeleted, err
		}
		totalDeleted += rows

		if rows < DefaultEventPruneBatchSize {
			break
		}
	}

	return totalDeleted, nil
}

// FindStalePendingEvents returns pending events created before olderThan, ordered by created_at ASC up to limit.
func (r *AsyncEventRepository) FindStalePendingEvents(ctx context.Context, olderThan time.Time, limit int) ([]*model.ScimAsyncEvent, error) {
	if limit <= 0 {
		limit = 1000
	}
	query := `SELECT ` + asyncEventColumns + `
		FROM scim_async_events
		WHERE status = 'PENDING' AND created_at < $1
		ORDER BY created_at ASC
		LIMIT $2`
	rows, err := jdbc.QueryContext(ctx, query, olderThan, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var events []*model.ScimAsyncEvent
	for rows.Next() {
		e, err := scanAsyncEvent(rows)
		if err != nil {
			return nil, err
		}
		events = append(events, e)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return events, nil
}

// TransitionPendingToFailed atomically transitions an event from PENDING to FAILED with the given payload and completedAt.
// It returns true if a row was updated, or false if the event was no longer PENDING or did not exist.
func (r *AsyncEventRepository) TransitionPendingToFailed(ctx context.Context, txnID uuid.UUID, payload string, completedAt time.Time) (bool, error) {
	query := `UPDATE scim_async_events
		SET status = 'FAILED', set_payload = $2, completed_at = $3
		WHERE txn_id = $1 AND status = 'PENDING'`

	tag, err := jdbc.ExecContext(ctx, query, txnID, payload, completedAt)
	if err != nil {
		return false, err
	}
	rows, err := tag.RowsAffected()
	if err != nil {
		return false, err
	}
	return rows > 0, nil
}
