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

type WorkspaceRepository struct{}

func NewWorkspaceRepository() *WorkspaceRepository {
	return &WorkspaceRepository{}
}

func (r *WorkspaceRepository) FindByID(ctx context.Context, id uuid.UUID) (*model.Workspace, error) {
	var w model.Workspace
	err := jdbc.QueryRowContext(ctx,
		`SELECT id, name, description, created_by_username, created_at, updated_at
		 FROM workspaces WHERE id = $1`, id).Scan(
		&w.ID, &w.Name, &w.Description, &w.CreatedByUsername, &w.CreatedAt, &w.UpdatedAt)
	if errors.Is(err, jdbc.ErrNoRows) {
		return nil, nil // Or a specific error
	}
	if err != nil {
		return nil, err
	}
	return &w, nil
}

func (r *WorkspaceRepository) ListIDs(ctx context.Context) ([]uuid.UUID, error) {
	rows, err := jdbc.QueryContext(ctx, `SELECT id FROM workspaces`)
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

func (r *WorkspaceRepository) TouchUpdatedAt(ctx context.Context, id uuid.UUID) error {
	_, err := jdbc.ExecContext(ctx,
		`UPDATE workspaces SET updated_at = $1 WHERE id = $2`, time.Now().UTC(), id)
	return err
}

func (r *WorkspaceRepository) DeleteStale(ctx context.Context, before time.Time) (int64, error) {
	tag, err := jdbc.ExecContext(ctx,
		`DELETE FROM workspaces WHERE updated_at < $1`, before)
	if err != nil {
		return 0, err
	}
	return tag.RowsAffected()
}

type TokenRepository struct{}

func NewTokenRepository() *TokenRepository {
	return &TokenRepository{}
}

func (r *TokenRepository) FindByTokenHashNotRevoked(ctx context.Context, tokenHash string) (*model.WorkspaceToken, error) {
	var t model.WorkspaceToken
	err := jdbc.QueryRowContext(ctx,
		`SELECT t.id, t.workspace_id, t.token_hash, t.name, t.description,
		        t.expires_at, t.revoked, t.created_at, t.updated_at
		 FROM workspace_tokens t
		 WHERE t.token_hash = $1 AND t.revoked = false`, tokenHash).Scan(
		&t.ID, &t.WorkspaceID, &t.TokenHash, &t.Name, &t.Description,
		&t.ExpiresAt, &t.Revoked, &t.CreatedAt, &t.UpdatedAt)
	if errors.Is(err, jdbc.ErrNoRows) {
		return nil, nil // Return nil, nil when no token is found, standard pattern here
	}
	if err != nil {
		return nil, err
	}
	return &t, nil
}

type RequestLogRepository struct{}

func NewRequestLogRepository() *RequestLogRepository {
	return &RequestLogRepository{}
}

func (r *RequestLogRepository) Create(ctx context.Context, log *model.ScimRequestLog) error {
	log.ID = uuid.New()
	log.CreatedAt = time.Now().UTC()
	_, err := jdbc.ExecContext(ctx,
		`INSERT INTO scim_request_logs (id, workspace_id, http_method, request_path, http_status, request_body, response_body, created_at)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
		log.ID, log.WorkspaceID, log.HttpMethod, log.RequestPath, log.HttpStatus,
		log.RequestBody, log.ResponseBody, log.CreatedAt)
	return err
}

const DefaultPruneBatchSize = 5000

// DeleteOldLogsForWorkspace deletes excess request logs for a workspace beyond the most recent maxCount.
// It executes in batches of DefaultPruneBatchSize to prevent long-lived locks and large WAL spikes.
// maxCount must be greater than 0; passing <= 0 returns an error to prevent accidental total deletion.
func (r *RequestLogRepository) DeleteOldLogsForWorkspace(ctx context.Context, workspaceID uuid.UUID, maxCount int) (int64, error) {
	if maxCount <= 0 {
		return 0, fmt.Errorf("maxCount must be greater than 0: %d", maxCount)
	}

	var totalDeleted int64
	for {
		if err := ctx.Err(); err != nil {
			return totalDeleted, err
		}

		tag, err := jdbc.ExecContext(ctx,
			`DELETE FROM scim_request_logs 
			 WHERE workspace_id = $1 
			   AND id IN (
			     SELECT id FROM scim_request_logs 
			     WHERE workspace_id = $1 
			     ORDER BY created_at DESC, id DESC 
			     OFFSET $2 
			     LIMIT $3
			   )`,
			workspaceID, maxCount, DefaultPruneBatchSize)
		if err != nil {
			return totalDeleted, err
		}

		rows, err := tag.RowsAffected()
		if err != nil {
			return totalDeleted, err
		}
		totalDeleted += rows

		if rows < DefaultPruneBatchSize {
			break
		}
	}

	return totalDeleted, nil
}

// ListWorkspaceIDsExceedingLogCount returns the IDs of all workspaces having more than maxCount request logs.
// maxCount must be greater than 0; passing <= 0 returns an error.
func (r *RequestLogRepository) ListWorkspaceIDsExceedingLogCount(ctx context.Context, maxCount int) ([]uuid.UUID, error) {
	if maxCount <= 0 {
		return nil, fmt.Errorf("maxCount must be greater than 0: %d", maxCount)
	}

	rows, err := jdbc.QueryContext(ctx,
		`SELECT workspace_id 
		 FROM scim_request_logs 
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
