package repository

import (
	"context"
	"errors"
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
