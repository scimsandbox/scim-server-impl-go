package repository

import (
	"context"
	"testing"

	"github.com/google/uuid"
)

func TestRequestLogRepository_DeleteOldLogsForWorkspace_NegativeMaxCount(t *testing.T) {
	t.Parallel()

	repo := NewRequestLogRepository()
	_, err := repo.DeleteOldLogsForWorkspace(context.Background(), uuid.New(), -1)
	if err == nil {
		t.Fatal("expected error for negative maxCount, got nil")
	}
}

func TestWorkspaceRepository_New(t *testing.T) {
	t.Parallel()

	repo := NewWorkspaceRepository()
	if repo == nil {
		t.Fatal("NewWorkspaceRepository() returned nil")
	}
}
