package repository

import (
	"context"
	"testing"

	"github.com/google/uuid"
)

func TestRequestLogRepository_DeleteOldLogsForWorkspace_NonPositiveMaxCount(t *testing.T) {
	t.Parallel()

	repo := NewRequestLogRepository()
	for _, invalidMax := range []int{-1, 0} {
		_, err := repo.DeleteOldLogsForWorkspace(context.Background(), uuid.New(), invalidMax)
		if err == nil {
			t.Fatalf("expected error for maxCount=%d, got nil", invalidMax)
		}
	}
}

func TestRequestLogRepository_ListWorkspaceIDsExceedingLogCount_NonPositiveMaxCount(t *testing.T) {
	t.Parallel()

	repo := NewRequestLogRepository()
	for _, invalidMax := range []int{-1, 0} {
		_, err := repo.ListWorkspaceIDsExceedingLogCount(context.Background(), invalidMax)
		if err == nil {
			t.Fatalf("expected error for maxCount=%d, got nil", invalidMax)
		}
	}
}

