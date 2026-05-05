package service

import (
	"context"
	"time"

	"github.com/scimsandbox/scim-server-impl-go/internal/logging"
	"github.com/scimsandbox/scim-server-impl-go/internal/repository"
)

type WorkspaceCleanupService struct {
	workspaceRepo *repository.WorkspaceRepository
	logger        logging.Logger
}

func NewWorkspaceCleanupService(
	workspaceRepo *repository.WorkspaceRepository,
	logger logging.Logger,
) *WorkspaceCleanupService {
	return &WorkspaceCleanupService{
		workspaceRepo: workspaceRepo,
		logger:        logger,
	}
}

func (s *WorkspaceCleanupService) Start(ctx context.Context, interval, staleAfter time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.cleanup(ctx, staleAfter)
		}
	}
}

func (s *WorkspaceCleanupService) cleanup(ctx context.Context, staleAfter time.Duration) {
	deleted, err := s.workspaceRepo.DeleteStale(ctx, time.Now().Add(-staleAfter))
	if err != nil {
		s.logger.Error("workspace cleanup failed", logging.Error(err))
		return
	}
	if deleted > 0 {
		s.logger.Info("cleaned up stale workspaces", logging.Int64("count", deleted))
	}
}
