package service

import (
	"context"
	"time"

	"github.com/google/uuid"
	"github.com/scimsandbox/scim-server-impl-go/internal/logging"
	"github.com/scimsandbox/scim-server-impl-go/internal/repository"
)

const (
	// DefaultRequestLogCleanupInterval is the default period between cleanup runs.
	DefaultRequestLogCleanupInterval = time.Hour
	// DefaultRequestLogCleanupMaxCount is the default number of latest logs retained per workspace.
	DefaultRequestLogCleanupMaxCount = 10000
)

// WorkspaceLister defines the workspace enumeration contract needed for cleanup.
type WorkspaceLister interface {
	ListIDs(ctx context.Context) ([]uuid.UUID, error)
}

// RequestLogDeleter defines the log pruning contract needed for cleanup.
type RequestLogDeleter interface {
	DeleteOldLogsForWorkspace(ctx context.Context, workspaceID uuid.UUID, maxCount int) (int64, error)
}

// Compile-time assertions verifying repository types satisfy service interfaces.
var (
	_ WorkspaceLister   = (*repository.WorkspaceRepository)(nil)
	_ RequestLogDeleter = (*repository.RequestLogRepository)(nil)
)

// RequestLogCleanupService periodically cleans up old request logs per workspace.
type RequestLogCleanupService struct {
	requestLogRepo RequestLogDeleter
	workspaceRepo  WorkspaceLister
	logger         logging.Logger
	enabled        bool
	interval       time.Duration
	maxCount       int
}

// NewRequestLogCleanupService creates a new RequestLogCleanupService.
func NewRequestLogCleanupService(
	requestLogRepo RequestLogDeleter,
	workspaceRepo WorkspaceLister,
	logger logging.Logger,
	enabled bool,
	interval time.Duration,
	maxCount int,
) *RequestLogCleanupService {
	if interval <= 0 {
		interval = DefaultRequestLogCleanupInterval
	}
	if maxCount <= 0 {
		maxCount = DefaultRequestLogCleanupMaxCount
	}
	return &RequestLogCleanupService{
		requestLogRepo: requestLogRepo,
		workspaceRepo:  workspaceRepo,
		logger:         logger,
		enabled:        enabled,
		interval:       interval,
		maxCount:       maxCount,
	}
}

// Enabled returns whether cleanup is enabled.
func (s *RequestLogCleanupService) Enabled() bool {
	return s.enabled
}

// Interval returns the cleanup interval.
func (s *RequestLogCleanupService) Interval() time.Duration {
	return s.interval
}

// MaxCount returns the maximum log count retained per workspace.
func (s *RequestLogCleanupService) MaxCount() int {
	return s.maxCount
}

// SetEnabled updates the enabled toggle.
func (s *RequestLogCleanupService) SetEnabled(enabled bool) {
	s.enabled = enabled
}

// SetInterval updates the cleanup interval.
func (s *RequestLogCleanupService) SetInterval(interval time.Duration) {
	if interval <= 0 {
		interval = DefaultRequestLogCleanupInterval
	}
	s.interval = interval
}

// SetMaxCount updates the max log count retained per workspace.
func (s *RequestLogCleanupService) SetMaxCount(maxCount int) {
	if maxCount <= 0 {
		maxCount = DefaultRequestLogCleanupMaxCount
	}
	s.maxCount = maxCount
}

// Start runs the periodic request log cleanup loop on time.NewTicker(s.interval).
// It terminates cleanly when ctx is cancelled.
func (s *RequestLogCleanupService) Start(ctx context.Context) {
	if !s.enabled {
		return
	}
	interval := s.interval
	if interval <= 0 {
		interval = DefaultRequestLogCleanupInterval
	}

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if ctx.Err() != nil {
				return
			}
			_, _ = s.CleanupOnce(ctx)
		}
	}
}

// CleanupOnce executes a single pruning cycle across all workspaces.
// It iterates workspaces from WorkspaceRepository.ListIDs and prunes each workspace
// via RequestLogRepository.DeleteOldLogsForWorkspace.
// Between workspaces and at start, ctx.Done() is checked for clean cancellation.
// Errors during pruning of one workspace are logged and contained without aborting
// subsequent workspaces.
func (s *RequestLogCleanupService) CleanupOnce(ctx context.Context) (int64, error) {
	if !s.enabled {
		return 0, nil
	}
	if ctx.Err() != nil {
		return 0, ctx.Err()
	}

	workspaceIDs, err := s.workspaceRepo.ListIDs(ctx)
	if err != nil {
		s.logger.Error("failed to list workspaces for request log cleanup", logging.Error(err))
		return 0, err
	}

	maxCount := s.maxCount
	if maxCount <= 0 {
		maxCount = DefaultRequestLogCleanupMaxCount
	}

	var totalDeleted int64
	for _, wsID := range workspaceIDs {
		select {
		case <-ctx.Done():
			return totalDeleted, ctx.Err()
		default:
		}

		deleted, err := s.requestLogRepo.DeleteOldLogsForWorkspace(ctx, wsID, maxCount)
		if err != nil {
			s.logger.Error("request log cleanup failed for workspace",
				logging.String("workspace_id", wsID.String()),
				logging.Error(err),
			)
			continue
		}
		totalDeleted += deleted
	}

	if totalDeleted > 0 {
		s.logger.Info("cleaned up old request logs",
			logging.Int64("deleted_count", totalDeleted),
			logging.Int("retained_per_workspace", maxCount),
		)
	}

	return totalDeleted, nil
}
