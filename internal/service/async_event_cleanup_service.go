package service

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/scimsandbox/scim-server-impl-go/internal/logging"
	"github.com/scimsandbox/scim-server-impl-go/internal/model"
	"github.com/scimsandbox/scim-server-impl-go/internal/repository"
)

const (
	// DefaultAsyncEventCleanupInterval is the default period between cleanup runs.
	DefaultAsyncEventCleanupInterval = time.Hour
	// DefaultAsyncEventCleanupMaxCount is the default number of latest terminal events retained per workspace.
	DefaultAsyncEventCleanupMaxCount = 5000
	// DefaultAsyncEventStalePendingAfter is the default duration after which PENDING events are considered stale.
	DefaultAsyncEventStalePendingAfter = 5 * time.Minute
	// StalePendingTimeoutDetail is the normative RFC 9967 error detail message for reaped pending events.
	StalePendingTimeoutDetail = "Asynchronous operation timed out or server restarted"
)

// AsyncEventPruner defines the interface needed by AsyncEventCleanupService for pruning and reaping.
type AsyncEventPruner interface {
	ListWorkspaceIDsExceedingEventCount(ctx context.Context, maxCount int) ([]uuid.UUID, error)
	DeleteOldEventsForWorkspace(ctx context.Context, workspaceID uuid.UUID, maxCount int) (int64, error)
	FindStalePendingEvents(ctx context.Context, olderThan time.Time, limit int) ([]*model.ScimAsyncEvent, error)
	TransitionPendingToFailed(ctx context.Context, txnID uuid.UUID, payload string, completedAt time.Time) (bool, error)
}

// Compile-time assertion verifying repository types satisfy service interfaces.
var _ AsyncEventPruner = (repository.AsyncEventRepo)(nil)

// AsyncEventCleanupService periodically prunes terminal events and sweeps orphaned PENDING events.
type AsyncEventCleanupService struct {
	repo              AsyncEventPruner
	logger            logging.Logger
	enabled           bool
	interval          time.Duration
	maxCount          int
	stalePendingAfter time.Duration
	baseURL           string
}

// NewAsyncEventCleanupService creates a new AsyncEventCleanupService.
func NewAsyncEventCleanupService(
	repo AsyncEventPruner,
	logger logging.Logger,
	enabled bool,
	interval time.Duration,
	maxCount int,
	stalePendingAfter time.Duration,
	baseURL ...string,
) *AsyncEventCleanupService {
	if interval <= 0 {
		interval = DefaultAsyncEventCleanupInterval
	}
	if maxCount <= 0 {
		maxCount = DefaultAsyncEventCleanupMaxCount
	}
	if stalePendingAfter <= 0 {
		stalePendingAfter = DefaultAsyncEventStalePendingAfter
	}
	resolvedBaseURL := "http://localhost:8080"
	if len(baseURL) > 0 && strings.TrimSpace(baseURL[0]) != "" {
		resolvedBaseURL = strings.TrimRight(strings.TrimSpace(baseURL[0]), "/")
	}
	return &AsyncEventCleanupService{
		repo:              repo,
		logger:            logger,
		enabled:           enabled,
		interval:          interval,
		maxCount:          maxCount,
		stalePendingAfter: stalePendingAfter,
		baseURL:           resolvedBaseURL,
	}
}

// Start runs the periodic cleanup and reaping loops on time.NewTicker(s.interval).
// Initial cycles run immediately on startup. It terminates cleanly when ctx is cancelled.
func (s *AsyncEventCleanupService) Start(ctx context.Context) {
	if !s.enabled {
		return
	}
	interval := s.interval
	if interval <= 0 {
		interval = DefaultAsyncEventCleanupInterval
	}

	// Run initial cleanup and reap on startup
	if _, err := s.CleanupTerminalOnce(ctx); err != nil && ctx.Err() != nil {
		return
	}
	if _, err := s.ReapStalePendingOnce(ctx); err != nil && ctx.Err() != nil {
		return
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
			_, _ = s.CleanupTerminalOnce(ctx)
			_, _ = s.ReapStalePendingOnce(ctx)
		}
	}
}

// CleanupTerminalOnce executes a single pruning cycle across workspaces with excess terminal events.
func (s *AsyncEventCleanupService) CleanupTerminalOnce(ctx context.Context) (int64, error) {
	if !s.enabled {
		return 0, nil
	}
	if ctx.Err() != nil {
		return 0, ctx.Err()
	}

	maxCount := s.maxCount
	if maxCount <= 0 {
		maxCount = DefaultAsyncEventCleanupMaxCount
	}

	workspaceIDs, err := s.repo.ListWorkspaceIDsExceedingEventCount(ctx, maxCount)
	if err != nil {
		s.logger.Error("failed to list workspaces for async event cleanup", logging.Error(err))
		return 0, err
	}

	var totalDeleted int64
	for _, wsID := range workspaceIDs {
		select {
		case <-ctx.Done():
			return totalDeleted, ctx.Err()
		default:
		}

		deleted, err := s.repo.DeleteOldEventsForWorkspace(ctx, wsID, maxCount)
		if err != nil {
			s.logger.Error("async event cleanup failed for workspace",
				logging.String("workspace_id", wsID.String()),
				logging.Error(err),
			)
			continue
		}
		totalDeleted += deleted
	}

	if totalDeleted > 0 {
		s.logger.Info("cleaned up old terminal async events",
			logging.Int64("deleted_count", totalDeleted),
			logging.Int("retained_per_workspace", maxCount),
		)
	}

	return totalDeleted, nil
}

// ReapStalePendingOnce sweeps orphaned PENDING events created prior to the stale cutoff,
// transitioning them to FAILED with an RFC 9967 error SET.
func (s *AsyncEventCleanupService) ReapStalePendingOnce(ctx context.Context) (int64, error) {
	if !s.enabled {
		return 0, nil
	}
	if ctx.Err() != nil {
		return 0, ctx.Err()
	}

	cutoff := time.Now().UTC().Add(-s.stalePendingAfter)
	staleEvents, err := s.repo.FindStalePendingEvents(ctx, cutoff, 1000)
	if err != nil {
		s.logger.Error("failed to query stale pending async events", logging.Error(err))
		return 0, err
	}

	var reapedCount int64
	for _, event := range staleEvents {
		select {
		case <-ctx.Done():
			return reapedCount, ctx.Err()
		default:
		}

		errorSet := BuildStalePendingErrorSET(event, s.baseURL)
		completedAt := time.Now().UTC()

		transitioned, err := s.repo.TransitionPendingToFailed(ctx, event.TxnID, errorSet, completedAt)
		if err != nil {
			s.logger.Error("failed to reap stale pending async event",
				logging.String("txn_id", event.TxnID.String()),
				logging.Error(err),
			)
			continue
		}

		if transitioned {
			reapedCount++
			s.logger.Warn("reaped orphaned PENDING async event",
				logging.String("txn_id", event.TxnID.String()),
				logging.String("operation", event.Operation),
				logging.String("resource_type", event.ResourceType),
			)
		}
	}

	if reapedCount > 0 {
		s.logger.Info("reaped stale PENDING async events",
			logging.Int64("reaped_count", reapedCount),
			logging.Duration("stale_after", s.stalePendingAfter),
		)
	}

	return reapedCount, nil
}

// BuildStalePendingErrorSET constructs an RFC 9967 Security Event Token payload for a reaped pending event.
func BuildStalePendingErrorSET(event *model.ScimAsyncEvent, baseOrigin ...string) string {
	statusStr := "500"
	upperMethod := strings.ToUpper(event.Operation)
	if upperMethod == "" {
		upperMethod = "POST"
	}

	errResp := map[string]any{
		"schemas": []string{"urn:ietf:params:scim:api:messages:2.0:Error"},
		"status":  statusStr,
		"detail":  StalePendingTimeoutDetail,
	}

	asyncRespPayload := map[string]any{
		"status":   statusStr,
		"method":   upperMethod,
		"response": errResp,
	}

	origin := "http://localhost:8080"
	if len(baseOrigin) > 0 && strings.TrimSpace(baseOrigin[0]) != "" {
		origin = strings.TrimRight(strings.TrimSpace(baseOrigin[0]), "/")
	}

	var baseURL string
	if strings.Contains(origin, "/ws/") || strings.HasSuffix(origin, "/scim/v2") {
		baseURL = origin
	} else if event.WorkspaceID != uuid.Nil {
		baseURL = fmt.Sprintf("%s/ws/%s/scim/v2", origin, event.WorkspaceID.String())
	} else {
		baseURL = origin + "/scim/v2"
	}

	payload := map[string]any{
		"iss": baseURL,
		"iat": time.Now().UTC().Unix(),
		"jti": uuid.New().String(),
		"txn": event.TxnID.String(),
		"events": map[string]any{
			"urn:ietf:params:scim:event:misc:asyncresp": asyncRespPayload,
		},
	}

	if event.ResourceID != nil && *event.ResourceID != uuid.Nil {
		plural := "Users"
		if strings.EqualFold(event.ResourceType, "group") {
			plural = "Groups"
		}
		resourceURI := baseURL + "/" + plural + "/" + event.ResourceID.String()
		asyncRespPayload["location"] = resourceURI
		payload["sub_id"] = map[string]any{
			"format": "uri",
			"uri":    resourceURI,
		}
	}

	bytes, err := json.Marshal(payload)
	if err != nil {
		return fmt.Sprintf(`{"iss":%q,"iat":%d,"jti":%q,"txn":%q,"events":{"urn:ietf:params:scim:event:misc:asyncresp":{"status":"500","method":%q,"response":{"schemas":["urn:ietf:params:scim:api:messages:2.0:Error"],"status":"500","detail":%q}}}}`,
			baseURL, time.Now().UTC().Unix(), uuid.New().String(), event.TxnID.String(), upperMethod, StalePendingTimeoutDetail)
	}
	return string(bytes)
}
