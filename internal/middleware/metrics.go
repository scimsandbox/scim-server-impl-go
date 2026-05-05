package middleware

import (
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var (
	scimOpCounter = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "scim_go_operation_requests_total",
		Help: "Total SCIM operation requests",
	}, []string{"operation", "resource", "action", "workspace_id", "user_email", "http_status", "outcome", "authentication", "throttled"})

	scimOpDuration = promauto.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "scim_go_operation_duration_seconds",
		Help:    "SCIM operation duration in seconds",
		Buckets: prometheus.DefBuckets,
	}, []string{"operation", "resource", "action", "workspace_id", "user_email", "http_status", "outcome", "authentication", "throttled"})
)

type scimOperation struct {
	Operation string
	Resource  string
	Action    string
}

type statusCapture struct {
	http.ResponseWriter
	statusCode int
}

func (s *statusCapture) WriteHeader(code int) {
	s.statusCode = code
	s.ResponseWriter.WriteHeader(code)
}

// ScimMetrics records Prometheus metrics for SCIM operations.
func ScimMetrics(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		operation := resolveOperation(r)
		if !isScimRequest(r.URL.Path) {
			next.ServeHTTP(w, r)
			return
		}

		r, state := withRequestMetricsState(r)
		rc := &statusCapture{ResponseWriter: w, statusCode: http.StatusOK}
		start := time.Now()
		next.ServeHTTP(rc, r)
		duration := time.Since(start).Seconds()

		httpStatus := strconv.Itoa(rc.statusCode)
		outcome := "success"
		if rc.statusCode >= 400 {
			outcome = "client_error"
		}
		if rc.statusCode >= 500 {
			outcome = "server_error"
		}
		if rc.statusCode >= 300 && rc.statusCode < 400 {
			outcome = "redirection"
		}

		workspaceID := resolveWorkspaceID(r, state)
		userEmail := resolveUserEmail(state)
		authentication := resolveAuthenticationOutcome(state.Authentication, rc.statusCode)
		throttled := resolveThrottledOutcome(state.Throttled, rc)

		scimOpCounter.WithLabelValues(
			operation.Operation,
			operation.Resource,
			operation.Action,
			workspaceID,
			userEmail,
			httpStatus,
			outcome,
			authentication,
			throttled,
		).Inc()
		scimOpDuration.WithLabelValues(
			operation.Operation,
			operation.Resource,
			operation.Action,
			workspaceID,
			userEmail,
			httpStatus,
			outcome,
			authentication,
			throttled,
		).Observe(duration)
	})
}

func resolveAuthenticationOutcome(state string, statusCode int) string {
	switch state {
	case AuthenticationOK, AuthenticationFailed:
		return state
	case "", AuthenticationUnknown:
		if statusCode == http.StatusUnauthorized || statusCode == http.StatusForbidden {
			return AuthenticationFailed
		}
		return AuthenticationUnknown
	default:
		return AuthenticationUnknown
	}
}

func resolveThrottledOutcome(state string, rc *statusCapture) string {
	switch state {
	case ThrottledYes, ThrottledNo:
		return state
	}

	if rc.statusCode == http.StatusServiceUnavailable && rc.Header().Get("Retry-After") != "" {
		return ThrottledYes
	}

	return ThrottledNo
}

func resolveWorkspaceID(r *http.Request, state *requestMetricsState) string {
	if state != nil && state.WorkspaceID != "" {
		return state.WorkspaceID
	}

	workspaceID, ok := r.Context().Value(WorkspaceIDKey).(uuid.UUID)
	if ok {
		return workspaceID.String()
	}

	segments := strings.Split(r.URL.Path, "/")
	if len(segments) <= 2 || segments[1] != "ws" {
		return "unknown"
	}

	parsedWorkspaceID, err := uuid.Parse(segments[2])
	if err != nil {
		return "invalid"
	}

	return parsedWorkspaceID.String()
}

func resolveUserEmail(state *requestMetricsState) string {
	if state != nil && state.UserEmail != "" {
		return state.UserEmail
	}

	return "unknown"
}

func isScimRequest(path string) bool {
	return path != "" && strings.HasPrefix(path, "/ws/") && strings.Contains(path, "/scim/v2")
}

func resolveOperation(r *http.Request) scimOperation {
	path := r.URL.Path
	// Find the SCIM path segment after /scim/v2/
	idx := strings.Index(path, "/scim/v2/")
	if idx < 0 {
		return unknownOperation()
	}
	rest := path[idx+len("/scim/v2/"):]

	// Skip optional compat segment (e.g., "MS/")
	parts := strings.Split(strings.TrimSuffix(rest, "/"), "/")
	if len(parts) == 0 {
		return unknownOperation()
	}

	// Check if first segment is a compat mode identifier
	resIdx := 0
	if parts[0] == "MS" && len(parts) > 1 {
		resIdx = 1
	}

	resourceName := parts[resIdx]
	tracked := map[string]bool{"Users": true, "Groups": true, "Bulk": true}
	if !tracked[resourceName] {
		return unknownOperation()
	}

	resource := strings.ToLower(resourceName)
	hasID := len(parts) > resIdx+1 && parts[resIdx+1] != ""
	action := ""

	switch r.Method {
	case http.MethodPost:
		if resourceName == "Bulk" {
			action = "process"
		} else if strings.HasSuffix(path, "/.search") {
			action = "list"
		} else {
			action = "create"
		}
	case http.MethodGet:
		if hasID {
			action = "get"
		} else {
			action = "list"
		}
	case http.MethodPut:
		action = "replace"
	case http.MethodPatch:
		action = "patch"
	case http.MethodDelete:
		action = "delete"
	default:
		return unknownOperation()
	}

	if action == "" {
		return unknownOperation()
	}

	return scimOperation{
		Operation: resolveOperationName(resource, action),
		Resource:  resource,
		Action:    action,
	}
}

func resolveOperationName(resource, action string) string {
	switch resource {
	case "users":
		switch action {
		case "create":
			return "createUser"
		case "list":
			return "listUsers"
		case "get":
			return "getUser"
		case "replace":
			return "replaceUser"
		case "patch":
			return "patchUser"
		case "delete":
			return "deleteUser"
		}
	case "groups":
		switch action {
		case "create":
			return "createGroup"
		case "list":
			return "listGroups"
		case "get":
			return "getGroup"
		case "replace":
			return "replaceGroup"
		case "patch":
			return "patchGroup"
		case "delete":
			return "deleteGroup"
		}
	case "bulk":
		if action == "process" {
			return "processBulk"
		}
	}

	return "unknown"
}

func unknownOperation() scimOperation {
	return scimOperation{Operation: "unknown", Resource: "unknown", Action: "unknown"}
}
