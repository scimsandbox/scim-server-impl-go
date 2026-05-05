package middleware

import (
	"context"
	"net/http"
)

type scimMetricsStateKey struct{}

type requestMetricsState struct {
	Authentication string
	Throttled      string
	WorkspaceID    string
	UserEmail      string
}

const (
	AuthenticationOK      = "ok"
	AuthenticationFailed  = "failed"
	AuthenticationUnknown = "unknown"

	ThrottledYes = "yes"
	ThrottledNo  = "no"
)

func withRequestMetricsState(r *http.Request) (*http.Request, *requestMetricsState) {
	if state := requestMetricsStateFromContext(r.Context()); state != nil {
		return r, state
	}

	state := &requestMetricsState{
		Authentication: AuthenticationUnknown,
		Throttled:      ThrottledNo,
	}
	ctx := context.WithValue(r.Context(), scimMetricsStateKey{}, state)
	return r.WithContext(ctx), state
}

func requestMetricsStateFromContext(ctx context.Context) *requestMetricsState {
	state, _ := ctx.Value(scimMetricsStateKey{}).(*requestMetricsState)
	return state
}

func MarkAuthentication(r *http.Request, outcome string) {
	if state := requestMetricsStateFromContext(r.Context()); state != nil {
		state.Authentication = outcome
	}
}

func MarkThrottled(r *http.Request, throttled string) {
	if state := requestMetricsStateFromContext(r.Context()); state != nil {
		state.Throttled = throttled
	}
}

func MarkWorkspaceID(r *http.Request, workspaceID string) {
	if state := requestMetricsStateFromContext(r.Context()); state != nil && workspaceID != "" {
		state.WorkspaceID = workspaceID
	}
}

func MarkUserEmail(r *http.Request, userEmail string) {
	if state := requestMetricsStateFromContext(r.Context()); state != nil && userEmail != "" {
		state.UserEmail = userEmail
	}
}
