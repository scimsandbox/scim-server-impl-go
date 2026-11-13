package httpapi

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/scimsandbox/scim-server-impl-go/internal/logging"
	"github.com/scimsandbox/scim-server-impl-go/internal/messages"
)

type stubLimiter struct {
	allow func() bool
	wait  func(context.Context) error
}

func (s stubLimiter) Allow() bool {
	if s.allow != nil {
		return s.allow()
	}
	return false
}

func (s stubLimiter) Wait(ctx context.Context) error {
	if s.wait != nil {
		return s.wait(ctx)
	}
	return nil
}

func TestStatusCapture_DefaultsToOK(t *testing.T) {
	t.Parallel()

	sc := &statusCapture{statusCode: http.StatusOK}

	if sc.statusCode != http.StatusOK {
		t.Fatalf("statusCapture.statusCode = %d, want %d", sc.statusCode, http.StatusOK)
	}
}

func TestStatusCapture_RecordsWrittenCode(t *testing.T) {
	t.Parallel()

	rw := httptest.NewRecorder()
	sc := &statusCapture{ResponseWriter: rw, statusCode: http.StatusOK}

	sc.WriteHeader(http.StatusCreated)

	if sc.statusCode != http.StatusCreated {
		t.Fatalf("statusCapture.statusCode = %d, want %d", sc.statusCode, http.StatusCreated)
	}
	if rw.Code != http.StatusCreated {
		t.Fatalf("underlying ResponseWriter.Code = %d, want %d", rw.Code, http.StatusCreated)
	}
}

func TestResolveRateLimitWaitTimeout_DefaultsToFailFastAndCapsMaxWait(t *testing.T) {
	t.Parallel()

	if got := resolveRateLimitWaitTimeout(0); got != 0 {
		t.Fatalf("resolveRateLimitWaitTimeout(0) = %v, want 0", got)
	}

	if got := resolveRateLimitWaitTimeout(2 * time.Second); got != 2*time.Second {
		t.Fatalf("resolveRateLimitWaitTimeout(2s) = %v, want 2s", got)
	}

	if got := resolveRateLimitWaitTimeout(60 * time.Second); got != maxRateLimitWaitTimeout {
		t.Fatalf("resolveRateLimitWaitTimeout(60s) = %v, want %v", got, maxRateLimitWaitTimeout)
	}
}

func TestRequestLoggingMiddleware_LogsRequestDetails(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	logger := logging.NewLogger(logging.Config{Writer: &buf, Level: logging.InfoLevel})
	localizer := messages.New(messages.Config{})

	handler := requestLoggingMiddleware(logger, localizer, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusAccepted)
	}))

	req := httptest.NewRequest(http.MethodPost, "/scim/v2/Users", nil)
	rw := httptest.NewRecorder()
	handler.ServeHTTP(rw, req)
	_ = logger.Flush()

	logged := buf.String()
	if !strings.Contains(logged, "POST") {
		t.Errorf("log does not contain method POST: %s", logged)
	}
	if !strings.Contains(logged, "/scim/v2/Users") {
		t.Errorf("log does not contain path /scim/v2/Users: %s", logged)
	}
	if !strings.Contains(logged, "202") {
		t.Errorf("log does not contain status 202: %s", logged)
	}
}

func TestRequestLoggingMiddleware_DefaultsToOKStatus(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	logger := logging.NewLogger(logging.Config{Writer: &buf, Level: logging.InfoLevel})
	localizer := messages.New(messages.Config{})

	handler := requestLoggingMiddleware(logger, localizer, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("ok"))
	}))

	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	rw := httptest.NewRecorder()
	handler.ServeHTTP(rw, req)
	_ = logger.Flush()

	logged := buf.String()
	if !strings.Contains(logged, "200") {
		t.Errorf("log does not contain status 200: %s", logged)
	}
}

func TestThrottlingMiddleware_WaitsForPermitBeforeCallingNext(t *testing.T) {
	release := make(chan struct{})
	t.Cleanup(func() {
		select {
		case <-release:
		default:
			close(release)
		}
	})

	handlerStarted := make(chan struct{}, 1)
	handler := throttlingMiddleware(stubLimiter{wait: func(ctx context.Context) error {
		<-release
		return nil
	}}, time.Second, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handlerStarted <- struct{}{}
		w.WriteHeader(http.StatusNoContent)
	}))

	req := httptest.NewRequest(http.MethodGet, "/scim/v2/Users", nil)
	rw := httptest.NewRecorder()
	done := make(chan struct{})

	go func() {
		handler.ServeHTTP(rw, req)
		close(done)
	}()

	select {
	case <-handlerStarted:
		t.Fatal("handler was called before a permit was released")
	case <-time.After(50 * time.Millisecond):
	}

	close(release)

	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("handler did not finish after a permit was released")
	}

	if rw.Code != http.StatusNoContent {
		t.Fatalf("response status = %d, want %d", rw.Code, http.StatusNoContent)
	}
}

func TestThrottlingMiddleware_ReturnsScimTooManyRequestsWhenPermitUnavailable(t *testing.T) {
	t.Parallel()

	calledNext := false
	handler := throttlingMiddleware(stubLimiter{wait: func(ctx context.Context) error {
		<-ctx.Done()
		return ctx.Err()
	}}, 10*time.Millisecond, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calledNext = true
	}))

	req := httptest.NewRequest(http.MethodGet, "/scim/v2/Users", nil)
	rw := httptest.NewRecorder()
	handler.ServeHTTP(rw, req)

	if calledNext {
		t.Fatal("next handler was called despite limiter timeout")
	}
	if rw.Code != http.StatusTooManyRequests {
		t.Fatalf("response status = %d, want %d", rw.Code, http.StatusTooManyRequests)
	}
	if got := rw.Header().Get("Retry-After"); got != "1" {
		t.Fatalf("Retry-After = %q, want %q", got, "1")
	}
	if got := rw.Header().Get("Content-Type"); got != "application/scim+json" {
		t.Fatalf("Content-Type = %q, want %q", got, "application/scim+json")
	}

	var body map[string]any
	if err := json.Unmarshal(rw.Body.Bytes(), &body); err != nil {
		t.Fatalf("response body is not valid JSON: %v", err)
	}
	if body["status"] != "429" {
		t.Fatalf("body status = %v, want %q", body["status"], "429")
	}
	if body["scimType"] != rateLimitScimType {
		t.Fatalf("body scimType = %v, want %q", body["scimType"], rateLimitScimType)
	}
	if body["detail"] != rateLimitCapacityDetail {
		t.Fatalf("body detail = %v, want %q", body["detail"], rateLimitCapacityDetail)
	}
	schemas, ok := body["schemas"].([]any)
	if !ok || len(schemas) != 1 || schemas[0] != "urn:ietf:params:scim:api:messages:2.0:Error" {
		t.Fatalf("body schemas = %v, want SCIM error schema", body["schemas"])
	}
	if strings.Contains(rw.Body.String(), "Too Many Requests") {
		t.Fatal("response body should use SCIM error payload, not plain http.Error output")
	}
}

func TestThrottlingMiddleware_CanceledRequestDoesNotWriteCapacityError(t *testing.T) {
	t.Parallel()

	calledNext := false
	handler := throttlingMiddleware(stubLimiter{wait: func(ctx context.Context) error {
		<-ctx.Done()
		return ctx.Err()
	}}, 10*time.Millisecond, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calledNext = true
	}))

	ctx, cancel := context.WithCancel(context.Background())
	req := httptest.NewRequest(http.MethodGet, "/scim/v2/Users", nil).WithContext(ctx)
	cancel()
	rw := httptest.NewRecorder()
	handler.ServeHTTP(rw, req)

	if calledNext {
		t.Fatal("next handler was called despite canceled request")
	}
	if rw.Body.Len() != 0 {
		t.Fatalf("response body = %q, want empty body for canceled request", rw.Body.String())
	}
	if rw.Header().Get("Retry-After") != "" {
		t.Fatalf("Retry-After = %q, want empty", rw.Header().Get("Retry-After"))
	}
}

func TestNew_WithRateLimit_DelaysSubsequentRequests(t *testing.T) {
	var buf bytes.Buffer
	logger := logging.NewLogger(logging.Config{Writer: &buf, Level: logging.InfoLevel})
	localizer := messages.New(messages.Config{})

	handler := New(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}), Config{
		Logger:    logger,
		Localizer: localizer,
		RateLimit: RateLimitConfig{Enabled: true, RequestsPerSecond: 5, Burst: 1, WaitTimeout: time.Second},
	})

	handler.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/scim/v2/Users", nil))

	start := time.Now()
	rw := httptest.NewRecorder()
	handler.ServeHTTP(rw, httptest.NewRequest(http.MethodGet, "/scim/v2/Users", nil))
	duration := time.Since(start)

	if rw.Code != http.StatusNoContent {
		t.Fatalf("response status = %d, want %d", rw.Code, http.StatusNoContent)
	}
	if duration < 150*time.Millisecond {
		t.Fatalf("second request completed in %v, want at least 150ms of throttling", duration)
	}
}

func TestNew_ReturnsHandlerWithLogging(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	logger := logging.NewLogger(logging.Config{Writer: &buf, Level: logging.InfoLevel})
	localizer := messages.New(messages.Config{})

	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})

	handler := New(inner, Config{Logger: logger, Localizer: localizer})

	req := httptest.NewRequest(http.MethodDelete, "/scim/v2/Users/123", nil)
	rw := httptest.NewRecorder()
	handler.ServeHTTP(rw, req)
	_ = logger.Flush()

	logged := buf.String()
	if !strings.Contains(logged, "DELETE") {
		t.Errorf("log does not contain method DELETE: %s", logged)
	}
	if !strings.Contains(logged, "204") {
		t.Errorf("log does not contain status 204: %s", logged)
	}
}

func TestNew_RecordsMetricsForThrottledRequests(t *testing.T) {
	var buf bytes.Buffer
	logger := logging.NewLogger(logging.Config{Writer: &buf, Level: logging.InfoLevel})
	localizer := messages.New(messages.Config{})

	handler := New(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}), Config{
		Logger:    logger,
		Localizer: localizer,
		RateLimit: RateLimitConfig{Enabled: true, RequestsPerSecond: 0.1, WaitTimeout: time.Millisecond},
	})

	path := "/ws/123e4567-e89b-12d3-a456-426614174000/scim/v2/Users"
	before := metricValueWithLabels(t, "scim_go_operation_requests_total", map[string]string{
		"operation":   "listUsers",
		"http_status": "429",
	})
	authBefore := metricValueWithLabels(t, "scim_go_operation_authentication_total", map[string]string{"state": "unknown"})
	throttledBefore := metricValueWithLabels(t, "scim_go_operation_throttled_total", map[string]string{"state": "yes"})

	handler.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, path, nil))
	rw := httptest.NewRecorder()
	handler.ServeHTTP(rw, httptest.NewRequest(http.MethodGet, path, nil))

	if rw.Code != http.StatusTooManyRequests {
		t.Fatalf("response status = %d, want %d", rw.Code, http.StatusTooManyRequests)
	}

	after := metricValueWithLabels(t, "scim_go_operation_requests_total", map[string]string{
		"operation":   "listUsers",
		"http_status": "429",
	})
	if after-before != 1 {
		t.Fatalf("counter delta = %v, want 1", after-before)
	}
	if after := metricValueWithLabels(t, "scim_go_operation_authentication_total", map[string]string{"state": "unknown"}); after-authBefore != 2 {
		t.Fatalf("authentication counter delta = %v, want 2", after-authBefore)
	}
	if after := metricValueWithLabels(t, "scim_go_operation_throttled_total", map[string]string{"state": "yes"}); after-throttledBefore != 1 {
		t.Fatalf("throttled counter delta = %v, want 1", after-throttledBefore)
	}
}

func TestThrottlingMiddleware_FailFast429BurstAndManagementBypass(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	logger := logging.NewLogger(logging.Config{Writer: &buf, Level: logging.InfoLevel})
	localizer := messages.New(messages.Config{})

	handler := New(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}), Config{
		Logger:    logger,
		Localizer: localizer,
		RateLimit: RateLimitConfig{Enabled: true, RequestsPerSecond: 1, Burst: 3, WaitTimeout: 0},
	})

	// First 3 requests within burst=3 succeed immediately.
	for i := 0; i < 3; i++ {
		rw := httptest.NewRecorder()
		handler.ServeHTTP(rw, httptest.NewRequest(http.MethodGet, "/ws/123e4567-e89b-12d3-a456-426614174000/scim/v2/Users", nil))
		if rw.Code != http.StatusOK {
			t.Fatalf("burst request %d status = %d, want 200", i+1, rw.Code)
		}
	}

	// 4th request fails fast (WaitTimeout=0) with 429 SCIM Error and Retry-After: 1 without parking.
	start := time.Now()
	rw := httptest.NewRecorder()
	handler.ServeHTTP(rw, httptest.NewRequest(http.MethodGet, "/ws/123e4567-e89b-12d3-a456-426614174000/scim/v2/Users", nil))
	if elapsed := time.Since(start); elapsed > 100*time.Millisecond {
		t.Fatalf("fail-fast 429 took %v, expected immediate response", elapsed)
	}
	if rw.Code != http.StatusTooManyRequests {
		t.Fatalf("4th request status = %d, want 429", rw.Code)
	}
	if got := rw.Header().Get("Retry-After"); got != "1" {
		t.Fatalf("Retry-After = %q, want 1", got)
	}

	// Management endpoints (/actuator/health and /metrics) are never throttled even when bucket is exhausted.
	for _, mgmtPath := range []string{"/actuator/health", "/actuator/health/readiness", "/metrics"} {
		mgmtRec := httptest.NewRecorder()
		handler.ServeHTTP(mgmtRec, httptest.NewRequest(http.MethodGet, mgmtPath, nil))
		if mgmtRec.Code != http.StatusOK {
			t.Fatalf("management path %s status = %d, want 200", mgmtPath, mgmtRec.Code)
		}
	}
}

func metricValueWithLabels(t *testing.T, metricName string, labels map[string]string) float64 {
	t.Helper()

	metricFamilies, err := prometheus.DefaultGatherer.Gather()
	if err != nil {
		t.Fatalf("Gather() error = %v", err)
	}

	for _, family := range metricFamilies {
		if family.GetName() != metricName {
			continue
		}

		for _, metric := range family.GetMetric() {
			if len(metric.GetLabel()) != len(labels) {
				continue
			}

			matches := true
			for _, label := range metric.GetLabel() {
				if labels[label.GetName()] != label.GetValue() {
					matches = false
					break
				}
			}
			if matches {
				if metric.Counter != nil {
					return metric.Counter.GetValue()
				}
				if metric.Histogram != nil {
					return float64(metric.Histogram.GetSampleCount())
				}
				if metric.Summary != nil {
					return float64(metric.Summary.GetSampleCount())
				}
			}
		}
	}

	return 0
}
