package httpapi

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"math"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/scimsandbox/scim-server-impl-go/internal/logging"
	"github.com/scimsandbox/scim-server-impl-go/internal/messages"
	"github.com/scimsandbox/scim-server-impl-go/internal/middleware"
	"github.com/scimsandbox/scim-server-impl-go/internal/model"
	"golang.org/x/time/rate"
)

type fakeClock struct {
	mu  sync.Mutex
	now time.Time
}

func newFakeClock(initial time.Time) *fakeClock {
	return &fakeClock{now: initial}
}

func (fc *fakeClock) Now() time.Time {
	fc.mu.Lock()
	defer fc.mu.Unlock()
	return fc.now
}

func (fc *fakeClock) Advance(d time.Duration) {
	fc.mu.Lock()
	fc.now = fc.now.Add(d)
	fc.mu.Unlock()
}

func TestStatusCapture_DefaultsToOK(t *testing.T) {
	t.Parallel()

	sc := &statusCapture{statusCode: http.StatusOK}

	if sc.statusCode != http.StatusOK {
		t.Fatalf("statusCapture.statusCode = %d, want %d", sc.statusCode, http.StatusOK)
	}
}

func TestStatusCapture_RecordsWrittenCodeAndPreservesFlusherAndUnwrap(t *testing.T) {
	t.Parallel()

	rw := httptest.NewRecorder()
	sc := &statusCapture{ResponseWriter: rw, statusCode: http.StatusOK}

	if sc.Unwrap() != rw {
		t.Fatal("statusCapture.Unwrap() did not return underlying ResponseWriter")
	}

	sc.WriteHeader(http.StatusCreated)
	// Second WriteHeader call must not overwrite recorded statusCode.
	sc.WriteHeader(http.StatusInternalServerError)

	if sc.statusCode != http.StatusCreated {
		t.Fatalf("statusCapture.statusCode = %d, want %d", sc.statusCode, http.StatusCreated)
	}
	if rw.Code != http.StatusCreated {
		t.Fatalf("underlying ResponseWriter.Code = %d, want %d", rw.Code, http.StatusCreated)
	}

	scImplicit := &statusCapture{ResponseWriter: rw, statusCode: http.StatusOK}
	if _, err := scImplicit.Write([]byte("hello")); err != nil {
		t.Fatalf("statusCapture.Write() error = %v", err)
	}
	scImplicit.Flush()
	if !rw.Flushed {
		t.Fatal("expected statusCapture.Flush() to flush underlying httptest.ResponseRecorder")
	}
	if scImplicit.statusCode != http.StatusOK {
		t.Fatalf("implicit Write statusCode = %d, want 200", scImplicit.statusCode)
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

func TestPreAuthThrottlingMiddleware_ReturnsScimTooManyRequestsWhenPermitUnavailable(t *testing.T) {
	t.Parallel()

	clock := newFakeClock(time.Date(2026, 11, 14, 12, 0, 0, 0, time.UTC))
	calls := 0
	handler := newPreAuthThrottlingMiddleware(RateLimitConfig{
		Enabled:                true,
		RequestsPerSecond:      0.1,
		Burst:                  1,
		PerIPRequestsPerSecond: 0.1,
		PerIPBurst:             1,
		WaitTimeout:            10 * time.Millisecond,
	}, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		w.WriteHeader(http.StatusNoContent)
	}), clock.Now)

	firstReq := httptest.NewRequest(http.MethodGet, "/scim/v2/Users", nil)
	firstReq.RemoteAddr = "198.51.100.10:1000"
	firstRec := httptest.NewRecorder()
	handler.ServeHTTP(firstRec, firstReq)
	if firstRec.Code != http.StatusNoContent {
		t.Fatalf("first request status = %d, want 204", firstRec.Code)
	}

	// Second request needs 10s delay (> 10ms WaitTimeout), so ReserveN cancels immediately and returns 429 SCIM error.
	req := httptest.NewRequest(http.MethodGet, "/scim/v2/Users", nil)
	req.RemoteAddr = "198.51.100.10:1001"
	rw := httptest.NewRecorder()
	handler.ServeHTTP(rw, req)

	if calls != 1 {
		t.Fatalf("next handler calls = %d, want 1", calls)
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

func TestPreAuthThrottlingMiddleware_CanceledRequestAndCanceledDuringWaitDoNotWriteError(t *testing.T) {
	t.Parallel()

	clock := newFakeClock(time.Date(2026, 11, 14, 12, 0, 0, 0, time.UTC))
	calledNext := atomic.Bool{}
	enteredWait := make(chan struct{})
	var notifyOnce sync.Once
	handler := newPreAuthThrottlingMiddlewareWithHooks(RateLimitConfig{
		Enabled:                true,
		RequestsPerSecond:      0.25, // 4s refill delay (<= 5s WaitTimeout)
		Burst:                  1,
		PerIPRequestsPerSecond: 0.25,
		PerIPBurst:             1,
		WaitTimeout:            5 * time.Second,
	}, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calledNext.Store(true)
		w.WriteHeader(http.StatusOK)
	}), clock.Now, func() {
		notifyOnce.Do(func() { close(enteredWait) })
	})

	// 1. Already-canceled request does not consume tokens or write 429.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	canceledReq := httptest.NewRequest(http.MethodGet, "/scim/v2/Users", nil).WithContext(ctx)
	canceledReq.RemoteAddr = "198.51.100.20:1234"
	rw := httptest.NewRecorder()
	handler.ServeHTTP(rw, canceledReq)

	if calledNext.Load() {
		t.Fatal("next handler was called despite pre-canceled request")
	}
	if rw.Body.Len() != 0 || rw.Header().Get("Retry-After") != "" {
		t.Fatalf("expected empty response for pre-canceled request, got body=%q retry-after=%q", rw.Body.String(), rw.Header().Get("Retry-After"))
	}

	// Consume the 1 burst token with a valid request.
	okReq := httptest.NewRequest(http.MethodGet, "/scim/v2/Users", nil)
	okReq.RemoteAddr = "198.51.100.20:1234"
	okRec := httptest.NewRecorder()
	handler.ServeHTTP(okRec, okReq)
	if okRec.Code != http.StatusOK {
		t.Fatalf("burst request status = %d, want 200", okRec.Code)
	}
	calledNext.Store(false)

	// Also test pre-canceled Bearer+workspace request path.
	wsCanceledReq := httptest.NewRequest(http.MethodGet, "/ws/"+uuid.NewString()+"/scim/v2/Users", nil).WithContext(ctx)
	wsCanceledReq.RemoteAddr = "198.51.100.99:1234"
	wsCanceledReq.Header.Set("Authorization", "Bearer some-token")
	wsCanceledRec := httptest.NewRecorder()
	handler.ServeHTTP(wsCanceledRec, wsCanceledReq)
	if wsCanceledRec.Body.Len() != 0 {
		t.Fatalf("expected empty response for pre-canceled Bearer request, got %q", wsCanceledRec.Body.String())
	}

	// 2. Request that enters timer wait (maxDelay = 4s <= 5s WaitTimeout) and is canceled mid-wait
	// must CancelAt its reservations and NOT write 429 — synchronized deterministically via enteredWait.
	waitCtx, waitCancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	waitRec := httptest.NewRecorder()
	go func() {
		req := httptest.NewRequest(http.MethodGet, "/scim/v2/Users", nil).WithContext(waitCtx)
		req.RemoteAddr = "198.51.100.20:1234"
		handler.ServeHTTP(waitRec, req)
		close(done)
	}()

	<-enteredWait
	clock.Advance(250 * time.Millisecond)
	waitCancel()
	<-done

	if calledNext.Load() {
		t.Fatal("next handler was called despite request cancellation during wait")
	}
	if waitRec.Body.Len() != 0 || waitRec.Header().Get("Retry-After") != "" {
		t.Fatalf("expected empty response when client cancels during wait, got body=%q", waitRec.Body.String())
	}

	// Advance fake clock by the remaining 3.75s (total 4s, NOT 8s!): proving the canceled waiter refunded its reservation!
	clock.Advance(3750 * time.Millisecond)
	afterCancelReq := httptest.NewRequest(http.MethodGet, "/scim/v2/Users", nil)
	afterCancelReq.RemoteAddr = "198.51.100.20:1234"
	afterCancelRec := httptest.NewRecorder()
	handler.ServeHTTP(afterCancelRec, afterCancelReq)
	if afterCancelRec.Code != http.StatusOK {
		t.Fatalf("request after canceled waiter status = %d, want 200", afterCancelRec.Code)
	}
}

func TestAcquireLimiters_MidWaitCancelRestoresZeroDelayPeerToken(t *testing.T) {
	t.Parallel()

	clock := newFakeClock(time.Date(2026, 11, 14, 12, 30, 0, 0, time.UTC))
	enteredWait := make(chan struct{})
	var notifyOnce sync.Once

	// Per-IP limiter has burst=1, rps=0.01 (takes 100s to refill if leaked).
	// Global limiter has burst=1, rps=0.25 (4s refill delay <= 5s WaitTimeout).
	mw := newPreAuthThrottlingMiddlewareWithHooks(RateLimitConfig{
		Enabled:                true,
		RequestsPerSecond:      0.25,
		Burst:                  1,
		PerIPRequestsPerSecond: 0.01,
		PerIPBurst:             1,
		WaitTimeout:            5 * time.Second,
	}, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}), clock.Now, func() {
		notifyOnce.Do(func() { close(enteredWait) })
	})

	// Drain globalLimiter's 1 burst token using IP B so global delay becomes 4s while IP A still has delay=0.
	drainReq := httptest.NewRequest(http.MethodGet, "/scim/v2/Users", nil)
	drainReq.RemoteAddr = "203.0.113.2:1000"
	drainRec := httptest.NewRecorder()
	mw.ServeHTTP(drainRec, drainReq)
	if drainRec.Code != http.StatusOK {
		t.Fatalf("drain global request status = %d, want 200", drainRec.Code)
	}

	// Start request from IP A: IP A's reservation has delay=0 (actAt == t0), global has delay=4s (actAt == t0+4s).
	waitCtx, waitCancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		reqA := httptest.NewRequest(http.MethodGet, "/scim/v2/Users", nil).WithContext(waitCtx)
		reqA.RemoteAddr = "198.51.100.1:2000"
		mw.ServeHTTP(httptest.NewRecorder(), reqA)
		close(done)
	}()

	<-enteredWait
	// Advance fakeClock by 250ms so t1 = t0 + 250ms -> actAt0.Before(t1) is true!
	clock.Advance(250 * time.Millisecond)
	waitCancel()
	<-done

	// Advance fakeClock by 4s so globalLimiter refills 1 token (4.25s * 0.25 >= 1),
	// whereas IP A's 0.01 rps limiter would only refill 0.0425 tokens (95.75s delay > 5s WaitTimeout -> 429) if leaked!
	clock.Advance(4 * time.Second)

	verifyReq := httptest.NewRequest(http.MethodGet, "/scim/v2/Users", nil)
	verifyReq.RemoteAddr = "198.51.100.1:2001"
	verifyRec := httptest.NewRecorder()
	mw.ServeHTTP(verifyRec, verifyReq)
	if verifyRec.Code != http.StatusOK {
		t.Fatalf("IP A request after mid-wait cancel status = %d, want 200 (zero-delay peer token must be refunded)", verifyRec.Code)
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

func TestThrottlingMiddleware_PerIPIsolationAndNoManagementBypass(t *testing.T) {
	t.Parallel()

	clock := newFakeClock(time.Date(2026, 11, 14, 15, 0, 0, 0, time.UTC))
	var buf bytes.Buffer
	logger := logging.NewLogger(logging.Config{Writer: &buf, Level: logging.InfoLevel})
	localizer := messages.New(messages.Config{})

	handler := newWithClock(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}), Config{
		Logger:    logger,
		Localizer: localizer,
		RateLimit: RateLimitConfig{
			Enabled:                true,
			RequestsPerSecond:      100,
			Burst:                  50,
			PerIPRequestsPerSecond: 1,
			PerIPBurst:             3,
			WaitTimeout:            0,
		},
	}, clock.Now)

	wsAPaths := []string{
		"/ws/123e4567-e89b-12d3-a456-426614174000/scim/v2/Users",
		"/ws/123E4567-E89B-12D3-A456-426614174000/scim/v2/Users",
		"/ws/123e4567-e89b-12d3-a456-426614174000/scim/v2/Groups",
	}
	for i, p := range wsAPaths {
		req := httptest.NewRequest(http.MethodGet, p, nil)
		req.RemoteAddr = "198.51.100.1:4000"
		rw := httptest.NewRecorder()
		handler.ServeHTTP(rw, req)
		if rw.Code != http.StatusOK {
			t.Fatalf("client A burst request %d status = %d, want 200", i+1, rw.Code)
		}
	}

	// 4th unauthenticated request from Client A fails deterministically (clock frozen, WaitTimeout=0)
	// with 429 SCIM Error and Retry-After: 1, even if targeting a different workspace UUID.
	rw := httptest.NewRecorder()
	fourthReq := httptest.NewRequest(http.MethodGet, "/ws/999e4567-e89b-12d3-a456-426614174999/scim/v2/Users", nil)
	fourthReq.RemoteAddr = "198.51.100.1:5555"
	handler.ServeHTTP(rw, fourthReq)
	if rw.Code != http.StatusTooManyRequests {
		t.Fatalf("client A 4th request status = %d, want 429", rw.Code)
	}
	if got := rw.Header().Get("Retry-After"); got != "1" {
		t.Fatalf("Retry-After = %q, want 1", got)
	}

	// Client B has its own independent IP bucket and still gets 200 OK while Client A is throttled.
	wsBPath := "/ws/223e4567-e89b-12d3-a456-426614174001/scim/v2/Users"
	for i := 0; i < 3; i++ {
		req := httptest.NewRequest(http.MethodGet, wsBPath, nil)
		req.RemoteAddr = "198.51.100.2:4000"
		wsBRec := httptest.NewRecorder()
		handler.ServeHTTP(wsBRec, req)
		if wsBRec.Code != http.StatusOK {
			t.Fatalf("client B request %d status = %d, want 200", i+1, wsBRec.Code)
		}
	}

	// /actuator/* and /metrics on the API router do NOT bypass rate limiting; they use client IP.
	nonWsPaths := []string{"/actuator/health", "/actuator/health/readiness", "/metrics"}
	for i, p := range nonWsPaths {
		req := httptest.NewRequest(http.MethodGet, p, nil)
		req.RemoteAddr = "192.0.2.10:4000"
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("non-workspace request %d (%s) status = %d, want 200", i+1, p, rec.Code)
		}
	}
	throttledMgmtReq := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	throttledMgmtReq.RemoteAddr = "192.0.2.10:5000" // Same client IP, different ephemeral port
	throttledMgmtRec := httptest.NewRecorder()
	handler.ServeHTTP(throttledMgmtRec, throttledMgmtReq)
	if throttledMgmtRec.Code != http.StatusTooManyRequests {
		t.Fatalf("4th non-workspace request (/metrics) status = %d, want 429", throttledMgmtRec.Code)
	}

	// Another client IP on a non-workspace or invalid-UUID path is isolated and still succeeds.
	otherIPReq := httptest.NewRequest(http.MethodGet, "/ws/not-a-valid-uuid/scim/v2/Users", nil)
	otherIPReq.RemoteAddr = "198.51.100.25:9999"
	otherIPRec := httptest.NewRecorder()
	handler.ServeHTTP(otherIPRec, otherIPReq)
	if otherIPRec.Code != http.StatusOK {
		t.Fatalf("other client IP status = %d, want 200", otherIPRec.Code)
	}

	// Advancing fake clock by 1s refills exactly 1 token for Client A.
	clock.Advance(time.Second)
	refilledRec := httptest.NewRecorder()
	handler.ServeHTTP(refilledRec, fourthReq)
	if refilledRec.Code != http.StatusOK {
		t.Fatalf("client A request after 1s clock advance status = %d, want 200", refilledRec.Code)
	}
}

func TestKeyedLimiterStore_KeyExtractionTTLEvictionAndCapacityCap(t *testing.T) {
	t.Parallel()

	if got := extractClientIPKey(nil, nil, nil); got != "global" {
		t.Fatalf("extractClientIPKey(nil) = %q, want global", got)
	}

	emptyAddrReq := httptest.NewRequest(http.MethodGet, "/scim/v2/Users", nil)
	emptyAddrReq.RemoteAddr = "   "
	if got := extractClientIPKey(emptyAddrReq, nil, nil); got != "global" {
		t.Fatalf("extractClientIPKey(empty RemoteAddr) = %q, want global", got)
	}

	nonIPAddrReq := httptest.NewRequest(http.MethodGet, "/scim/v2/Users", nil)
	nonIPAddrReq.RemoteAddr = "unix-socket-peer"
	if got := extractClientIPKey(nonIPAddrReq, nil, nil); got != "ip:unix-socket-peer" {
		t.Fatalf("extractClientIPKey(non-IP RemoteAddr) = %q, want ip:unix-socket-peer", got)
	}

	rawAddrReq := httptest.NewRequest(http.MethodGet, "/ws/invalid-ws/scim/v2/Users", nil)
	rawAddrReq.RemoteAddr = "203.0.113.7"
	if got := extractClientIPKey(rawAddrReq, nil, nil); got != "ip:203.0.113.7" {
		t.Fatalf("extractClientIPKey(raw IP) = %q, want ip:203.0.113.7", got)
	}

	ipv6Req := httptest.NewRequest(http.MethodGet, "/scim/v2/Users", nil)
	ipv6Req.RemoteAddr = "[2001:db8:abcd:1234::1]:44321"
	if got := extractClientIPKey(ipv6Req, nil, nil); got != "ip:2001:db8:abcd:1234::/64" {
		t.Fatalf("extractClientIPKey(IPv6) = %q, want ip:2001:db8:abcd:1234::/64", got)
	}

	// Pre-auth IP key extraction NEVER keys by URL workspace UUID.
	wsReq := httptest.NewRequest(http.MethodGet, "/ws/ABCDEF01-2345-6789-ABCD-EF0123456789/scim/v2/Users", nil)
	wsReq.RemoteAddr = "198.51.100.42:1234"
	if got := extractClientIPKey(wsReq, nil, nil); got != "ip:198.51.100.42" {
		t.Fatalf("extractClientIPKey(ws URL) = %q, want ip:198.51.100.42", got)
	}

	// Verify O(1) doubly-linked-list LRU + TTL expiration and hard maxEntries capacity eviction.
	now := time.Date(2026, 11, 13, 12, 0, 0, 0, time.UTC)
	store := newKeyedLimiterStoreWithOptions(1, 1, 3, 5*time.Minute, func() time.Time {
		return now
	})

	lim1 := store.LimiterForKey("ip:10.0.0.1")
	if !lim1.AllowN(now, 1) || lim1.AllowN(now, 1) {
		t.Fatal("expected burst=1 bucket for 10.0.0.1 to allow first call and reject second")
	}
	now = now.Add(10 * time.Second)
	_ = store.LimiterForKey("ip:10.0.0.2")
	now = now.Add(10 * time.Second)
	_ = store.LimiterForKey("ip:10.0.0.3")

	if store.lenEntries() != 3 {
		t.Fatalf("lenEntries() = %d, want 3", store.lenEntries())
	}

	// Touch 10.0.0.1 (MoveToBack) so 10.0.0.2 becomes the oldest (Front) entry.
	now = now.Add(10 * time.Second)
	if got := store.LimiterForKey("ip:10.0.0.1"); got != lim1 {
		t.Fatal("expected existing non-expired limiter for 10.0.0.1")
	}

	// Inserting 10.0.0.4 at capacity=3 must evict LRU front (ip:10.0.0.2) in O(1) and keep size == 3.
	now = now.Add(10 * time.Second)
	_ = store.LimiterForKey("ip:10.0.0.4")
	if store.lenEntries() != 3 {
		t.Fatalf("lenEntries() after capacity eviction = %d, want 3", store.lenEntries())
	}
	if store.hasKey("ip:10.0.0.2") {
		t.Fatal("expected LRU entry ip:10.0.0.2 to be evicted")
	}

	// Advance past TTL for ip:10.0.0.3 (seen at +20s; at +5m25s it is >5m old, while 10.0.0.1 at +30s & 10.0.0.4 at +40s are <5m old).
	now = time.Date(2026, 11, 13, 12, 5, 25, 0, time.UTC)
	_ = store.LimiterForKey("ip:10.0.0.5")
	if store.lenEntries() != 3 {
		t.Fatalf("lenEntries() after expired front eviction = %d, want 3", store.lenEntries())
	}
	if store.hasKey("ip:10.0.0.3") {
		t.Fatal("expected expired entry ip:10.0.0.3 to be popped before active entries")
	}
	if !store.hasKey("ip:10.0.0.1") {
		t.Fatal("expected active entry ip:10.0.0.1 to remain in store")
	}

	bigStore := newKeyedLimiterStoreWithOptions(1, 1, 16, 5*time.Minute, func() time.Time {
		return now
	})
	for i := 1; i <= 6; i++ {
		_ = bigStore.LimiterForKey(fmt.Sprintf("k%d", i))
	}
	oldTarget := bigStore.LimiterForKey("target")
	now = now.Add(6 * time.Minute)
	freshTarget := bigStore.LimiterForKey("target")
	if freshTarget == oldTarget {
		t.Fatal("expected direct lookup of expired entry beyond maxExpiredEvictPerAccess to allocate a fresh limiter")
	}
}

func TestRateLimit_IPv6Prefix64Masking(t *testing.T) {
	t.Parallel()

	clock := newFakeClock(time.Date(2026, 11, 14, 16, 0, 0, 0, time.UTC))
	mw := newPreAuthThrottlingMiddleware(RateLimitConfig{
		Enabled:                true,
		RequestsPerSecond:      100,
		Burst:                  50,
		PerIPRequestsPerSecond: 1,
		PerIPBurst:             3,
	}, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}), clock.Now)

	// Rotating distinct /128 interface IDs inside 2001:db8:abcd:1234::/64 shares a single bucket (burst=3).
	same64Addrs := []string{
		"[2001:db8:abcd:1234::1]:4000",
		"[2001:db8:abcd:1234:dead:beef:cafe:1]:4001",
		"[2001:db8:abcd:1234:ffff:ffff:ffff:ffff]:4002",
	}
	for i, remote := range same64Addrs {
		req := httptest.NewRequest(http.MethodGet, "/scim/v2/Users", nil)
		req.RemoteAddr = remote
		rec := httptest.NewRecorder()
		mw.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("same /64 request %d (%s) status = %d, want 200", i+1, remote, rec.Code)
		}
	}

	// 4th distinct /128 inside the same /64 must hit 429!
	fourthSame64 := httptest.NewRequest(http.MethodGet, "/scim/v2/Users", nil)
	fourthSame64.RemoteAddr = "[2001:db8:abcd:1234:1111:2222:3333:4444]:4003"
	fourthRec := httptest.NewRecorder()
	mw.ServeHTTP(fourthRec, fourthSame64)
	if fourthRec.Code != http.StatusTooManyRequests {
		t.Fatalf("4th distinct /128 in same /64 status = %d, want 429", fourthRec.Code)
	}

	// A different /64 prefix (2001:db8:abcd:1235::/64) gets an independent bucket and succeeds.
	other64 := httptest.NewRequest(http.MethodGet, "/scim/v2/Users", nil)
	other64.RemoteAddr = "[2001:db8:abcd:1235::1]:4000"
	other64Rec := httptest.NewRecorder()
	mw.ServeHTTP(other64Rec, other64)
	if other64Rec.Code != http.StatusOK {
		t.Fatalf("distinct /64 prefix status = %d, want 200", other64Rec.Code)
	}

	// IPv4-mapped IPv6 unmaps to IPv4 /32 (different IPv4s do NOT share a /64).
	v4Mapped1 := httptest.NewRequest(http.MethodGet, "/scim/v2/Users", nil)
	v4Mapped1.RemoteAddr = "[::ffff:198.51.100.1]:8080"
	if got := extractClientIPKey(v4Mapped1, nil, nil); got != "ip:198.51.100.1" {
		t.Fatalf("IPv4-in-IPv6 key = %q, want ip:198.51.100.1", got)
	}
}

func TestRateLimit_TrustedProxyFailClosedAndCloudflareSeparation(t *testing.T) {
	t.Parallel()

	// 1. Default fail-closed: when both TrustedProxies and TrustedCloudflareProxies are empty,
	// NO forwarding headers are trusted even from loopback, RFC1918, Docker gateway, or link-local peers!
	for _, peer := range []string{
		"127.0.0.1:8080",
		"10.0.0.5:8080",
		"172.18.0.4:3456",
		"192.168.65.1:50000",
		"[::1]:8080",
		"[fe80::1%eth0]:8080",
		"203.0.113.7:9000",
	} {
		r := httptest.NewRequest(http.MethodGet, "/scim/v2/Users", nil)
		r.RemoteAddr = peer
		r.Header.Set("CF-Connecting-IP", "198.51.100.200")
		r.Header.Set("X-Forwarded-For", "198.51.100.201")
		got := extractClientIPKey(r, nil, nil)
		if got == "ip:198.51.100.200" || got == "ip:198.51.100.201" {
			t.Fatalf("fail-closed default trusted forwarding header from peer %s: got %q", peer, got)
		}
	}

	// 2. Behind nginx / K8s ingress (TrustedProxies = 10.0.0.0/8, TrustedCloudflareProxies = empty):
	// Attacker spoofing CF-Connecting-IP MUST be ignored; X-Forwarded-For is walked right-to-left
	// skipping trusted hops (10.0.0.2) to select the rightmost untrusted client IP!
	k8sProxies, err := ParseTrustedProxies("10.0.0.0/8, 192.168.65.1")
	if err != nil {
		t.Fatalf("ParseTrustedProxies error = %v", err)
	}
	spoofCFBehindNginx := httptest.NewRequest(http.MethodGet, "/scim/v2/Users", nil)
	spoofCFBehindNginx.RemoteAddr = "10.0.0.5:8080"
	spoofCFBehindNginx.Header.Set("CF-Connecting-IP", "1.2.3.4")
	spoofCFBehindNginx.Header.Add("X-Forwarded-For", "forged-leftmost, 203.0.113.55")
	spoofCFBehindNginx.Header.Add("X-Forwarded-For", "198.51.100.77, 10.0.0.2")
	if got := extractClientIPKey(spoofCFBehindNginx, k8sProxies, nil); got != "ip:198.51.100.77" {
		t.Fatalf("spoofed CF behind nginx got %q, want rightmost untrusted XFF hop ip:198.51.100.77", got)
	}

	// 3. Multi-hop XFF where ALL hops are trusted proxies falls back to leftmost valid IP.
	allTrustedXFF := httptest.NewRequest(http.MethodGet, "/scim/v2/Users", nil)
	allTrustedXFF.RemoteAddr = "10.0.0.5:8080"
	allTrustedXFF.Header.Set("X-Forwarded-For", "10.1.2.3, 10.0.0.2")
	if got := extractClientIPKey(allTrustedXFF, k8sProxies, nil); got != "ip:10.1.2.3" {
		t.Fatalf("all-trusted XFF got %q, want leftmost valid hop ip:10.1.2.3", got)
	}

	// 4. Malformed rightmost XFF hop falls back safely to peer IP; malformed earlier hop after a trusted hop falls back to last valid trusted hop.
	invalidRightmost := httptest.NewRequest(http.MethodGet, "/scim/v2/Users", nil)
	invalidRightmost.RemoteAddr = "10.0.0.9:8080"
	invalidRightmost.Header.Set("X-Forwarded-For", "1.2.3.4, not-an-ip")
	if got := extractClientIPKey(invalidRightmost, k8sProxies, nil); got != "ip:10.0.0.9" {
		t.Fatalf("invalid rightmost XFF fallback got %q, want ip:10.0.0.9", got)
	}

	invalidEarlier := httptest.NewRequest(http.MethodGet, "/scim/v2/Users", nil)
	invalidEarlier.RemoteAddr = "10.0.0.9:8080"
	invalidEarlier.Header.Set("X-Forwarded-For", "garbage, 10.0.0.2")
	if got := extractClientIPKey(invalidEarlier, k8sProxies, nil); got != "ip:10.0.0.2" {
		t.Fatalf("invalid earlier XFF fallback got %q, want ip:10.0.0.2", got)
	}

	// 5. TrustedCloudflareProxies trusts single valid CF-Connecting-IP (including IPv6 masked to /64),
	// and falls back to X-Forwarded-For when CF-Connecting-IP is absent/ambiguous/invalid.
	cfProxies, err := ParseTrustedProxies("173.245.48.0/20, , ::ffff:192.0.2.5/128, 2400:cb00::1")
	if err != nil {
		t.Fatalf("ParseTrustedProxies(CF) error = %v", err)
	}

	cfReq := httptest.NewRequest(http.MethodGet, "/scim/v2/Users", nil)
	cfReq.RemoteAddr = "173.245.48.10:443"
	cfReq.Header.Set("CF-Connecting-IP", " 2001:db8:1111:2222::abcd ")
	cfReq.Header.Set("X-Forwarded-For", "198.51.100.99")
	if got := extractClientIPKey(cfReq, k8sProxies, cfProxies); got != "ip:2001:db8:1111:2222::/64" {
		t.Fatalf("trusted CF peer with IPv6 CF-Connecting-IP got %q, want ip:2001:db8:1111:2222::/64", got)
	}

	ambigCF := httptest.NewRequest(http.MethodGet, "/scim/v2/Users", nil)
	ambigCF.RemoteAddr = "173.245.48.10:443"
	ambigCF.Header.Add("CF-Connecting-IP", "1.1.1.1")
	ambigCF.Header.Add("CF-Connecting-IP", "2.2.2.2")
	ambigCF.Header.Set("X-Forwarded-For", "203.0.113.44, 173.245.48.11")
	if got := extractClientIPKey(ambigCF, k8sProxies, cfProxies); got != "ip:203.0.113.44" {
		t.Fatalf("ambiguous CF fallback to XFF got %q, want ip:203.0.113.44", got)
	}
}

type countingTokenFinder struct {
	calls atomic.Int64
	find  func(ctx context.Context, tokenHash string) (*model.WorkspaceToken, error)
}

func (c *countingTokenFinder) FindByTokenHashNotRevoked(ctx context.Context, tokenHash string) (*model.WorkspaceToken, error) {
	c.calls.Add(1)
	if c.find != nil {
		return c.find(ctx, tokenHash)
	}
	return nil, nil
}

type staticWorkspaceFinder struct {
	workspaces map[uuid.UUID]*model.Workspace
}

func (s staticWorkspaceFinder) FindByID(_ context.Context, id uuid.UUID) (*model.Workspace, error) {
	if ws, ok := s.workspaces[id]; ok {
		return ws, nil
	}
	return nil, nil
}

func buildThreeTierTestPipelineWithClock(
	rateCfg RateLimitConfig,
	tokenRepo *countingTokenFinder,
	wsRepo staticWorkspaceFinder,
	nowFn func() time.Time,
) http.Handler {
	var buf bytes.Buffer
	logger := logging.NewLogger(logging.Config{Writer: &buf, Level: logging.ErrorLevel})
	localizer := messages.New(messages.Config{})

	r := chi.NewRouter()
	r.Route("/ws/{workspaceId}/scim/v2", func(sr chi.Router) {
		sr.Use(middleware.ExtractWorkspaceID)
		sr.Use(middleware.BearerTokenAuth(tokenRepo, wsRepo))
		sr.Use(newWorkspaceRateLimitMiddlewareWithClock(rateCfg, nowFn))
		sr.Get("/Users", func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusOK)
		})
		sr.Get("/ServiceProviderConfig", func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusOK)
		})
	})

	return newWithClock(r, Config{
		Logger:    logger,
		Localizer: localizer,
		RateLimit: rateCfg,
	}, nowFn)
}

func TestRateLimit_SharedIdPEgressIPMultiTenancyAndSprayProtection(t *testing.T) {
	t.Parallel()

	clock := newFakeClock(time.Date(2026, 11, 14, 17, 0, 0, 0, time.UTC))
	wsA := uuid.New()
	wsB := uuid.New()
	tokenA := "idp-tenant-a-valid-token"
	tokenB := "idp-tenant-b-valid-token"
	hashA := middleware.HashToken(tokenA)
	hashB := middleware.HashToken(tokenB)

	tokenRepo := &countingTokenFinder{
		find: func(_ context.Context, tokenHash string) (*model.WorkspaceToken, error) {
			switch tokenHash {
			case hashA:
				return &model.WorkspaceToken{WorkspaceID: wsA, TokenHash: hashA}, nil
			case hashB:
				return &model.WorkspaceToken{WorkspaceID: wsB, TokenHash: hashB}, nil
			default:
				return nil, nil
			}
		},
	}
	wsRepo := staticWorkspaceFinder{
		workspaces: map[uuid.UUID]*model.Workspace{
			wsA: {ID: wsA},
			wsB: {ID: wsB},
		},
	}

	pipeline := buildThreeTierTestPipelineWithClock(RateLimitConfig{
		Enabled:                       true,
		RequestsPerSecond:             1000,
		Burst:                         400, // Global burst 400
		PerIPRequestsPerSecond:        250,
		PerIPBurst:                    50, // Per-(IP,ws) and unauth-IP burst 50
		PerWorkspaceRequestsPerSecond: 250,
		PerWorkspaceBurst:             50,
		TrustedCloudflareProxies:      "10.0.0.5",
	}, tokenRepo, wsRepo, clock.Now)

	// Scenario 1: Shared IdP egress IP (52.160.1.10) sends 80 requests for Tenant A (burst=50).
	// First 50 succeed (200 OK); requests 51..80 are throttled at 429 in ipws:<idpIP>:ws:<wsA>,
	// WITHOUT draining globalLimiter beyond 50 and WITHOUT draining unauthIPStore!
	// Tenant B arriving from the EXACT SAME shared IdP IP (52.160.1.10) succeeds with 200 OK!
	sharedIdPIP := "52.160.1.10:443"
	for i := 0; i < 80; i++ {
		req := httptest.NewRequest(http.MethodGet, "/ws/"+wsA.String()+"/scim/v2/Users", nil)
		req.RemoteAddr = sharedIdPIP
		req.Header.Set("Authorization", "Bearer "+tokenA)
		rec := httptest.NewRecorder()
		pipeline.ServeHTTP(rec, req)
		if i < 50 && rec.Code != http.StatusOK {
			t.Fatalf("Tenant A request %d status = %d, want 200", i+1, rec.Code)
		}
		if i >= 50 && rec.Code != http.StatusTooManyRequests {
			t.Fatalf("Tenant A overflow request %d status = %d, want 429", i+1, rec.Code)
		}
	}

	for i := 0; i < 50; i++ {
		req := httptest.NewRequest(http.MethodGet, "/ws/"+wsB.String()+"/scim/v2/Users", nil)
		req.RemoteAddr = sharedIdPIP
		req.Header.Set("Authorization", "Bearer "+tokenB)
		rec := httptest.NewRecorder()
		pipeline.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("Tenant B request %d from same shared IdP IP status = %d, want 200", i+1, rec.Code)
		}
	}
	// Request 1 of Tenant A used unauthIPStore and promoted tokenA into verifiedCache;
	// requests 2..51 used verifiedIPWSStore (request 51 hit post-auth PerWorkspaceBurst=50),
	// and requests 52..80 were blocked pre-auth in verifiedIPWSStore without hitting DB!
	if got := tokenRepo.calls.Load(); got != 101 {
		t.Fatalf("tokenRepo calls after Tenant A+B = %d, want 101 (29 of 30 overflow Tenant A requests blocked pre-auth)", got)
	}

	// Scenario 2: Unauthenticated random-UUID spray without Bearer token
	// is capped at perIPBurst (50) pre-auth, with ZERO tokenRepo DB lookups across all 70 requests!
	callsBeforeUnauthSpray := tokenRepo.calls.Load()
	nonBearerHeaders := []string{
		"",
		"Basic dXNlcjpwYXNz",
		"Bearer",
		"bearer lower-prefix",
		"Bearer\ttab-prefix",
	}
	for i := 0; i < 70; i++ {
		req := httptest.NewRequest(http.MethodGet, "/ws/"+uuid.NewString()+"/scim/v2/Users", nil)
		req.RemoteAddr = "203.0.113.50:40000"
		if hdr := nonBearerHeaders[i%len(nonBearerHeaders)]; hdr != "" {
			req.Header.Set("Authorization", hdr)
		}
		rec := httptest.NewRecorder()
		pipeline.ServeHTTP(rec, req)
		if i < 50 && rec.Code != http.StatusUnauthorized {
			t.Fatalf("unauth spray request %d status = %d, want 401", i+1, rec.Code)
		}
		if i >= 50 && rec.Code != http.StatusTooManyRequests {
			t.Fatalf("unauth spray request %d status = %d, want 429", i+1, rec.Code)
		}
	}
	if got := tokenRepo.calls.Load() - callsBeforeUnauthSpray; got != 0 {
		t.Fatalf("unauth spray triggered %d DB lookups, want 0", got)
	}

	// Verify extractBearerToken and extractSCIMWorkspaceUUID edge cases directly.
	if _, ok := extractBearerToken(nil); ok {
		t.Fatal("expected false for nil request")
	}
	for _, badHdr := range []string{"", "Basic abc", "Bearer", "Bearer    ", "bearer lowercase", "Bearer\ttab", "BearerX token"} {
		r := httptest.NewRequest(http.MethodGet, "/ws/"+wsA.String()+"/scim/v2/Users", nil)
		if badHdr != "" {
			r.Header.Set("Authorization", badHdr)
		}
		if _, ok := extractBearerToken(r); ok {
			t.Fatalf("expected extractBearerToken(%q) == false", badHdr)
		}
	}
	for _, badPath := range []string{
		"/scim/v2/Users",
		"/ws//scim/v2/Users",
		"/ws/" + wsA.String(),
		"/ws/" + wsA.String() + "/anything",
		"/ws/" + wsA.String() + "/scim/v20/Users",
		"/ws/not-a-uuid/scim/v2/Users",
		"/ws/" + uuid.Nil.String() + "/scim/v2/Users",
	} {
		if _, ok := extractSCIMWorkspaceUUID(badPath); ok {
			t.Fatalf("expected extractSCIMWorkspaceUUID(%q) == false", badPath)
		}
	}
	upperWS, ok := extractSCIMWorkspaceUUID("/ws/" + strings.ToUpper(wsA.String()) + "/scim/v2")
	if !ok || upperWS != wsA.String() {
		t.Fatalf("extractSCIMWorkspaceUUID uppercase = (%q, %v), want (%q, true)", upperWS, ok, wsA.String())
	}

	// Non-SCIM /ws/<random-uuid>/anything spray with Bearer header also hits unauthIPStore directly (404 for 50, then 429).
	for i := 0; i < 60; i++ {
		req := httptest.NewRequest(http.MethodGet, "/ws/"+uuid.NewString()+"/not-scim", nil)
		req.RemoteAddr = "203.0.113.51:40000"
		req.Header.Set("Authorization", "Bearer anything")
		rec := httptest.NewRecorder()
		pipeline.ServeHTTP(rec, req)
		if i < 50 && rec.Code != http.StatusNotFound {
			t.Fatalf("non-SCIM path spray %d status = %d, want 404", i+1, rec.Code)
		}
		if i >= 50 && rec.Code != http.StatusTooManyRequests {
			t.Fatalf("non-SCIM path spray %d status = %d, want 429", i+1, rec.Code)
		}
	}

	// Scenario 3: Fake-Bearer random-UUID spray (`Authorization: Bearer invalid` + random `/ws/<random-uuid>/scim/v2/Users`):
	// First perIPBurst (50) reserve unauthIPStore up front and return 401; requests 51..75 are rejected pre-auth with 429
	// BEFORE reaching BearerTokenAuth/DB!
	callsBeforeFakeBearerSpray := tokenRepo.calls.Load()
	for i := 0; i < 75; i++ {
		req := httptest.NewRequest(http.MethodGet, "/ws/"+uuid.NewString()+"/scim/v2/Users", nil)
		req.RemoteAddr = "10.0.0.5:50000"
		req.Header.Set("CF-Connecting-IP", "198.51.100.77")
		req.Header.Set("Authorization", "Bearer invalid-spray-token")
		rec := httptest.NewRecorder()
		pipeline.ServeHTTP(rec, req)
		if i < 50 && rec.Code != http.StatusUnauthorized {
			t.Fatalf("fake-Bearer spray request %d status = %d, want 401", i+1, rec.Code)
		}
		if i >= 50 && rec.Code != http.StatusTooManyRequests {
			t.Fatalf("fake-Bearer spray request %d status = %d, want 429 pre-auth", i+1, rec.Code)
		}
	}
	if got := tokenRepo.calls.Load() - callsBeforeFakeBearerSpray; got != 50 {
		t.Fatalf("fake-Bearer spray DB lookups = %d, want exactly 50 (requests 51..75 blocked pre-auth)", got)
	}
}

func TestRateLimit_ConcurrentFakeBearerSprayZeroTOCTOU(t *testing.T) {
	t.Parallel()

	clock := newFakeClock(time.Date(2026, 11, 14, 17, 15, 0, 0, time.UTC))
	const (
		perIPBurst   = 10
		totalWorkers = 200
	)

	var authCalls atomic.Int64
	allAdmittedEntered := make(chan struct{})
	releaseAuth := make(chan struct{})

	tokenRepo := &countingTokenFinder{
		find: func(_ context.Context, _ string) (*model.WorkspaceToken, error) {
			if authCalls.Add(1) == perIPBurst {
				close(allAdmittedEntered)
			}
			// Hold all admitted fake-Bearer requests concurrently inside BearerTokenAuth
			// so all 200 goroutines race against preAuthThrottlingMiddleware before any 401 returns!
			<-releaseAuth
			return nil, nil
		},
	}

	pipeline := buildThreeTierTestPipelineWithClock(RateLimitConfig{
		Enabled:                       true,
		RequestsPerSecond:             1000,
		Burst:                         500,
		PerIPRequestsPerSecond:        250,
		PerIPBurst:                    perIPBurst,
		PerWorkspaceRequestsPerSecond: 250,
		PerWorkspaceBurst:             50,
		WaitTimeout:                   0,
	}, tokenRepo, staticWorkspaceFinder{}, clock.Now)

	start := make(chan struct{})
	var wg sync.WaitGroup
	var got401, got429 atomic.Int64

	for i := 0; i < totalWorkers; i++ {
		wg.Add(1)
		wsUUID := uuid.NewString()
		go func(id string) {
			defer wg.Done()
			<-start
			req := httptest.NewRequest(http.MethodGet, "/ws/"+id+"/scim/v2/Users", nil)
			req.RemoteAddr = "198.51.100.88:50000"
			req.Header.Set("Authorization", "Bearer fake")
			rec := httptest.NewRecorder()
			pipeline.ServeHTTP(rec, req)
			switch rec.Code {
			case http.StatusUnauthorized:
				got401.Add(1)
			case http.StatusTooManyRequests:
				got429.Add(1)
			default:
				t.Errorf("unexpected status code %d", rec.Code)
			}
		}(wsUUID)
	}

	close(start)
	<-allAdmittedEntered
	close(releaseAuth)
	wg.Wait()

	if calls := authCalls.Load(); calls != perIPBurst {
		t.Fatalf("concurrent fake-Bearer spray reached BearerTokenAuth %d times, want exact %d (zero TOCTOU)", calls, perIPBurst)
	}
	if got401.Load() != perIPBurst || got429.Load() != totalWorkers-perIPBurst {
		t.Fatalf("got 401=%d 429=%d, want 401=%d 429=%d", got401.Load(), got429.Load(), perIPBurst, totalWorkers-perIPBurst)
	}
}

func TestRateLimit_SharedNATIsolationUnderActiveAttackAndDiscoveryNoPromote(t *testing.T) {
	t.Parallel()

	clock := newFakeClock(time.Date(2026, 11, 14, 17, 30, 0, 0, time.UTC))
	wsA := uuid.New()
	wsB := uuid.New()
	tokenB := "tenant-b-secret-token"
	hashB := middleware.HashToken(tokenB)

	tokenRepo := &countingTokenFinder{
		find: func(_ context.Context, tokenHash string) (*model.WorkspaceToken, error) {
			if tokenHash == hashB {
				return &model.WorkspaceToken{WorkspaceID: wsB, TokenHash: hashB}, nil
			}
			return nil, nil
		},
	}
	wsRepo := staticWorkspaceFinder{
		workspaces: map[uuid.UUID]*model.Workspace{
			wsA: {ID: wsA},
			wsB: {ID: wsB},
		},
	}

	rateCfg := RateLimitConfig{
		Enabled:                       true,
		RequestsPerSecond:             1000,
		Burst:                         500,
		PerIPRequestsPerSecond:        1,
		PerIPBurst:                    8,
		PerWorkspaceRequestsPerSecond: 250,
		PerWorkspaceBurst:             50,
		WaitTimeout:                   0,
	}

	var buf bytes.Buffer
	logger := logging.NewLogger(logging.Config{Writer: &buf, Level: logging.ErrorLevel})
	localizer := messages.New(messages.Config{})

	r := chi.NewRouter()
	// Also expose an unauthenticated discovery route returning 200 OK WITHOUT BearerTokenAuth
	// to prove that a 200 OK response without BearerTokenAuth NEVER promotes "fake" into verifiedCache!
	r.Get("/ws/{workspaceId}/scim/v2/ServiceProviderConfig", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	r.Route("/ws/{workspaceId}/scim/v2", func(sr chi.Router) {
		sr.Use(middleware.ExtractWorkspaceID)
		sr.Use(middleware.BearerTokenAuth(tokenRepo, wsRepo))
		sr.Use(newWorkspaceRateLimitMiddlewareWithClock(rateCfg, clock.Now))
		sr.Get("/Users", func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusOK)
		})
	})
	pipeline := newWithClock(r, Config{
		Logger:    logger,
		Localizer: localizer,
		RateLimit: rateCfg,
	}, clock.Now)

	sharedIP := "198.51.100.123:443"

	// Step 1: Legitimate Tenant B authenticates ONCE on sharedIP (uses 1 of 8 unauthIPStore tokens, leaving 7,
	// and promotes (sharedIP, wsB, sha256(tokenB)) into verifiedCache while leaving verifiedIPWSStore[sharedIP,wsB] at full 8/8!).
	initReq := httptest.NewRequest(http.MethodGet, "/ws/"+wsB.String()+"/scim/v2/Users", nil)
	initReq.RemoteAddr = sharedIP
	initReq.Header.Set("Authorization", "Bearer "+tokenB)
	initRec := httptest.NewRecorder()
	pipeline.ServeHTTP(initRec, initReq)
	if initRec.Code != http.StatusOK {
		t.Fatalf("Tenant B initial auth status = %d, want 200", initRec.Code)
	}

	// Step 2: Before unauthIPStore is exhausted, attacker calls GET /ws/<random>/scim/v2/ServiceProviderConfig
	// WITH Authorization: Bearer fake -> gets 200 OK from discovery without running BearerTokenAuth!
	discWS := uuid.New()
	discReq := httptest.NewRequest(http.MethodGet, "/ws/"+discWS.String()+"/scim/v2/ServiceProviderConfig", nil)
	discReq.RemoteAddr = sharedIP
	discReq.Header.Set("Authorization", "Bearer fake")
	discRec := httptest.NewRecorder()
	pipeline.ServeHTTP(discRec, discReq)
	if discRec.Code != http.StatusOK {
		t.Fatalf("discovery ServiceProviderConfig status = %d, want 200", discRec.Code)
	}

	// Step 3: From the SAME sharedIP, attacker completely exhausts unauthIPStore[sharedIP] via:
	// (a) unauthenticated requests,
	// (b) fake-Bearer requests to Tenant A / random UUIDs (401),
	// (c) fake-Bearer requests targeting Tenant B's OWN /ws/<wsB>/scim/v2/Users (401),
	// (d) additional discovery requests with "Bearer fake".
	attackReqs := []*http.Request{
		httptest.NewRequest(http.MethodGet, "/ws/"+wsA.String()+"/scim/v2/Users", nil),
		func() *http.Request {
			q := httptest.NewRequest(http.MethodGet, "/ws/"+wsA.String()+"/scim/v2/Users", nil)
			q.Header.Set("Authorization", "Bearer fake")
			return q
		}(),
		func() *http.Request {
			q := httptest.NewRequest(http.MethodGet, "/ws/"+uuid.NewString()+"/scim/v2/Users", nil)
			q.Header.Set("Authorization", "Bearer fake")
			return q
		}(),
		func() *http.Request {
			q := httptest.NewRequest(http.MethodGet, "/ws/"+wsB.String()+"/scim/v2/Users", nil)
			q.Header.Set("Authorization", "Bearer fake-targeting-victim-wsB")
			return q
		}(),
		func() *http.Request {
			q := httptest.NewRequest(http.MethodGet, "/ws/"+discWS.String()+"/scim/v2/ServiceProviderConfig", nil)
			q.Header.Set("Authorization", "Bearer fake")
			return q
		}(),
	}
	for i := 0; i < 20; i++ {
		base := attackReqs[i%len(attackReqs)]
		q := base.Clone(context.Background())
		q.RemoteAddr = sharedIP
		rec := httptest.NewRecorder()
		pipeline.ServeHTTP(rec, q)
		// 6 tokens remained in unauthIPStore before this loop; requests 7..20 MUST all get 429!
		if i >= 6 && rec.Code != http.StatusTooManyRequests {
			t.Fatalf("attack request %d (%s) status = %d, want 429", i+1, q.URL.Path, rec.Code)
		}
	}

	// Verify specifically that (d) did NOT promote ("fake", discWS) into verifiedCache:
	// calling /ws/<discWS>/scim/v2/Users with "Bearer fake" is blocked pre-auth with 429 (0 DB calls)!
	callsBeforeProbe := tokenRepo.calls.Load()
	probeFake := httptest.NewRequest(http.MethodGet, "/ws/"+discWS.String()+"/scim/v2/Users", nil)
	probeFake.RemoteAddr = sharedIP
	probeFake.Header.Set("Authorization", "Bearer fake")
	probeRec := httptest.NewRecorder()
	pipeline.ServeHTTP(probeRec, probeFake)
	if probeRec.Code != http.StatusTooManyRequests {
		t.Fatalf("probe with discovery 'Bearer fake' status = %d, want 429 (must NOT be promoted)", probeRec.Code)
	}
	if tokenRepo.calls.Load() != callsBeforeProbe {
		t.Fatal("probe with discovery 'Bearer fake' unexpectedly hit DB")
	}

	// Step 4: Despite unauthIPStore[sharedIP] being completely drained AND attacker spraying fake tokens against wsB,
	// Tenant B's valid Bearer requests from sharedIP STILL succeed (200 OK) for Tenant B's FULL PerIPBurst (8)
	// (including uppercase workspace UUID path variant) without a single 429!
	for i := 0; i < rateCfg.PerIPBurst; i++ {
		wsSegment := wsB.String()
		if i%2 == 1 {
			wsSegment = strings.ToUpper(wsSegment)
		}
		reqB := httptest.NewRequest(http.MethodGet, "/ws/"+wsSegment+"/scim/v2/Users", nil)
		reqB.RemoteAddr = sharedIP
		reqB.Header.Set("Authorization", "Bearer "+tokenB)
		recB := httptest.NewRecorder()
		pipeline.ServeHTTP(recB, reqB)
		if recB.Code != http.StatusOK {
			t.Fatalf("Tenant B verified burst request %d status = %d, want 200", i+1, recB.Code)
		}
	}

	// 9th verified request from Tenant B on sharedIP hits Tenant B's own PerIPBurst=8 limit.
	ninthB := httptest.NewRequest(http.MethodGet, "/ws/"+wsB.String()+"/scim/v2/Users", nil)
	ninthB.RemoteAddr = sharedIP
	ninthB.Header.Set("Authorization", "Bearer "+tokenB)
	ninthRec := httptest.NewRecorder()
	pipeline.ServeHTTP(ninthRec, ninthB)
	if ninthRec.Code != http.StatusTooManyRequests {
		t.Fatalf("Tenant B 9th verified request status = %d, want 429", ninthRec.Code)
	}
}

func TestRateLimit_TokenRevocationEvictsVerifiedBearerCacheAndCacheLRUTTL(t *testing.T) {
	t.Parallel()

	clock := newFakeClock(time.Date(2026, 11, 14, 17, 45, 0, 0, time.UTC))
	wsA := uuid.New()
	tokenA := "revocable-tenant-a-token"
	hashA := middleware.HashToken(tokenA)
	var revoked atomic.Bool

	tokenRepo := &countingTokenFinder{
		find: func(_ context.Context, tokenHash string) (*model.WorkspaceToken, error) {
			if tokenHash == hashA && !revoked.Load() {
				return &model.WorkspaceToken{WorkspaceID: wsA, TokenHash: hashA}, nil
			}
			return nil, nil
		},
	}
	wsRepo := staticWorkspaceFinder{
		workspaces: map[uuid.UUID]*model.Workspace{wsA: {ID: wsA}},
	}

	pipeline := buildThreeTierTestPipelineWithClock(RateLimitConfig{
		Enabled:                       true,
		RequestsPerSecond:             1000,
		Burst:                         200,
		PerIPRequestsPerSecond:        1,
		PerIPBurst:                    3, // unauth burst = 3, verified burst = 3
		PerWorkspaceRequestsPerSecond: 250,
		PerWorkspaceBurst:             50,
		WaitTimeout:                   0,
	}, tokenRepo, wsRepo, clock.Now)

	clientIP := "203.0.113.77:443"
	send := func() int {
		req := httptest.NewRequest(http.MethodGet, "/ws/"+wsA.String()+"/scim/v2/Users", nil)
		req.RemoteAddr = clientIP
		req.Header.Set("Authorization", "Bearer "+tokenA)
		rec := httptest.NewRecorder()
		pipeline.ServeHTTP(rec, req)
		return rec.Code
	}

	// Authenticate Tenant A once (consumes 1/3 of unauthIPStore, leaving 2 unauth tokens; promotes tokenA into verifiedCache).
	if code := send(); code != http.StatusOK {
		t.Fatalf("initial auth status = %d, want 200", code)
	}

	// Revoke tokenA! Next request enters verified path (1/3 verifiedIPWSStore), gets 401 from BearerTokenAuth,
	// and immediately evicts tokenA from verifiedCache!
	revoked.Store(true)
	if code := send(); code != http.StatusUnauthorized {
		t.Fatalf("first request after revocation status = %d, want 401", code)
	}

	// Subsequent retries with the revoked token are now throttled by unauthIPStore (only 2 unauth tokens left -> 2x 401, then 429 pre-auth!).
	if code := send(); code != http.StatusUnauthorized {
		t.Fatalf("revoked retry 1 status = %d, want 401", code)
	}
	if code := send(); code != http.StatusUnauthorized {
		t.Fatalf("revoked retry 2 status = %d, want 401", code)
	}
	callsBeforeThrottled := tokenRepo.calls.Load()
	if code := send(); code != http.StatusTooManyRequests {
		t.Fatalf("revoked retry 3 status = %d, want 429 (throttled by unauthIPStore after cache eviction)", code)
	}
	if tokenRepo.calls.Load() != callsBeforeThrottled {
		t.Fatal("throttled revoked-token retry must not hit DB")
	}

	// Direct unit tests on verifiedBearerCache (single-shard & multi-shard LRU capacity, re-Put, TTL expiry, no-op notify).
	notifyPreAuthTokenVerified(context.Background(), wsA)
	notifyPreAuthTokenVerified(context.Background(), uuid.Nil)

	defaultCache := newVerifiedBearerCache(0, time.Minute)
	if len(defaultCache.shards) != defaultRateLimitShards {
		t.Fatalf("defaultCache shards = %d, want %d", len(defaultCache.shards), defaultRateLimitShards)
	}
	kMulti := verifiedBearerKey{ipKey: "ip:1.2.3.4", wsID: wsA.String(), tokenHash: [32]byte{1, 2, 3, 4}}
	defaultCache.Put(kMulti, clock.Now())
	if !defaultCache.Contains(kMulti, clock.Now()) {
		t.Fatal("expected multi-shard Contains == true")
	}

	smallCache := newVerifiedBearerCache(2, 5*time.Minute)
	t0 := clock.Now()
	k1 := verifiedBearerKey{ipKey: "ip:1", wsID: "w1", tokenHash: [32]byte{1}}
	k2 := verifiedBearerKey{ipKey: "ip:2", wsID: "w2", tokenHash: [32]byte{2}}
	k3 := verifiedBearerKey{ipKey: "ip:3", wsID: "w3", tokenHash: [32]byte{3}}

	smallCache.Put(k1, t0)
	smallCache.Put(k1, t0.Add(time.Second)) // update existing entry
	smallCache.Put(k2, t0.Add(2*time.Second))
	// Refresh k1 so k2 is LRU front, then insert k3 to evict k2.
	if !smallCache.Contains(k1, t0.Add(3*time.Second)) {
		t.Fatal("expected k1 in cache")
	}
	smallCache.Put(k3, t0.Add(4*time.Second))
	if smallCache.Contains(k2, t0.Add(4*time.Second)) {
		t.Fatal("expected k2 evicted at capacity=2")
	}
	// Advance past TTL: front eviction on Put and direct expiry on Contains.
	bigCache := newVerifiedBearerCache(8, time.Minute)
	for i := 0; i < 6; i++ {
		bigCache.Put(verifiedBearerKey{ipKey: fmt.Sprintf("ip:%d", i)}, t0)
	}
	targetKey := verifiedBearerKey{ipKey: "ip:target"}
	bigCache.Put(targetKey, t0)
	if bigCache.Contains(targetKey, t0.Add(2*time.Minute)) {
		t.Fatal("expected expired targetKey to return false on Contains")
	}
}

func TestRateLimit_UnauthenticatedFloodCannotDrainVictimWorkspaceBucket(t *testing.T) {
	t.Parallel()

	clock := newFakeClock(time.Date(2026, 11, 14, 18, 0, 0, 0, time.UTC))
	victimWS := uuid.New()
	otherWS := uuid.New()
	victimToken := "victim-valid-token"
	otherToken := "other-valid-token"
	victimHash := middleware.HashToken(victimToken)
	otherHash := middleware.HashToken(otherToken)

	tokenRepo := &countingTokenFinder{
		find: func(_ context.Context, tokenHash string) (*model.WorkspaceToken, error) {
			switch tokenHash {
			case victimHash:
				return &model.WorkspaceToken{WorkspaceID: victimWS, TokenHash: victimHash}, nil
			case otherHash:
				return &model.WorkspaceToken{WorkspaceID: otherWS, TokenHash: otherHash}, nil
			default:
				return nil, nil
			}
		},
	}
	wsRepo := staticWorkspaceFinder{
		workspaces: map[uuid.UUID]*model.Workspace{
			victimWS: {ID: victimWS},
			otherWS:  {ID: otherWS},
		},
	}

	// Scenario 4: Unauthenticated flood against victim /ws/<victim>/... gets 429 while legitimate IdP IP for <victim> gets 200 OK!
	pipeline := buildThreeTierTestPipelineWithClock(RateLimitConfig{
		Enabled:                       true,
		RequestsPerSecond:             500,
		Burst:                         100,
		PerIPRequestsPerSecond:        10,
		PerIPBurst:                    5,
		PerWorkspaceRequestsPerSecond: 0.1,
		PerWorkspaceBurst:             3,
	}, tokenRepo, wsRepo, clock.Now)

	for i := 0; i < 8; i++ {
		r1 := httptest.NewRequest(http.MethodGet, "/ws/"+victimWS.String()+"/scim/v2/Users", nil)
		r1.RemoteAddr = "203.0.113.10:1234"
		rec1 := httptest.NewRecorder()
		pipeline.ServeHTTP(rec1, r1)
		if i >= 5 && rec1.Code != http.StatusTooManyRequests {
			t.Fatalf("attacker IP 1 flood request %d status = %d, want 429", i+1, rec1.Code)
		}

		r2 := httptest.NewRequest(http.MethodGet, "/ws/"+victimWS.String()+"/scim/v2/ServiceProviderConfig", nil)
		r2.RemoteAddr = "203.0.113.11:1234"
		rec2 := httptest.NewRecorder()
		pipeline.ServeHTTP(rec2, r2)
		if i >= 5 && rec2.Code != http.StatusTooManyRequests {
			t.Fatalf("attacker IP 2 flood request %d status = %d, want 429", i+1, rec2.Code)
		}
	}

	// Victim's authenticated workspace bucket (burst=3) is completely untouched.
	for i := 0; i < 3; i++ {
		req := httptest.NewRequest(http.MethodGet, "/ws/"+victimWS.String()+"/scim/v2/Users", nil)
		req.RemoteAddr = "198.51.100.10:443"
		req.Header.Set("Authorization", "Bearer "+victimToken)
		rec := httptest.NewRecorder()
		pipeline.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("victim authenticated request %d status = %d, want 200", i+1, rec.Code)
		}
	}

	// 4th authenticated request for victimWS — even from a SECOND legitimate IP — hits post-auth PerWorkspaceBurst=3.
	fourthVictimReq := httptest.NewRequest(http.MethodGet, "/ws/"+victimWS.String()+"/scim/v2/Users", nil)
	fourthVictimReq.RemoteAddr = "198.51.100.11:443"
	fourthVictimReq.Header.Set("Authorization", "Bearer "+victimToken)
	fourthVictimRec := httptest.NewRecorder()
	pipeline.ServeHTTP(fourthVictimRec, fourthVictimReq)
	if fourthVictimRec.Code != http.StatusTooManyRequests {
		t.Fatalf("4th authenticated victimWS request across 2nd IP status = %d, want 429", fourthVictimRec.Code)
	}

	// Meanwhile, otherWS on another IP still gets 200 OK.
	otherReq := httptest.NewRequest(http.MethodGet, "/ws/"+otherWS.String()+"/scim/v2/Users", nil)
	otherReq.RemoteAddr = "198.51.100.12:443"
	otherReq.Header.Set("Authorization", "Bearer "+otherToken)
	otherRec := httptest.NewRecorder()
	pipeline.ServeHTTP(otherRec, otherReq)
	if otherRec.Code != http.StatusOK {
		t.Fatalf("otherWS authenticated request status = %d, want 200", otherRec.Code)
	}
}

func TestAcquireLimiters_NonDrainingReserveCancelAt(t *testing.T) {
	t.Parallel()

	clock := newFakeClock(time.Date(2026, 11, 14, 19, 0, 0, 0, time.UTC))

	// Global limiter has 2 tokens (refills at 2 rps); per-IP limiter has 5 tokens (refills at 0.01 rps).
	mw := newPreAuthThrottlingMiddleware(RateLimitConfig{
		Enabled:                true,
		RequestsPerSecond:      2,
		Burst:                  2,
		PerIPRequestsPerSecond: 0.01,
		PerIPBurst:             5,
		WaitTimeout:            0,
	}, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}), clock.Now)

	// Drain globalLimiter's 2 burst tokens using another IP (203.0.113.1).
	for i := 0; i < 2; i++ {
		r := httptest.NewRequest(http.MethodGet, "/scim/v2/Users", nil)
		r.RemoteAddr = "203.0.113.1:1000"
		rec := httptest.NewRecorder()
		mw.ServeHTTP(rec, r)
		if rec.Code != http.StatusOK {
			t.Fatalf("setup global drain %d status = %d, want 200", i+1, rec.Code)
		}
	}

	// Compliant client (198.51.100.55) sends 10 requests while globalLimiter has 0 tokens.
	// All 10 are rejected with 429, and CancelAt MUST leave 198.51.100.55's per-IP bucket completely undrained (all 5 burst tokens intact)!
	for i := 0; i < 10; i++ {
		r := httptest.NewRequest(http.MethodGet, "/scim/v2/Users", nil)
		r.RemoteAddr = "198.51.100.55:2000"
		rec := httptest.NewRecorder()
		mw.ServeHTTP(rec, r)
		if rec.Code != http.StatusTooManyRequests {
			t.Fatalf("rejected request %d while global empty status = %d, want 429", i+1, rec.Code)
		}
	}

	// Also verify direct acquireLimiters when a limiter has burst=0 (!res.OK()) leaves peer limiter undrained.
	peerLim := rate.NewLimiter(rate.Limit(0.01), 3)
	zeroBurstLim := rate.NewLimiter(rate.Limit(1), 0)
	req := httptest.NewRequest(http.MethodGet, "/scim/v2/Users", nil)
	if allowed, canceled := acquireLimiters(req, clock.Now, 0, nil, peerLim, zeroBurstLim); allowed || canceled {
		t.Fatalf("acquireLimiters with zero-burst limiter = (%v, %v), want (false, false)", allowed, canceled)
	}
	if gotTokens := peerLim.TokensAt(clock.Now()); gotTokens != 3 {
		t.Fatalf("peerLim tokens after failed ReserveN = %v, want 3 (undrained)", gotTokens)
	}
	if allowed, canceled := acquireLimiters(req, clock.Now, 0, nil); !allowed || canceled {
		t.Fatalf("acquireLimiters with empty limiter list = (%v, %v), want (true, false)", allowed, canceled)
	}

	// Refill globalLimiter (advance 1s -> 2 global tokens; 0.01 rps * 1s = +0.01 tokens on per-IP, so per-IP only has 5 tokens if undrained!).
	// Send 2 bursts of 2 + 2 + 1 = 5 requests for 198.51.100.55 across 2.5s; if its 5 burst tokens were drained during the global outage, it would have < 0.03 tokens and fail!
	for batch := 0; batch < 2; batch++ {
		clock.Advance(time.Second) // refills 2 global tokens
		for j := 0; j < 2; j++ {
			r := httptest.NewRequest(http.MethodGet, "/scim/v2/Users", nil)
			r.RemoteAddr = "198.51.100.55:2000"
			rec := httptest.NewRecorder()
			mw.ServeHTTP(rec, r)
			if rec.Code != http.StatusOK {
				t.Fatalf("compliant client batch %d req %d status = %d, want 200 (per-IP bucket must be undrained)", batch+1, j+1, rec.Code)
			}
		}
	}
	clock.Advance(500 * time.Millisecond) // refills 5th global token; total elapsed 2.5s -> +0.025 per-IP tokens
	fifthReq := httptest.NewRequest(http.MethodGet, "/scim/v2/Users", nil)
	fifthReq.RemoteAddr = "198.51.100.55:2000"
	fifthRec := httptest.NewRecorder()
	mw.ServeHTTP(fifthRec, fifthReq)
	if fifthRec.Code != http.StatusOK {
		t.Fatalf("compliant client 5th burst token status = %d, want 200", fifthRec.Code)
	}

	// 6th request from 198.51.100.55 now hits its own PerIPBurst=5 limit.
	clock.Advance(500 * time.Millisecond)
	sixthRec := httptest.NewRecorder()
	mw.ServeHTTP(sixthRec, fifthReq)
	if sixthRec.Code != http.StatusTooManyRequests {
		t.Fatalf("compliant client 6th request status = %d, want 429 after using all 5 burst tokens", sixthRec.Code)
	}
}

func TestRateLimit_GlobalCapAndSubLimitResolutionAndWorkspaceMiddlewareEdgeCases(t *testing.T) {
	t.Parallel()

	if rps, burst := resolveSubRateLimit(1000, 100, 0, 0); rps != 250 || burst != 50 {
		t.Fatalf("resolveSubRateLimit(1000, 100, 0, 0) = (%v, %d), want (250, 50)", rps, burst)
	}
	if rps, burst := resolveSubRateLimit(1000, 100, 12, 0); rps != 12 || burst != 12 {
		t.Fatalf("resolveSubRateLimit(1000, 100, 12, 0) = (%v, %d), want (12, 12)", rps, burst)
	}
	if rps, burst := resolveSubRateLimit(1, 3, 0, 0); rps != 1 || burst != 3 {
		t.Fatalf("resolveSubRateLimit(1, 3, 0, 0) = (%v, %d), want (1, 3)", rps, burst)
	}

	clock := newFakeClock(time.Date(2026, 11, 14, 20, 0, 0, 0, time.UTC))
	var buf bytes.Buffer
	logger := logging.NewLogger(logging.Config{Writer: &buf, Level: logging.ErrorLevel})
	localizer := messages.New(messages.Config{})

	globalCapped := newWithClock(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}), Config{
		Logger:    logger,
		Localizer: localizer,
		RateLimit: RateLimitConfig{
			Enabled:                true,
			RequestsPerSecond:      0.1,
			Burst:                  4,
			PerIPRequestsPerSecond: 100,
			PerIPBurst:             20,
			WaitTimeout:            0,
		},
	}, clock.Now)

	for i := 1; i <= 6; i++ {
		req := httptest.NewRequest(http.MethodGet, "/scim/v2/Users", nil)
		req.RemoteAddr = fmt.Sprintf("198.51.100.%d:1234", i)
		rec := httptest.NewRecorder()
		globalCapped.ServeHTTP(rec, req)
		if i <= 4 && rec.Code != http.StatusOK {
			t.Fatalf("distinct IP %d within global burst=4 got %d, want 200", i, rec.Code)
		}
		if i > 4 && rec.Code != http.StatusTooManyRequests {
			t.Fatalf("distinct IP %d exceeding global burst=4 got %d, want 429", i, rec.Code)
		}
	}

	// Verify shared WaitTimeout path when IP bucket allows and Global bucket waits briefly.
	globalWait := New(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}), Config{
		Logger:    logger,
		Localizer: localizer,
		RateLimit: RateLimitConfig{
			Enabled:                true,
			RequestsPerSecond:      20,
			Burst:                  1,
			PerIPRequestsPerSecond: 100,
			PerIPBurst:             10,
			WaitTimeout:            time.Second,
		},
	})
	r1 := httptest.NewRequest(http.MethodGet, "/scim/v2/Users", nil)
	r1.RemoteAddr = "198.51.100.201:1234"
	globalWait.ServeHTTP(httptest.NewRecorder(), r1)

	r2 := httptest.NewRequest(http.MethodGet, "/scim/v2/Users", nil)
	r2.RemoteAddr = "198.51.100.202:1234"
	rec2 := httptest.NewRecorder()
	globalWait.ServeHTTP(rec2, r2)
	if rec2.Code != http.StatusNoContent {
		t.Fatalf("second IP waiting on global limiter status = %d, want 204", rec2.Code)
	}

	// Verify NewWorkspaceRateLimitMiddleware pass-through when disabled, unauthenticated pass-through, and canceled-context safety.
	disabledMW := NewWorkspaceRateLimitMiddleware(RateLimitConfig{Enabled: false})(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusAccepted)
	}))
	disabledRec := httptest.NewRecorder()
	disabledMW.ServeHTTP(disabledRec, httptest.NewRequest(http.MethodGet, "/Users", nil))
	if disabledRec.Code != http.StatusAccepted {
		t.Fatalf("disabled workspace middleware status = %d, want 202", disabledRec.Code)
	}

	enabledWSMW := NewWorkspaceRateLimitMiddleware(RateLimitConfig{
		Enabled:                       true,
		RequestsPerSecond:             10,
		PerWorkspaceRequestsPerSecond: 0.1,
		PerWorkspaceBurst:             1,
		WaitTimeout:                   5 * time.Millisecond,
	})(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	// Unauthenticated request (e.g., anonymous discovery) passes through workspace middleware without throttling.
	unauthRec := httptest.NewRecorder()
	enabledWSMW.ServeHTTP(unauthRec, httptest.NewRequest(http.MethodGet, "/ServiceProviderConfig", nil))
	if unauthRec.Code != http.StatusOK {
		t.Fatalf("unauthenticated workspace middleware pass-through status = %d, want 200", unauthRec.Code)
	}

	wsID := uuid.New()
	canceledCtx, cancel := context.WithCancel(middleware.WithAuthenticatedWorkspaceID(context.Background(), wsID))
	cancel()
	canceledRec := httptest.NewRecorder()
	enabledWSMW.ServeHTTP(canceledRec, httptest.NewRequest(http.MethodGet, "/Users", nil).WithContext(canceledCtx))
	if canceledRec.Body.Len() != 0 {
		t.Fatalf("expected empty body for canceled workspace-limited request, got %q", canceledRec.Body.String())
	}
}

func TestKeyedLimiterStore_ShardedO1EvictionUnderKeySpray(t *testing.T) {
	t.Parallel()

	store := newKeyedLimiterStore(100, 10)
	if len(store.shards) != defaultRateLimitShards {
		t.Fatalf("len(shards) = %d, want %d", len(store.shards), defaultRateLimitShards)
	}

	const (
		workers       = 8
		keysPerWorker = 2000 // 16,000 unique keys across 4,096 max entries
	)
	var wg sync.WaitGroup
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()
			for i := 0; i < keysPerWorker; i++ {
				key := fmt.Sprintf("ip:198.18.%d.%d:%d", workerID, (i>>8)&0xff, i&0xff)
				_ = store.LimiterForKey(key)
			}
		}(w)
	}
	wg.Wait()

	if total := store.lenEntries(); total > defaultMaxRateLimitBuckets {
		t.Fatalf("store.lenEntries() = %d, exceeds hard cap %d", total, defaultMaxRateLimitBuckets)
	}

	defaultCapStore := newKeyedLimiterStoreWithOptions(10, 5, 0, time.Minute, nil)
	if len(defaultCapStore.shards) != defaultRateLimitShards {
		t.Fatalf("defaultCapStore shards = %d, want %d", len(defaultCapStore.shards), defaultRateLimitShards)
	}
	unevenStore := newKeyedLimiterStoreWithOptions(10, 5, 35, time.Minute, time.Now)
	capSum := 0
	for i := range unevenStore.shards {
		capSum += unevenStore.shards[i].maxEntries
	}
	if capSum != 35 {
		t.Fatalf("unevenStore shard capacity sum = %d, want 35", capSum)
	}
}

func TestResolveRateLimitBurst_AndWaiterCapOverflow(t *testing.T) {
	t.Parallel()

	if got := resolveRateLimitBurst(0.5, 0); got != 1 {
		t.Fatalf("resolveRateLimitBurst(0.5, 0) = %d, want 1", got)
	}
	if got := resolveRateLimitBurst(25.2, 0); got != 26 {
		t.Fatalf("resolveRateLimitBurst(25.2, 0) = %d, want 26", got)
	}
	if got := resolveRateLimitBurst(5000, 0); got != maxDefaultRateLimitBurst {
		t.Fatalf("resolveRateLimitBurst(5000, 0) = %d, want %d", got, maxDefaultRateLimitBurst)
	}
	if got := resolveRateLimitBurst(5000, 42); got != 42 {
		t.Fatalf("resolveRateLimitBurst(5000, 42) = %d, want 42", got)
	}
	if got := resolveRateLimitBurst(math.NaN(), 0); got != 1 {
		t.Fatalf("resolveRateLimitBurst(NaN, 0) = %d, want 1", got)
	}
	if got := resolveRateLimitBurst(math.Inf(-1), 0); got != 1 {
		t.Fatalf("resolveRateLimitBurst(-Inf, 0) = %d, want 1", got)
	}
	if got := resolveRateLimitBurst(math.Inf(1), 0); got != maxDefaultRateLimitBurst {
		t.Fatalf("resolveRateLimitBurst(+Inf, 0) = %d, want %d", got, maxDefaultRateLimitBurst)
	}
	if got := resolveRateLimitBurst(1e30, 0); got != maxDefaultRateLimitBurst {
		t.Fatalf("resolveRateLimitBurst(1e30, 0) = %d, want %d", got, maxDefaultRateLimitBurst)
	}
	if got := sanitizeRateLimit(math.NaN()); got != 0 {
		t.Fatalf("sanitizeRateLimit(NaN) = %v, want 0", got)
	}
	if got := sanitizeRateLimit(math.Inf(1)); got <= 0 {
		t.Fatalf("sanitizeRateLimit(+Inf) = %v, want rate.Inf", got)
	}
	if rps, burst := resolveSubRateLimit(math.NaN(), 0, math.NaN(), 0); rps != defaultPerKeyRequestsPerSecond || burst != 1 {
		t.Fatalf("resolveSubRateLimit(NaN, 0, NaN, 0) = (%v, %d), want (%v, 1)", rps, burst, defaultPerKeyRequestsPerSecond)
	}

	// Deterministic waitSem overflow test via acquireLimiters: fill waitSem of capacity 1 and verify
	// the overflow request fails fast and cancels its reservation without draining its per-IP limiter.
	clock := newFakeClock(time.Date(2026, 11, 14, 21, 0, 0, 0, time.UTC))
	waitSem := make(chan struct{}, 1)
	waitSem <- struct{}{} // occupy sole waiter slot

	globalSlow := rate.NewLimiter(rate.Limit(2), 1)
	globalSlow.AllowN(clock.Now(), 1) // 0 tokens left; next ReserveN has 500ms delay (<= 1s waitTimeout)
	clientLim := rate.NewLimiter(rate.Limit(0.01), 4)

	req := httptest.NewRequest(http.MethodGet, "/scim/v2/Users", nil)
	allowed, canceled := acquireLimiters(req, clock.Now, time.Second, waitSem, clientLim, globalSlow)
	if allowed || canceled {
		t.Fatalf("overflow waiter acquireLimiters = (%v, %v), want (false, false)", allowed, canceled)
	}
	if gotTokens := clientLim.TokensAt(clock.Now()); gotTokens != 4 {
		t.Fatalf("clientLim tokens after waitSem overflow = %v, want 4 (reservation must be canceled)", gotTokens)
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
