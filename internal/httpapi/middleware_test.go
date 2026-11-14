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

func (s stubLimiter) LimiterFor(*http.Request) requestLimiter {
	return s
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

func TestThrottlingMiddleware_RequestCanceledDuringWaitDoesNotWriteCapacityError(t *testing.T) {
	t.Parallel()

	enteredWait := make(chan struct{})
	calledNext := false
	handler := throttlingMiddleware(stubLimiter{wait: func(ctx context.Context) error {
		close(enteredWait)
		<-ctx.Done()
		return ctx.Err()
	}}, 5*time.Second, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calledNext = true
	}))

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() {
		<-enteredWait
		cancel()
	}()

	req := httptest.NewRequest(http.MethodGet, "/scim/v2/Users", nil).WithContext(ctx)
	rw := httptest.NewRecorder()
	handler.ServeHTTP(rw, req)

	if calledNext {
		t.Fatal("next handler was called despite request cancellation during Wait")
	}
	if rw.Body.Len() != 0 {
		t.Fatalf("response body = %q, want empty body when client cancels during Wait", rw.Body.String())
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

func TestThrottlingMiddleware_PerIPIsolationAndNoManagementBypass(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	logger := logging.NewLogger(logging.Config{Writer: &buf, Level: logging.InfoLevel})
	localizer := messages.New(messages.Config{})

	handler := New(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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
	})

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

	// 4th request from Client A fails fast (WaitTimeout=0) with 429 SCIM Error and Retry-After: 1,
	// even if targeting a completely different workspace UUID!
	start := time.Now()
	rw := httptest.NewRecorder()
	fourthReq := httptest.NewRequest(http.MethodGet, "/ws/999e4567-e89b-12d3-a456-426614174999/scim/v2/Users", nil)
	fourthReq.RemoteAddr = "198.51.100.1:5555"
	handler.ServeHTTP(rw, fourthReq)
	if elapsed := time.Since(start); elapsed > 100*time.Millisecond {
		t.Fatalf("fail-fast 429 took %v, expected immediate response", elapsed)
	}
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
}

func TestKeyedLimiterStore_KeyExtractionTTLEvictionAndCapacityCap(t *testing.T) {
	t.Parallel()

	if got := extractClientIPKey(nil, nil); got != "global" {
		t.Fatalf("extractClientIPKey(nil) = %q, want global", got)
	}

	emptyAddrReq := httptest.NewRequest(http.MethodGet, "/scim/v2/Users", nil)
	emptyAddrReq.RemoteAddr = "   "
	if got := extractClientIPKey(emptyAddrReq, nil); got != "global" {
		t.Fatalf("extractClientIPKey(empty RemoteAddr) = %q, want global", got)
	}

	nonIPAddrReq := httptest.NewRequest(http.MethodGet, "/scim/v2/Users", nil)
	nonIPAddrReq.RemoteAddr = "unix-socket-peer"
	if got := extractClientIPKey(nonIPAddrReq, nil); got != "ip:unix-socket-peer" {
		t.Fatalf("extractClientIPKey(non-IP RemoteAddr) = %q, want ip:unix-socket-peer", got)
	}

	rawAddrReq := httptest.NewRequest(http.MethodGet, "/ws/invalid-ws/scim/v2/Users", nil)
	rawAddrReq.RemoteAddr = "203.0.113.7"
	if got := extractClientIPKey(rawAddrReq, nil); got != "ip:203.0.113.7" {
		t.Fatalf("extractClientIPKey(raw IP) = %q, want ip:203.0.113.7", got)
	}

	ipv6Req := httptest.NewRequest(http.MethodGet, "/scim/v2/Users", nil)
	ipv6Req.RemoteAddr = "[2001:db8::1]:44321"
	if got := extractClientIPKey(ipv6Req, nil); got != "ip:2001:db8::1" {
		t.Fatalf("extractClientIPKey(IPv6) = %q, want ip:2001:db8::1", got)
	}

	// Pre-auth key extraction NEVER keys by URL workspace UUID.
	wsReq := httptest.NewRequest(http.MethodGet, "/ws/ABCDEF01-2345-6789-ABCD-EF0123456789/scim/v2/Users", nil)
	wsReq.RemoteAddr = "198.51.100.42:1234"
	if got := extractClientIPKey(wsReq, nil); got != "ip:198.51.100.42" {
		t.Fatalf("extractClientIPKey(ws URL) = %q, want ip:198.51.100.42 (must ignore unauthenticated URL UUID)", got)
	}

	// Verify O(1) doubly-linked-list LRU + TTL expiration and hard maxEntries capacity eviction.
	now := time.Date(2026, 11, 13, 12, 0, 0, 0, time.UTC)
	store := newKeyedLimiterStoreWithOptions(1, 1, 3, 5*time.Minute, func() time.Time {
		return now
	})

	reqForIP := func(ip string) *http.Request {
		r := httptest.NewRequest(http.MethodGet, "/scim/v2/Users", nil)
		r.RemoteAddr = ip + ":1234"
		return r
	}

	lim1 := store.LimiterFor(reqForIP("10.0.0.1"))
	if !lim1.Allow() || lim1.Allow() {
		t.Fatal("expected burst=1 bucket for 10.0.0.1 to allow first call and reject second")
	}
	now = now.Add(10 * time.Second)
	_ = store.LimiterFor(reqForIP("10.0.0.2"))
	now = now.Add(10 * time.Second)
	_ = store.LimiterFor(reqForIP("10.0.0.3"))

	if store.lenEntries() != 3 {
		t.Fatalf("lenEntries() = %d, want 3", store.lenEntries())
	}

	// Touch 10.0.0.1 (MoveToBack) so 10.0.0.2 becomes the oldest (Front) entry.
	now = now.Add(10 * time.Second)
	if got := store.LimiterFor(reqForIP("10.0.0.1")); got != lim1 {
		t.Fatal("expected existing non-expired limiter for 10.0.0.1")
	}

	// Inserting 10.0.0.4 at capacity=3 must evict LRU front (ip:10.0.0.2) in O(1) and keep size == 3.
	now = now.Add(10 * time.Second)
	_ = store.LimiterFor(reqForIP("10.0.0.4"))
	if store.lenEntries() != 3 {
		t.Fatalf("lenEntries() after capacity eviction = %d, want 3", store.lenEntries())
	}
	if store.hasKey("ip:10.0.0.2") {
		t.Fatal("expected LRU entry ip:10.0.0.2 to be evicted")
	}

	// Advance past TTL for ip:10.0.0.3 (seen at +20s; at +5m25s it is >5m old, while 10.0.0.1 at +30s & 10.0.0.4 at +40s are <5m old).
	now = time.Date(2026, 11, 13, 12, 5, 25, 0, time.UTC)
	_ = store.LimiterFor(reqForIP("10.0.0.5"))
	if store.lenEntries() != 3 {
		t.Fatalf("lenEntries() after expired front eviction = %d, want 3", store.lenEntries())
	}
	if store.hasKey("ip:10.0.0.3") {
		t.Fatal("expected expired entry ip:10.0.0.3 to be popped before active entries")
	}
	if !store.hasKey("ip:10.0.0.1") {
		t.Fatal("expected active entry ip:10.0.0.1 to remain in store")
	}

	// Advance past TTL for 10.0.0.4 while keeping 10.0.0.5 active, then look up expired 10.0.0.4 directly.
	// First add a larger store so front isn't the only expired element when >maxExpiredEvictPerAccess expire.
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

func buildThreeTierTestPipeline(
	rateCfg RateLimitConfig,
	tokenRepo *countingTokenFinder,
	wsRepo staticWorkspaceFinder,
) http.Handler {
	var buf bytes.Buffer
	logger := logging.NewLogger(logging.Config{Writer: &buf, Level: logging.ErrorLevel})
	localizer := messages.New(messages.Config{})

	r := chi.NewRouter()
	r.Route("/ws/{workspaceId}/scim/v2", func(sr chi.Router) {
		sr.Use(middleware.ExtractWorkspaceID)
		sr.Use(middleware.BearerTokenAuth(tokenRepo, wsRepo))
		sr.Use(NewWorkspaceRateLimitMiddleware(rateCfg))
		sr.Get("/Users", func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusOK)
		})
		sr.Get("/ServiceProviderConfig", func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusOK)
		})
	})

	return New(r, Config{
		Logger:    logger,
		Localizer: localizer,
		RateLimit: rateCfg,
	})
}

func TestRateLimit_RandomWorkspaceUUIDSprayBlockedPreAuthWithoutDBLookups(t *testing.T) {
	t.Parallel()

	legitWS := uuid.New()
	legitToken := "valid-workspace-token-123"
	legitHash := middleware.HashToken(legitToken)

	tokenRepo := &countingTokenFinder{
		find: func(_ context.Context, tokenHash string) (*model.WorkspaceToken, error) {
			if tokenHash == legitHash {
				return &model.WorkspaceToken{WorkspaceID: legitWS, TokenHash: legitHash}, nil
			}
			return nil, nil
		},
	}
	wsRepo := staticWorkspaceFinder{
		workspaces: map[uuid.UUID]*model.Workspace{legitWS: {ID: legitWS}},
	}

	pipeline := buildThreeTierTestPipeline(RateLimitConfig{
		Enabled:                       true,
		RequestsPerSecond:             500,
		Burst:                         50,
		PerIPRequestsPerSecond:        0.1,
		PerIPBurst:                    3,
		PerWorkspaceRequestsPerSecond: 50,
		PerWorkspaceBurst:             10,
	}, tokenRepo, wsRepo)

	// 1. Direct attacker from public IP spraying 20 random workspace UUIDs with fake Bearer tokens.
	for i := 0; i < 20; i++ {
		req := httptest.NewRequest(http.MethodGet, "/ws/"+uuid.NewString()+"/scim/v2/Users", nil)
		req.RemoteAddr = "203.0.113.99:40000"
		req.Header.Set("Authorization", "Bearer fake-spray-token")
		rec := httptest.NewRecorder()
		pipeline.ServeHTTP(rec, req)

		if i < 3 {
			if rec.Code != http.StatusUnauthorized {
				t.Fatalf("spray request %d status = %d, want 401 before IP burst exhausted", i+1, rec.Code)
			}
		} else {
			if rec.Code != http.StatusTooManyRequests {
				t.Fatalf("spray request %d status = %d, want 429 from pre-auth per-IP limiter", i+1, rec.Code)
			}
		}
	}
	if gotCalls := tokenRepo.calls.Load(); gotCalls != 3 {
		t.Fatalf("tokenRepo DB lookups = %d, want exactly 3 (requests 4..20 must be blocked before BearerTokenAuth)", gotCalls)
	}

	// 2. Attacker behind trusted cloudflared proxy (private peer 10.0.0.5 + CF-Connecting-IP) spraying random UUIDs.
	for i := 0; i < 15; i++ {
		req := httptest.NewRequest(http.MethodGet, "/ws/"+uuid.NewString()+"/scim/v2/Users", nil)
		req.RemoteAddr = "10.0.0.5:50000"
		req.Header.Set("CF-Connecting-IP", "198.51.100.77")
		req.Header.Set("Authorization", "Bearer fake-spray-token-cf")
		rec := httptest.NewRecorder()
		pipeline.ServeHTTP(rec, req)

		if i >= 3 && rec.Code != http.StatusTooManyRequests {
			t.Fatalf("CF spray request %d status = %d, want 429", i+1, rec.Code)
		}
	}
	if gotCalls := tokenRepo.calls.Load(); gotCalls != 6 {
		t.Fatalf("tokenRepo DB lookups after CF spray = %d, want 6 (only 3 permitted for CF IP)", gotCalls)
	}

	// 3. Legitimate client on a different CF-Connecting-IP is unaffected (global bucket was NOT drained by attacker!).
	legitReq := httptest.NewRequest(http.MethodGet, "/ws/"+legitWS.String()+"/scim/v2/Users", nil)
	legitReq.RemoteAddr = "10.0.0.5:50001"
	legitReq.Header.Set("CF-Connecting-IP", "198.51.100.88")
	legitReq.Header.Set("Authorization", "Bearer "+legitToken)
	legitRec := httptest.NewRecorder()
	pipeline.ServeHTTP(legitRec, legitReq)
	if legitRec.Code != http.StatusOK {
		t.Fatalf("legitimate client status = %d, want 200", legitRec.Code)
	}
}

func TestRateLimit_UnauthenticatedFloodCannotDrainVictimWorkspaceBucket(t *testing.T) {
	t.Parallel()

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

	pipeline := buildThreeTierTestPipeline(RateLimitConfig{
		Enabled:                       true,
		RequestsPerSecond:             500,
		Burst:                         100,
		PerIPRequestsPerSecond:        10,
		PerIPBurst:                    5,
		PerWorkspaceRequestsPerSecond: 0.1,
		PerWorkspaceBurst:             3,
	}, tokenRepo, wsRepo)

	// Unauthenticated attackers from two different IPs hammer victimWS (/Users without token and anonymous /ServiceProviderConfig).
	for i := 0; i < 8; i++ {
		r1 := httptest.NewRequest(http.MethodGet, "/ws/"+victimWS.String()+"/scim/v2/Users", nil)
		r1.RemoteAddr = "203.0.113.10:1234"
		pipeline.ServeHTTP(httptest.NewRecorder(), r1)

		r2 := httptest.NewRequest(http.MethodGet, "/ws/"+victimWS.String()+"/scim/v2/ServiceProviderConfig", nil)
		r2.RemoteAddr = "203.0.113.11:1234"
		pipeline.ServeHTTP(httptest.NewRecorder(), r2)
	}

	// Victim's authenticated workspace bucket (burst=3) must still be completely untouched!
	for i := 0; i < 3; i++ {
		req := httptest.NewRequest(http.MethodGet, "/ws/"+victimWS.String()+"/scim/v2/Users", nil)
		req.RemoteAddr = "198.51.100.10:443"
		req.Header.Set("Authorization", "Bearer "+victimToken)
		rec := httptest.NewRecorder()
		pipeline.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("victim authenticated request %d status = %d, want 200 (workspace bucket must not be drained by unauth flood)", i+1, rec.Code)
		}
	}

	// 4th authenticated request for victimWS — even from a SECOND legitimate IP — hits post-auth PerWorkspaceBurst=3!
	fourthVictimReq := httptest.NewRequest(http.MethodGet, "/ws/"+victimWS.String()+"/scim/v2/Users", nil)
	fourthVictimReq.RemoteAddr = "198.51.100.11:443"
	fourthVictimReq.Header.Set("Authorization", "Bearer "+victimToken)
	fourthVictimRec := httptest.NewRecorder()
	pipeline.ServeHTTP(fourthVictimRec, fourthVictimReq)
	if fourthVictimRec.Code != http.StatusTooManyRequests {
		t.Fatalf("4th authenticated victimWS request across 2nd IP status = %d, want 429 from NewWorkspaceRateLimitMiddleware", fourthVictimRec.Code)
	}

	// Meanwhile, otherWS on another IP still gets 200 OK (post-auth workspace buckets are isolated per tenant).
	otherReq := httptest.NewRequest(http.MethodGet, "/ws/"+otherWS.String()+"/scim/v2/Users", nil)
	otherReq.RemoteAddr = "198.51.100.12:443"
	otherReq.Header.Set("Authorization", "Bearer "+otherToken)
	otherRec := httptest.NewRecorder()
	pipeline.ServeHTTP(otherRec, otherReq)
	if otherRec.Code != http.StatusOK {
		t.Fatalf("otherWS authenticated request status = %d, want 200", otherRec.Code)
	}
}

func TestRateLimit_TrustedProxyExtractionAndSpoofRejection(t *testing.T) {
	t.Parallel()

	// 1. Untrusted public RemoteAddr attempting to spoof CF-Connecting-IP & X-Forwarded-For on every request.
	publicReq := httptest.NewRequest(http.MethodGet, "/scim/v2/Users", nil)
	publicReq.RemoteAddr = "203.0.113.7:9000"
	publicReq.Header.Set("CF-Connecting-IP", "1.2.3.4")
	publicReq.Header.Set("X-Forwarded-For", "5.6.7.8")
	if got := extractClientIPKey(publicReq, nil); got != "ip:203.0.113.7" {
		t.Fatalf("untrusted public peer spoofed key = %q, want ip:203.0.113.7", got)
	}

	// 2. Trusted private/loopback/link-local/4in6 peers honor single valid CF-Connecting-IP.
	for _, peer := range []string{"127.0.0.1:8080", "172.18.0.4:3456", "[::1]:8080", "[fe80::1%eth0]:8080", "[::ffff:10.1.2.3]:8080"} {
		r := httptest.NewRequest(http.MethodGet, "/scim/v2/Users", nil)
		r.RemoteAddr = peer
		r.Header.Set("CF-Connecting-IP", " 198.51.100.200 ")
		if got := extractClientIPKey(r, nil); got != "ip:198.51.100.200" {
			t.Fatalf("peer %s with CF-Connecting-IP got %q, want ip:198.51.100.200", peer, got)
		}
	}

	// 3. Ambiguous multi-header or comma-containing CF-Connecting-IP is rejected; falls back to rightmost X-Forwarded-For hop.
	ambigCF := httptest.NewRequest(http.MethodGet, "/scim/v2/Users", nil)
	ambigCF.RemoteAddr = "10.0.0.2:8080"
	ambigCF.Header.Add("CF-Connecting-IP", "1.1.1.1")
	ambigCF.Header.Add("CF-Connecting-IP", "2.2.2.2")
	ambigCF.Header.Add("X-Forwarded-For", "forged-client-entry, 203.0.113.55")
	ambigCF.Header.Add("X-Forwarded-For", "192.0.2.99, ::ffff:198.51.100.44")
	if got := extractClientIPKey(ambigCF, nil); got != "ip:198.51.100.44" {
		t.Fatalf("ambiguous CF + multi XFF got %q, want rightmost XFF hop ip:198.51.100.44", got)
	}

	// 4. Invalid CF-Connecting-IP and invalid rightmost XFF falls back safely to peer IP.
	invalidHdrs := httptest.NewRequest(http.MethodGet, "/scim/v2/Users", nil)
	invalidHdrs.RemoteAddr = "10.0.0.9:8080"
	invalidHdrs.Header.Set("CF-Connecting-IP", "   ")
	invalidHdrs.Header.Set("X-Forwarded-For", "1.2.3.4, not-an-ip")
	if got := extractClientIPKey(invalidHdrs, nil); got != "ip:10.0.0.9" {
		t.Fatalf("invalid proxy headers fallback got %q, want ip:10.0.0.9", got)
	}

	// 5. Custom ParseTrustedProxies list overrides default private-range trust.
	customProxies, err := ParseTrustedProxies("198.51.100.0/24, , ::ffff:192.0.2.5/128, 2001:db8::1")
	if err != nil {
		t.Fatalf("ParseTrustedProxies error = %v", err)
	}
	customAllowed := httptest.NewRequest(http.MethodGet, "/scim/v2/Users", nil)
	customAllowed.RemoteAddr = "198.51.100.9:443"
	customAllowed.Header.Set("CF-Connecting-IP", "203.0.113.88")
	if got := extractClientIPKey(customAllowed, customProxies); got != "ip:203.0.113.88" {
		t.Fatalf("custom trusted proxy got %q, want ip:203.0.113.88", got)
	}

	notInCustom := httptest.NewRequest(http.MethodGet, "/scim/v2/Users", nil)
	notInCustom.RemoteAddr = "10.0.0.1:443"
	notInCustom.Header.Set("CF-Connecting-IP", "203.0.113.88")
	if got := extractClientIPKey(notInCustom, customProxies); got != "ip:10.0.0.1" {
		t.Fatalf("peer outside custom trusted proxies got %q, want ip:10.0.0.1", got)
	}
}

func TestRateLimit_GlobalCapAndSubLimitResolutionAndWorkspaceMiddlewareEdgeCases(t *testing.T) {
	t.Parallel()

	// Verify resolveSubRateLimit defaults for production (1000 rps / 100 burst -> 250 rps / 50 burst)
	// and explicit sub-rate overrides.
	if rps, burst := resolveSubRateLimit(1000, 100, 0, 0); rps != 250 || burst != 50 {
		t.Fatalf("resolveSubRateLimit(1000, 100, 0, 0) = (%v, %d), want (250, 50)", rps, burst)
	}
	if rps, burst := resolveSubRateLimit(1000, 100, 12, 0); rps != 12 || burst != 12 {
		t.Fatalf("resolveSubRateLimit(1000, 100, 12, 0) = (%v, %d), want (12, 12)", rps, burst)
	}
	if rps, burst := resolveSubRateLimit(1, 3, 0, 0); rps != 1 || burst != 3 {
		t.Fatalf("resolveSubRateLimit(1, 3, 0, 0) = (%v, %d), want (1, 3)", rps, burst)
	}

	// Global server-wide cap enforced even when every request comes from a distinct client IP.
	var buf bytes.Buffer
	logger := logging.NewLogger(logging.Config{Writer: &buf, Level: logging.ErrorLevel})
	localizer := messages.New(messages.Config{})

	globalCapped := New(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
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
	})

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

	// Verify NewWorkspaceRateLimitMiddleware pass-through when disabled and canceled-context safety when enabled.
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
	start := time.Now()
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
	elapsed := time.Since(start)

	if total := store.lenEntries(); total > defaultMaxRateLimitBuckets {
		t.Fatalf("store.lenEntries() = %d, exceeds hard cap %d", total, defaultMaxRateLimitBuckets)
	}
	if elapsed > 2*time.Second {
		t.Fatalf("16,000 sharded O(1) LRU operations took %v, expected well under 2s", elapsed)
	}

	// Verify maxEntries <= 0 defaults to defaultMaxRateLimitBuckets and uneven maxEntries distributes remainder across shards.
	defaultCapStore := newKeyedLimiterStoreWithOptions(10, 5, 0, time.Minute, time.Now)
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

	// Fill all maxConcurrentRateLimitWaits slots and verify the next request fails fast with 429.
	entered := make(chan struct{}, maxConcurrentRateLimitWaits)
	release := make(chan struct{})
	done := make(chan struct{}, maxConcurrentRateLimitWaits)

	mw := throttlingMiddleware(stubLimiter{
		allow: func() bool { return false },
		wait: func(ctx context.Context) error {
			entered <- struct{}{}
			<-release
			return nil
		},
	}, time.Second, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	for i := 0; i < maxConcurrentRateLimitWaits; i++ {
		go func() {
			mw.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/scim/v2/Users", nil))
			done <- struct{}{}
		}()
	}
	for i := 0; i < maxConcurrentRateLimitWaits; i++ {
		<-entered
	}

	overflowRec := httptest.NewRecorder()
	mw.ServeHTTP(overflowRec, httptest.NewRequest(http.MethodGet, "/scim/v2/Users", nil))
	if overflowRec.Code != http.StatusTooManyRequests {
		t.Fatalf("overflow waiter status = %d, want 429", overflowRec.Code)
	}

	close(release)
	for i := 0; i < maxConcurrentRateLimitWaits; i++ {
		<-done
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
