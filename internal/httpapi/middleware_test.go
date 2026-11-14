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

func TestThrottlingMiddleware_PerWorkspaceIsolationAndNoManagementBypass(t *testing.T) {
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

	wsAPaths := []string{
		"/ws/123e4567-e89b-12d3-a456-426614174000/scim/v2/Users",
		"/ws/123E4567-E89B-12D3-A456-426614174000/scim/v2/Users",
		"/ws/123e4567-e89b-12d3-a456-426614174000/scim/v2/Groups",
	}
	// First 3 requests for Workspace A (including uppercase UUID normalization) succeed within burst=3.
	for i, p := range wsAPaths {
		rw := httptest.NewRecorder()
		handler.ServeHTTP(rw, httptest.NewRequest(http.MethodGet, p, nil))
		if rw.Code != http.StatusOK {
			t.Fatalf("workspace A burst request %d status = %d, want 200", i+1, rw.Code)
		}
	}

	// 4th request to Workspace A fails fast (WaitTimeout=0) with 429 SCIM Error and Retry-After: 1.
	start := time.Now()
	rw := httptest.NewRecorder()
	handler.ServeHTTP(rw, httptest.NewRequest(http.MethodGet, wsAPaths[0], nil))
	if elapsed := time.Since(start); elapsed > 100*time.Millisecond {
		t.Fatalf("fail-fast 429 took %v, expected immediate response", elapsed)
	}
	if rw.Code != http.StatusTooManyRequests {
		t.Fatalf("workspace A 4th request status = %d, want 429", rw.Code)
	}
	if got := rw.Header().Get("Retry-After"); got != "1" {
		t.Fatalf("Retry-After = %q, want 1", got)
	}

	// Workspace B has its own independent bucket and still gets 200 OK while Workspace A is throttled.
	wsBPath := "/ws/223e4567-e89b-12d3-a456-426614174001/scim/v2/Users"
	for i := 0; i < 3; i++ {
		wsBRec := httptest.NewRecorder()
		handler.ServeHTTP(wsBRec, httptest.NewRequest(http.MethodGet, wsBPath, nil))
		if wsBRec.Code != http.StatusOK {
			t.Fatalf("workspace B request %d status = %d, want 200", i+1, wsBRec.Code)
		}
	}

	// /actuator/* and /metrics on the API router do NOT bypass rate limiting; they fall back to client IP.
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

	if got := extractRateLimitKey(nil); got != "global" {
		t.Fatalf("extractRateLimitKey(nil) = %q, want global", got)
	}

	emptyAddrReq := httptest.NewRequest(http.MethodGet, "/scim/v2/Users", nil)
	emptyAddrReq.RemoteAddr = "   "
	if got := extractRateLimitKey(emptyAddrReq); got != "global" {
		t.Fatalf("extractRateLimitKey(empty RemoteAddr) = %q, want global", got)
	}

	rawAddrReq := httptest.NewRequest(http.MethodGet, "/ws/invalid-ws/scim/v2/Users", nil)
	rawAddrReq.RemoteAddr = "203.0.113.7"
	if got := extractRateLimitKey(rawAddrReq); got != "ip:203.0.113.7" {
		t.Fatalf("extractRateLimitKey(raw IP) = %q, want ip:203.0.113.7", got)
	}

	ipv6Req := httptest.NewRequest(http.MethodGet, "/scim/v2/Users", nil)
	ipv6Req.RemoteAddr = "[2001:db8::1]:44321"
	if got := extractRateLimitKey(ipv6Req); got != "ip:2001:db8::1" {
		t.Fatalf("extractRateLimitKey(IPv6) = %q, want ip:2001:db8::1", got)
	}

	wsReq := httptest.NewRequest(http.MethodGet, "/ws/ABCDEF01-2345-6789-ABCD-EF0123456789/scim/v2/Users", nil)
	if got := extractRateLimitKey(wsReq); got != "ws:abcdef01-2345-6789-abcd-ef0123456789" {
		t.Fatalf("extractRateLimitKey(ws) = %q, want canonical lowercase ws key", got)
	}

	// Verify TTL expiration and hard maxEntries capacity eviction.
	now := time.Date(2026, 11, 13, 12, 0, 0, 0, time.UTC)
	store := newKeyedLimiterStoreWithOptions(1, 1, 3, 5*time.Minute, time.Minute, func() time.Time {
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

	if len(store.entries) != 3 {
		t.Fatalf("len(entries) = %d, want 3", len(store.entries))
	}

	// Touch 10.0.0.1 so 10.0.0.2 becomes the oldest entry.
	now = now.Add(10 * time.Second)
	if got := store.LimiterFor(reqForIP("10.0.0.1")); got != lim1 {
		t.Fatal("expected existing non-expired limiter for 10.0.0.1")
	}

	// Inserting 10.0.0.4 at capacity=3 must evict oldest (ip:10.0.0.2) and keep size <= 3.
	now = now.Add(10 * time.Second)
	_ = store.LimiterFor(reqForIP("10.0.0.4"))
	if len(store.entries) != 3 {
		t.Fatalf("len(entries) after capacity eviction = %d, want 3", len(store.entries))
	}
	if _, exists := store.entries["ip:10.0.0.2"]; exists {
		t.Fatal("expected oldest entry ip:10.0.0.2 to be evicted")
	}

	// Advance past TTL for ip:10.0.0.3 (seen at +20s; at +5m25s it is >5m old, while 10.0.0.1 at +30s & 10.0.0.4 at +40s are <5m old).
	now = time.Date(2026, 11, 13, 12, 5, 25, 0, time.UTC)
	_ = store.LimiterFor(reqForIP("10.0.0.5"))
	if len(store.entries) != 3 {
		t.Fatalf("len(entries) after expired sweep = %d, want 3", len(store.entries))
	}
	if _, exists := store.entries["ip:10.0.0.3"]; exists {
		t.Fatal("expected expired entry ip:10.0.0.3 to be swept before evicting active entries")
	}
	if _, exists := store.entries["ip:10.0.0.1"]; !exists {
		t.Fatal("expected active entry ip:10.0.0.1 to remain in store")
	}

	// Advance past TTL without triggering sweepPeriod (< 1m since lastSweep), then access an expired key directly.
	now = now.Add(30 * time.Second) // 12:05:55 -> ip:10.0.0.1 (lastSeen 12:00:30) is expired (>5m), sweepPeriod (1m from 12:05:25) not reached
	lim1Fresh := store.LimiterFor(reqForIP("10.0.0.1"))
	if lim1Fresh == lim1 {
		t.Fatal("expected direct lookup of expired entry to allocate a fresh limiter")
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
