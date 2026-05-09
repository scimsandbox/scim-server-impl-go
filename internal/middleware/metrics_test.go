package middleware

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/prometheus/client_golang/prometheus/testutil"
)

func TestMetricsUseScimGoPrefix(t *testing.T) {
	t.Parallel()

	scimOpCounter.WithLabelValues("listUsers", "200").Inc()
	scimOpDuration.WithLabelValues("listUsers", "200").Observe(0.01)
	scimAuthCounter.WithLabelValues(AuthenticationOK).Inc()
	scimThrottledCounter.WithLabelValues(ThrottledNo).Inc()

	metricFamilies, err := prometheus.DefaultGatherer.Gather()
	if err != nil {
		t.Fatalf("Gather() error = %v", err)
	}

	present := make(map[string]bool, len(metricFamilies))
	for _, family := range metricFamilies {
		present[family.GetName()] = true
	}

	for _, metricName := range []string{
		"scim_go_operation_requests_total",
		"scim_go_operation_duration_seconds",
		"scim_go_operation_authentication_total",
		"scim_go_operation_throttled_total",
		"go_goroutines",
		"go_memstats_alloc_bytes",
		"process_cpu_seconds_total",
		"process_resident_memory_bytes",
	} {
		if !present[metricName] {
			t.Fatalf("metric %q not found in default gatherer", metricName)
		}
	}

	for _, oldMetricName := range []string{
		"scim_operation_requests_total",
		"scim_operation_duration_seconds",
	} {
		if present[oldMetricName] {
			t.Fatalf("old metric %q is still registered", oldMetricName)
		}
	}
}

func TestScimMetrics_RecordsAuthenticationFailureLabels(t *testing.T) {
	counter := scimOpCounter.WithLabelValues("getGroup", "401")
	before := testutil.ToFloat64(counter)
	authCounter := scimAuthCounter.WithLabelValues(AuthenticationFailed)
	authBefore := testutil.ToFloat64(authCounter)
	throttledCounter := scimThrottledCounter.WithLabelValues(ThrottledNo)
	throttledBefore := testutil.ToFloat64(throttledCounter)

	handler := ScimMetrics(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		MarkAuthentication(r, AuthenticationFailed)
		w.WriteHeader(http.StatusUnauthorized)
	}))

	req := httptest.NewRequest(http.MethodGet, "/ws/123e4567-e89b-12d3-a456-426614174000/scim/v2/Groups/123", nil)
	rw := httptest.NewRecorder()
	handler.ServeHTTP(rw, req)

	after := testutil.ToFloat64(counter)
	if after-before != 1 {
		t.Fatalf("counter delta = %v, want 1", after-before)
	}
	if after := testutil.ToFloat64(authCounter); after-authBefore != 1 {
		t.Fatalf("auth counter delta = %v, want 1", after-authBefore)
	}
	if after := testutil.ToFloat64(throttledCounter); after-throttledBefore != 1 {
		t.Fatalf("throttled counter delta = %v, want 1", after-throttledBefore)
	}
}

func TestScimMetrics_ExposesDurationHistogramWithConfiguredBuckets(t *testing.T) {
	handler := ScimMetrics(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		MarkAuthentication(r, AuthenticationOK)
		w.WriteHeader(http.StatusCreated)
	}))

	handler.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodPost, "/ws/123e4567-e89b-12d3-a456-426614174000/scim/v2/Users", nil))

	metricsHandler := promhttp.Handler()
	rw := httptest.NewRecorder()
	metricsHandler.ServeHTTP(rw, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	scrape := rw.Body.String()

	if !containsMetricLine(scrape, "scim_go_operation_duration_seconds_count", "operation=\"createUser\"", "http_status=\"201\"") {
		t.Fatalf("scrape output did not contain expected summary count metric: %s", scrape)
	}
	if !containsMetricLine(scrape, "scim_go_operation_duration_seconds_sum", "operation=\"createUser\"", "http_status=\"201\"") {
		t.Fatalf("scrape output did not contain expected histogram sum metric: %s", scrape)
	}
	for _, bucket := range []string{"0.05", "0.1", "0.25", "0.5", "1", "+Inf"} {
		if !containsMetricLine(scrape, "scim_go_operation_duration_seconds_bucket", "operation=\"createUser\"", "http_status=\"201\"", "le=\""+bucket+"\"") {
			t.Fatalf("scrape output did not contain expected histogram bucket %s: %s", bucket, scrape)
		}
	}
	if containsMetricLine(scrape, "scim_go_operation_duration_seconds_bucket", "operation=\"createUser\"", "http_status=\"201\"", "le=\"0.075\"") {
		t.Fatalf("scrape output still contains an unexpected bucket boundary: %s", scrape)
	}
}

func containsMetricLine(scrape string, metricName string, substrings ...string) bool {
	for _, line := range strings.Split(scrape, "\n") {
		if !strings.HasPrefix(line, metricName+"{") {
			continue
		}

		matches := true
		for _, substring := range substrings {
			if !strings.Contains(line, substring) {
				matches = false
				break
			}
		}
		if matches {
			return true
		}
	}

	return false
}
