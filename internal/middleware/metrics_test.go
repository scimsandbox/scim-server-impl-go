package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
)

func TestMetricsUseScimGoPrefix(t *testing.T) {
	t.Parallel()

	scimOpCounter.WithLabelValues("listUsers", "users", "list", "workspace-1", "alice@example.com", "200", "success", AuthenticationOK, ThrottledNo).Inc()
	scimOpDuration.WithLabelValues("listUsers", "users", "list", "workspace-1", "alice@example.com", "200", "success", AuthenticationOK, ThrottledNo).Observe(0.01)

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
	counter := scimOpCounter.WithLabelValues("getGroup", "groups", "get", "123e4567-e89b-12d3-a456-426614174000", "unknown", "401", "client_error", AuthenticationFailed, ThrottledNo)
	before := testutil.ToFloat64(counter)

	handler := ScimMetrics(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		MarkAuthentication(r, AuthenticationFailed)
		MarkWorkspaceID(r, "123e4567-e89b-12d3-a456-426614174000")
		w.WriteHeader(http.StatusUnauthorized)
	}))

	req := httptest.NewRequest(http.MethodGet, "/ws/123e4567-e89b-12d3-a456-426614174000/scim/v2/Groups/123", nil)
	rw := httptest.NewRecorder()
	handler.ServeHTTP(rw, req)

	after := testutil.ToFloat64(counter)
	if after-before != 1 {
		t.Fatalf("counter delta = %v, want 1", after-before)
	}
}
