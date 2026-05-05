package logging

import (
	"bytes"
	stdjson "encoding/json"
	"errors"
	"testing"
)

const flushErrorMessage = "Flush() error = %v"

func TestLoggerEmitsStructuredJSON(t *testing.T) {
	t.Parallel()

	var buffer bytes.Buffer
	logger := NewLogger(Config{Writer: &buffer, Level: DebugLevel})

	logger.Info("configuration loaded",
		String("service", "scim-server-api-go"),
		Int("port", 8080),
		Bool("enabled", true),
		Any("meta", map[string]any{"environment": "test"}),
		Error(errors.New("boom")),
	)
	if err := logger.Flush(); err != nil {
		t.Fatalf(flushErrorMessage, err)
	}

	record := decodeLogRecord(t, buffer.Bytes())
	assertStringField(t, record, "level", "info")
	assertStringField(t, record, "msg", "configuration loaded")
	assertStringField(t, record, "service", "scim-server-api-go")
	assertNumberField(t, record, "port", 8080)
	assertBoolField(t, record, "enabled", true)
	assertStringField(t, record, "error", "boom")

	meta, ok := record["meta"].(map[string]any)
	if !ok {
		t.Fatalf("meta field type = %T, want map[string]any", record["meta"])
	}
	if got := meta["environment"]; got != "test" {
		t.Fatalf("meta.environment = %v, want %q", got, "test")
	}
}

func TestLoggerWithPropagatesContext(t *testing.T) {
	t.Parallel()

	var buffer bytes.Buffer
	logger := NewLogger(Config{Writer: &buffer, Level: DebugLevel})
	child := logger.With(String("component", "bootstrap"))

	child.Warn("starting", Int64("attempt", 2), Float64("ratio", 0.5), Strings("tags", []string{"config", "logging"}))
	if err := child.Flush(); err != nil {
		t.Fatalf(flushErrorMessage, err)
	}

	record := decodeLogRecord(t, buffer.Bytes())
	assertStringField(t, record, "level", "warn")
	assertStringField(t, record, "msg", "starting")
	assertStringField(t, record, "component", "bootstrap")
	assertNumberField(t, record, "attempt", 2)
	assertFloatField(t, record, "ratio", 0.5)

	tags, ok := record["tags"].([]any)
	if !ok {
		t.Fatalf("tags field type = %T, want []any", record["tags"])
	}
	if len(tags) != 2 || tags[0] != "config" || tags[1] != "logging" {
		t.Fatalf("tags field = %#v, want [config logging]", tags)
	}
}

func TestLoggerHonorsLevelConfiguration(t *testing.T) {
	t.Parallel()

	var buffer bytes.Buffer
	logger := NewLogger(Config{Writer: &buffer})
	logger.Debug("suppressed")
	if buffer.Len() != 0 {
		t.Fatalf("buffer length = %d, want 0", buffer.Len())
	}

	debugLogger := NewLogger(Config{Writer: &buffer, Level: DebugLevel})
	debugLogger.Debug("visible")
	if err := debugLogger.Flush(); err != nil {
		t.Fatalf(flushErrorMessage, err)
	}

	record := decodeLogRecord(t, buffer.Bytes())
	assertStringField(t, record, "level", "debug")
	assertStringField(t, record, "msg", "visible")
}

func decodeLogRecord(t *testing.T, data []byte) map[string]any {
	t.Helper()

	trimmed := bytes.TrimSpace(data)
	if len(trimmed) == 0 {
		t.Fatal("log output is empty")
	}

	var record map[string]any
	if err := stdjson.Unmarshal(trimmed, &record); err != nil {
		t.Fatalf("Unmarshal() error = %v", err)
	}
	return record
}

func assertStringField(t *testing.T, record map[string]any, key, want string) {
	t.Helper()

	got, ok := record[key].(string)
	if !ok {
		t.Fatalf("%s field type = %T, want string", key, record[key])
	}
	if got != want {
		t.Fatalf("%s field = %q, want %q", key, got, want)
	}
}

func assertNumberField(t *testing.T, record map[string]any, key string, want int) {
	t.Helper()

	got, ok := record[key].(float64)
	if !ok {
		t.Fatalf("%s field type = %T, want float64", key, record[key])
	}
	if int(got) != want {
		t.Fatalf("%s field = %v, want %d", key, got, want)
	}
}

func assertFloatField(t *testing.T, record map[string]any, key string, want float64) {
	t.Helper()

	got, ok := record[key].(float64)
	if !ok {
		t.Fatalf("%s field type = %T, want float64", key, record[key])
	}
	if got != want {
		t.Fatalf("%s field = %v, want %v", key, got, want)
	}
}

func assertBoolField(t *testing.T, record map[string]any, key string, want bool) {
	t.Helper()

	got, ok := record[key].(bool)
	if !ok {
		t.Fatalf("%s field type = %T, want bool", key, record[key])
	}
	if got != want {
		t.Fatalf("%s field = %v, want %v", key, got, want)
	}
}
