package logging

import (
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

type structuredLogger struct {
	logger *zap.Logger
}

func (l structuredLogger) Debug(msg string, fields ...Field) {
	l.logger.Debug(msg, toFields(fields)...)
}

func (l structuredLogger) Info(msg string, fields ...Field) {
	l.logger.Info(msg, toFields(fields)...)
}

func (l structuredLogger) Warn(msg string, fields ...Field) {
	l.logger.Warn(msg, toFields(fields)...)
}

func (l structuredLogger) Error(msg string, fields ...Field) {
	l.logger.Error(msg, toFields(fields)...)
}

func (l structuredLogger) With(fields ...Field) Logger {
	return structuredLogger{logger: l.logger.With(toFields(fields)...)}
}

func (l structuredLogger) Flush() error {
	return l.logger.Sync()
}

func levelFromConfig(level Level) zapcore.Level {
	switch normalizeLevel(level) {
	case DebugLevel:
		return zapcore.DebugLevel
	case WarnLevel:
		return zapcore.WarnLevel
	case ErrorLevel:
		return zapcore.ErrorLevel
	case InfoLevel:
		return zapcore.InfoLevel
	default:
		return zapcore.InfoLevel
	}
}

func normalizeLevel(level Level) Level {
	switch strings.ToLower(strings.TrimSpace(string(level))) {
	case string(DebugLevel):
		return DebugLevel
	case string(WarnLevel):
		return WarnLevel
	case string(ErrorLevel):
		return ErrorLevel
	case "", string(InfoLevel):
		return InfoLevel
	default:
		return InfoLevel
	}
}

func toFields(fields []Field) []zap.Field {
	if len(fields) == 0 {
		return nil
	}

	result := make([]zap.Field, 0, len(fields))
	for _, field := range fields {
		zapField, ok := field.toField()
		if !ok {
			continue
		}
		result = append(result, zapField)
	}

	return result
}

func (field Field) toField() (zap.Field, bool) {
	switch field.kind {
	case fieldAny:
		if field.value == nil {
			return zap.Skip(), false
		}
		return zap.Any(field.key, field.value), true
	case fieldString:
		if field.value == nil {
			return zap.Skip(), false
		}
		return zap.String(field.key, field.value.(string)), true
	case fieldInt:
		return zap.Int(field.key, field.value.(int)), true
	case fieldInt64:
		return zap.Int64(field.key, field.value.(int64)), true
	case fieldUint64:
		return zap.Uint64(field.key, field.value.(uint64)), true
	case fieldBool:
		return zap.Bool(field.key, field.value.(bool)), true
	case fieldDuration:
		return zap.Duration(field.key, field.value.(time.Duration)), true
	case fieldTime:
		return zap.Time(field.key, field.value.(time.Time)), true
	case fieldStrings:
		return zap.Strings(field.key, field.value.([]string)), true
	case fieldStringer:
		if field.value == nil {
			return zap.Skip(), false
		}
		return zap.Stringer(field.key, field.value.(fmt.Stringer)), true
	case fieldError:
		if field.value == nil {
			return zap.Skip(), false
		}
		return zap.Error(field.value.(error)), true
	case fieldFloat64:
		return zap.Float64(field.key, field.value.(float64)), true
	case fieldUnset:
		return zap.Skip(), false
	default:
		return zap.Skip(), false
	}
}

func defaultWriter(writer io.Writer) io.Writer {
	if writer != nil {
		return writer
	}
	return os.Stderr
}
