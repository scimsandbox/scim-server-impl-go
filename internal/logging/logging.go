package logging

import (
	"fmt"
	"time"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

func NewLogger(config Config) Logger {
	writer := defaultWriter(config.Writer)

	encoderConfig := zap.NewProductionEncoderConfig()
	encoderConfig.TimeKey = "time"
	encoderConfig.EncodeTime = zapcore.RFC3339TimeEncoder

	core := zapcore.NewCore(
		zapcore.NewJSONEncoder(encoderConfig),
		zapcore.AddSync(writer),
		levelFromConfig(config.Level),
	)

	return structuredLogger{logger: zap.New(core)}
}

func String(key, value string) Field {
	return Field{kind: fieldString, key: key, value: value}
}

func Int(key string, value int) Field {
	return Field{kind: fieldInt, key: key, value: value}
}

func Int64(key string, value int64) Field {
	return Field{kind: fieldInt64, key: key, value: value}
}

func Uint64(key string, value uint64) Field {
	return Field{kind: fieldUint64, key: key, value: value}
}

func Bool(key string, value bool) Field {
	return Field{kind: fieldBool, key: key, value: value}
}

func Duration(key string, value time.Duration) Field {
	return Field{kind: fieldDuration, key: key, value: value}
}

func Time(key string, value time.Time) Field {
	return Field{kind: fieldTime, key: key, value: value}
}

func Strings(key string, value []string) Field {
	return Field{kind: fieldStrings, key: key, value: value}
}

func Stringer(key string, value fmt.Stringer) Field {
	return Field{kind: fieldStringer, key: key, value: value}
}

func Error(err error) Field {
	return Field{kind: fieldError, key: "error", value: err}
}

func Float64(key string, value float64) Field {
	return Field{kind: fieldFloat64, key: key, value: value}
}

func Any(key string, value any) Field {
	return Field{kind: fieldAny, key: key, value: value}
}
