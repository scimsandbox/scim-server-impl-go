// Package logging provides structured JSON logging built on top of zap.
//
// Create a logger with NewLogger:
//
//	logger := logging.NewLogger(logging.Config{Writer: os.Stderr, Level: logging.InfoLevel})
//	logger.Info("server started", logging.String("addr", ":8080"))
//
// The logger writes RFC 3339 timestamped JSON lines.
package logging
