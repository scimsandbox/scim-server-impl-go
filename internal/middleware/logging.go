package middleware

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"net/http"
	"regexp"
	"time"

	"github.com/google/uuid"
	"github.com/scimsandbox/scim-server-impl-go/internal/model"
	"github.com/scimsandbox/scim-server-impl-go/internal/repository"
)

const maxBodyLog = 20000

var wsRegex = regexp.MustCompile(`/ws/([0-9a-fA-F-]{36})/`)

// ResponseCapture wraps http.ResponseWriter to capture status and body.
type ResponseCapture struct {
	http.ResponseWriter
	statusCode int
	body       bytes.Buffer
}

func (rc *ResponseCapture) WriteHeader(code int) {
	rc.statusCode = code
	rc.ResponseWriter.WriteHeader(code)
}

func (rc *ResponseCapture) Write(b []byte) (int, error) {
	rc.body.Write(b)
	return rc.ResponseWriter.Write(b)
}

// RequestResponseLogging logs SCIM request/response bodies to the database.
func RequestResponseLogging(logRepo *repository.RequestLogRepository) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Read and buffer request body
			var reqBody []byte
			if r.Body != nil {
				reqBody, _ = io.ReadAll(r.Body)
				r.Body = io.NopCloser(bytes.NewReader(reqBody))
			}

			rc := &ResponseCapture{ResponseWriter: w, statusCode: http.StatusOK}
			start := time.Now()
			next.ServeHTTP(rc, r)
			duration := time.Since(start)

			// Extract workspace ID from path
			var workspaceID uuid.UUID
			if matches := wsRegex.FindStringSubmatch(r.URL.Path); len(matches) > 1 {
				if id, err := uuid.Parse(matches[1]); err == nil {
					workspaceID = id
				}
			}

			reqBodyStr := truncate(string(reqBody), maxBodyLog)
			respBodyStr := truncate(rc.body.String(), maxBodyLog)

			log := &model.ScimRequestLog{
				ID:           uuid.New(),
				WorkspaceID:  workspaceID,
				HttpMethod:   r.Method,
				RequestPath:  r.URL.RequestURI(),
				RequestBody:  ptrOrNil(reqBodyStr),
				ResponseBody: ptrOrNil(respBodyStr),
				HttpStatus:   rc.statusCode,
				CreatedAt:    time.Now(),
			}

			_ = duration // duration tracked but not stored in current schema

			if err := logRepo.Create(context.Background(), log); err != nil {
				slog.Error("failed to save request log", "error", err)
			}
		})
	}
}

func truncate(s string, max int) string {
	if len(s) > max {
		return s[:max] + "...[truncated]"
	}
	return s
}

func ptrOrNil(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}
