package middleware

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/scimsandbox/scim-server-impl-go/internal/model"
)

const (
	maxBodyLog     = 20000
	maxBodyCapture = maxBodyLog + 1024
	redactedValue  = "[REDACTED]"
)

var (
	wsRegex = regexp.MustCompile(`/ws/([0-9a-fA-F-]{36})/`)
	// Matches JSON-like key/value pairs whose key is "password" or ends with ":password" (case-insensitive),
	// with a complete quoted string value (handling escaped quotes).
	passwordJSONStringRe = regexp.MustCompile(`(?i)("(?:\s*(?:urn:[^"]*:)?password)"\s*:\s*)"(?:\\.|[^"\\])*"`)
	// Matches truncated JSON-like password string values at the end of a malformed/cut payload.
	passwordJSONTruncatedRe = regexp.MustCompile(`(?i)("(?:\s*(?:urn:[^"]*:)?password)"\s*:\s*)"(?:\\.|[^"\\])*$`)
	// Matches JSON-like "authorization" header/token fields and Bearer token strings.
	authJSONStringRe    = regexp.MustCompile(`(?i)("\s*authorization\s*"\s*:\s*)"(?:\\.|[^"\\])*"`)
	authJSONTruncatedRe = regexp.MustCompile(`(?i)("\s*authorization\s*"\s*:\s*)"(?:\\.|[^"\\])*$`)
	bearerTokenRe       = regexp.MustCompile(`(?i)\b(Bearer(?:\s|\\[tnr])+)[A-Za-z0-9._~+/=-]+`)
	// Matches malformed/non-JSON PATCH fragments where "path":"password" precedes or follows "value":"..."
	// within the same JSON object (allowing intervening fields such as "op":"replace" and truncated trailing values).
	patchPathThenValueRe          = regexp.MustCompile(`(?is)("path"\s*:\s*"\s*(?:urn:ietf:params:scim:schemas:core:2\.0:User:)?password\s*"[^{}]*?"value"\s*:\s*)"(?:\\.|[^"\\])*"`)
	patchPathThenValueTruncatedRe = regexp.MustCompile(`(?is)("path"\s*:\s*"\s*(?:urn:ietf:params:scim:schemas:core:2\.0:User:)?password\s*"[^{}]*?"value"\s*:\s*)"(?:\\.|[^"\\])*$`)
	patchValueThenPathRe          = regexp.MustCompile(`(?is)("value"\s*:\s*)"(?:\\.|[^"\\])*"([^{}]*?"path"\s*:\s*"\s*(?:urn:ietf:params:scim:schemas:core:2\.0:User:)?password\s*")`)
)

type requestLogCreator interface {
	Create(ctx context.Context, log *model.ScimRequestLog) error
}

type bodyCaptureReader struct {
	rc  io.ReadCloser
	buf bytes.Buffer
	eof bool
}

func (b *bodyCaptureReader) Read(p []byte) (int, error) {
	n, err := b.rc.Read(p)
	if n > 0 && b.buf.Len() < maxBodyCapture {
		rem := maxBodyCapture - b.buf.Len()
		if n < rem {
			rem = n
		}
		b.buf.Write(p[:rem])
	}
	if err == io.EOF {
		b.eof = true
	}
	return n, err
}

func (b *bodyCaptureReader) Close() error {
	return b.rc.Close()
}

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
	if rc.body.Len() < maxBodyCapture {
		rem := maxBodyCapture - rc.body.Len()
		if len(b) < rem {
			rem = len(b)
		}
		rc.body.Write(b[:rem])
	}
	return rc.ResponseWriter.Write(b)
}

// RequestResponseLogging logs SCIM request/response bodies to the database,
// redacting sensitive credential values before persistence without mutating r.Body.
func RequestResponseLogging(logRepo requestLogCreator) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			var bcr *bodyCaptureReader
			if r.Body != nil {
				bcr = &bodyCaptureReader{rc: r.Body}
				r.Body = bcr
			}

			rc := &ResponseCapture{ResponseWriter: w, statusCode: http.StatusOK}
			start := time.Now()
			next.ServeHTTP(rc, r)
			duration := time.Since(start)

			var reqBody []byte
			if bcr != nil {
				if !bcr.eof && bcr.buf.Len() < maxBodyCapture && rc.statusCode != http.StatusRequestEntityTooLarge {
					rem := maxBodyCapture - bcr.buf.Len()
					_, _ = io.CopyN(&bcr.buf, bcr.rc, int64(rem))
				}
				reqBody = bcr.buf.Bytes()
			}

			// Extract workspace ID from path
			var workspaceID uuid.UUID
			if matches := wsRegex.FindStringSubmatch(r.URL.Path); len(matches) > 1 {
				if id, err := uuid.Parse(matches[1]); err == nil {
					workspaceID = id
				}
			}

			reqBodyStr := redactRegexFallback(truncate(RedactSensitiveBody(string(reqBody)), maxBodyLog))
			respBodyStr := redactRegexFallback(truncate(RedactSensitiveBody(rc.body.String()), maxBodyLog))

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

			if logRepo != nil {
				if err := logRepo.Create(context.Background(), log); err != nil {
					slog.Error("failed to save request log", "error", err)
				}
			}
		})
	}
}

// RedactSensitiveBody recursively redacts password values across JSON objects, PATCH operations,
// and Bulk request/response payloads, falling back to regex redaction on invalid/truncated JSON.
func RedactSensitiveBody(raw string) string {
	if strings.TrimSpace(raw) == "" {
		return raw
	}
	lowerRaw := strings.ToLower(raw)
	if !strings.Contains(lowerRaw, "password") &&
		!strings.Contains(lowerRaw, "authorization") &&
		!strings.Contains(lowerRaw, "bearer") &&
		!strings.Contains(lowerRaw, `\u`) {
		return raw
	}

	var parsed any
	dec := json.NewDecoder(strings.NewReader(raw))
	dec.UseNumber()
	if err := dec.Decode(&parsed); err != nil {
		return redactRegexFallback(raw)
	}
	// Ensure no trailing non-whitespace tokens exist after first JSON value.
	var trailing any
	if err := dec.Decode(&trailing); err != io.EOF {
		return redactRegexFallback(raw)
	}

	redacted, changed := redactValue(parsed)
	if !changed {
		return redactRegexFallback(raw)
	}

	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(redacted); err != nil {
		return redactRegexFallback(raw)
	}
	out := strings.TrimSuffix(buf.String(), "\n")
	return redactRegexFallback(out)
}

func redactValue(v any) (any, bool) {
	switch val := v.(type) {
	case map[string]any:
		changed := false
		out := make(map[string]any, len(val))
		var patchPath string
		for k, sub := range val {
			if strings.EqualFold(strings.TrimSpace(k), "path") {
				if ps, ok := sub.(string); ok {
					patchPath = ps
				}
			}
		}
		isPwPatch := isPasswordPatchPath(patchPath)

		for k, sub := range val {
			if isPasswordKey(k) {
				if sub != nil {
					out[k] = redactedValue
					changed = true
				} else {
					out[k] = nil
				}
				continue
			}
			if isPwPatch && strings.EqualFold(strings.TrimSpace(k), "value") {
				if sub != nil {
					out[k] = redactedValue
					changed = true
				} else {
					out[k] = nil
				}
				continue
			}
			nextSub, subChanged := redactValue(sub)
			if subChanged {
				changed = true
			}
			out[k] = nextSub
		}
		return out, changed

	case []any:
		changed := false
		out := make([]any, len(val))
		for i, elem := range val {
			nextElem, elemChanged := redactValue(elem)
			if elemChanged {
				changed = true
			}
			out[i] = nextElem
		}
		return out, changed

	case string:
		if strings.Contains(strings.ToLower(val), "bearer") && bearerTokenRe.MatchString(val) {
			return bearerTokenRe.ReplaceAllString(val, "${1}"+redactedValue), true
		}
		return val, false

	default:
		return v, false
	}
}

func isPasswordKey(key string) bool {
	lk := strings.ToLower(strings.TrimSpace(key))
	return lk == "password" || strings.HasSuffix(lk, ":password") || lk == "authorization"
}

func isPasswordPatchPath(path string) bool {
	lp := strings.ToLower(strings.TrimSpace(path))
	return lp == "password" || lp == "urn:ietf:params:scim:schemas:core:2.0:user:password"
}

func redactRegexFallback(s string) string {
	if s == "" {
		return s
	}
	norm := decodeASCIIUnicodeEscapes(s)
	lower := strings.ToLower(norm)
	if !strings.Contains(lower, "password") && !strings.Contains(lower, "authorization") && !strings.Contains(lower, "bearer") {
		return s
	}
	redacted := norm
	if strings.Contains(lower, "password") {
		redacted = passwordJSONStringRe.ReplaceAllString(redacted, `${1}"[REDACTED]"`)
		redacted = patchPathThenValueRe.ReplaceAllString(redacted, `${1}"[REDACTED]"`)
		redacted = patchValueThenPathRe.ReplaceAllString(redacted, `${1}"[REDACTED]"${2}`)
		redacted = patchPathThenValueTruncatedRe.ReplaceAllString(redacted, `${1}"[REDACTED]"`)
		redacted = passwordJSONTruncatedRe.ReplaceAllString(redacted, `${1}"[REDACTED]"`)
	}
	if strings.Contains(lower, "authorization") {
		redacted = authJSONStringRe.ReplaceAllString(redacted, `${1}"[REDACTED]"`)
		redacted = authJSONTruncatedRe.ReplaceAllString(redacted, `${1}"[REDACTED]"`)
	}
	if strings.Contains(lower, "bearer") {
		redacted = bearerTokenRe.ReplaceAllString(redacted, `${1}[REDACTED]`)
	}
	if redacted == norm {
		return s
	}
	return redacted
}

// decodeASCIIUnicodeEscapes normalizes JSON \u00XX ASCII escapes (excluding '"' and '\'
// so quote boundaries stay intact) to allow regex fallback redaction on malformed/truncated payloads.
func decodeASCIIUnicodeEscapes(s string) string {
	if !strings.Contains(s, `\u`) && !strings.Contains(s, `\U`) {
		return s
	}
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' && i+1 < len(s) && s[i+1] == '\\' {
			b.WriteString(`\\`)
			i++
			continue
		}
		if i+6 <= len(s) && s[i] == '\\' && (s[i+1] == 'u' || s[i+1] == 'U') && s[i+2] == '0' && s[i+3] == '0' {
			hi, okHi := hexNibble(s[i+4])
			lo, okLo := hexNibble(s[i+5])
			if okHi && okLo {
				ch := (hi << 4) | lo
				switch {
				case ch == '\t':
					b.WriteString(`\t`)
					i += 5
					continue
				case ch == '\n':
					b.WriteString(`\n`)
					i += 5
					continue
				case ch == '\r':
					b.WriteString(`\r`)
					i += 5
					continue
				case ch >= 0x20 && ch <= 0x7e && ch != '"' && ch != '\\':
					b.WriteByte(ch)
					i += 5
					continue
				}
			}
		}
		b.WriteByte(s[i])
	}
	return b.String()
}

func hexNibble(c byte) (byte, bool) {
	switch {
	case c >= '0' && c <= '9':
		return c - '0', true
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10, true
	case c >= 'A' && c <= 'F':
		return c - 'A' + 10, true
	default:
		return 0, false
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
