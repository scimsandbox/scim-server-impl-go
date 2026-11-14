package middleware

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"net/http"
	"regexp"
	"sort"
	"strings"
	"time"
	"unicode/utf16"
	"unicode/utf8"

	"github.com/google/uuid"
	"github.com/scimsandbox/scim-server-impl-go/internal/model"
)

const (
	maxBodyLog       = 20000
	maxBodyCapture   = maxBodyLog + 1024
	redactedValue    = "[REDACTED]"
	redactedJSONStr  = `"` + redactedValue + `"`
	minBearerTokSize = 6
	longAlphaTokSize = 20
)

var wsRegex = regexp.MustCompile(`/ws/([0-9a-fA-F-]{36})/`)

type requestLogCreator interface {
	Create(ctx context.Context, log *model.ScimRequestLog) error
}

type bodyCaptureReader struct {
	rc        io.ReadCloser
	buf       bytes.Buffer
	eof       bool
	truncated bool
}

func (b *bodyCaptureReader) Read(p []byte) (int, error) {
	n, err := b.rc.Read(p)
	if n > 0 {
		rem := maxBodyCapture - b.buf.Len()
		if rem > 0 {
			if n <= rem {
				b.buf.Write(p[:n])
			} else {
				b.buf.Write(p[:rem])
				b.truncated = true
			}
		} else {
			b.truncated = true
		}
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
	truncated  bool
}

func (rc *ResponseCapture) WriteHeader(code int) {
	rc.statusCode = code
	rc.ResponseWriter.WriteHeader(code)
}

func (rc *ResponseCapture) Write(b []byte) (int, error) {
	if len(b) > 0 {
		rem := maxBodyCapture - rc.body.Len()
		if rem > 0 {
			if len(b) <= rem {
				rc.body.Write(b)
			} else {
				rc.body.Write(b[:rem])
				rc.truncated = true
			}
		} else {
			rc.truncated = true
		}
	}
	return rc.ResponseWriter.Write(b)
}

// RequestResponseLogging logs SCIM request/response bodies to the database,
// surgically redacting sensitive credential spans before persistence without
// mutating r.Body or altering unrelated payload bytes.
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
			var reqTruncated bool
			if bcr != nil {
				if !bcr.eof && !bcr.truncated && rc.statusCode != http.StatusRequestEntityTooLarge {
					rem := maxBodyCapture - bcr.buf.Len()
					var probe [1]byte
					if rem > 0 {
						copied, copyErr := io.CopyN(&bcr.buf, bcr.rc, int64(rem))
						if copied == int64(rem) && copyErr == nil {
							if extra, _ := bcr.rc.Read(probe[:]); extra > 0 {
								bcr.truncated = true
							}
						}
					} else if extra, _ := bcr.rc.Read(probe[:]); extra > 0 {
						bcr.truncated = true
					}
				}
				reqBody = bcr.buf.Bytes()
				reqTruncated = bcr.truncated
			}

			// Extract workspace ID from path
			var workspaceID uuid.UUID
			if matches := wsRegex.FindStringSubmatch(r.URL.Path); len(matches) > 1 {
				if id, err := uuid.Parse(matches[1]); err == nil {
					workspaceID = id
				}
			}

			reqBodyStr := finalizeLoggedBody(string(reqBody), reqTruncated)
			respBodyStr := finalizeLoggedBody(rc.body.String(), rc.truncated)

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

func finalizeLoggedBody(raw string, captureTruncated bool) string {
	redacted := RedactSensitiveBody(raw)
	if len(redacted) > maxBodyLog {
		return redacted[:maxBodyLog] + "...[truncated]"
	}
	if captureTruncated {
		return redacted + "...[truncated]"
	}
	return redacted
}

type redactSpan struct {
	start       int
	end         int
	replacement string
}

type byteRange struct {
	start int
	end   int
}

type decodedJSONString struct {
	rawStart int
	rawEnd   int
	closed   bool
	decoded  string
	offsets  []byteRange
}

type parsedObjectMember struct {
	keyDecoded string
	valStart   int
	valEnd     int
	valIsNull  bool
	valStr     *decodedJSONString
	valSpans   []redactSpan
}

// RedactSensitiveBody surgically replaces sensitive password, Authorization, and
// inline Bearer credential byte spans in raw while preserving every unrelated byte
// (key ordering, whitespace, indentation, and Unicode escapes) verbatim.
func RedactSensitiveBody(raw string) string {
	if raw == "" || !hasSensitiveCandidate(raw) {
		return raw
	}

	spans := collectSensitiveSpans(raw)
	if len(spans) == 0 {
		return raw
	}

	return applyRedactSpans(raw, spans)
}

func hasSensitiveCandidate(s string) bool {
	return containsFoldASCII(s, "password") ||
		containsFoldASCII(s, "authorization") ||
		containsFoldASCII(s, "bearer") ||
		containsFoldASCII(s, "operations") ||
		containsFoldASCII(s, "value") ||
		strings.IndexByte(s, '\\') >= 0
}

func containsFoldASCII(s, needleLower string) bool {
	n := len(needleLower)
	if len(s) < n {
		return false
	}
	first := needleLower[0]
	limit := len(s) - n
	for i := 0; i <= limit; i++ {
		if asciiLower(s[i]) != first {
			continue
		}
		match := true
		for j := 1; j < n; j++ {
			if asciiLower(s[i+j]) != needleLower[j] {
				match = false
				break
			}
		}
		if match {
			return true
		}
	}
	return false
}

func asciiLower(b byte) byte {
	if b >= 'A' && b <= 'Z' {
		return b + ('a' - 'A')
	}
	return b
}

func collectSensitiveSpans(raw string) []redactSpan {
	var spans []redactSpan
	pos := 0
	for pos < len(raw) {
		pos = skipASCIIWhitespace(raw, pos)
		if pos >= len(raw) {
			break
		}

		switch raw[pos] {
		case '{', '[':
			endPos, _, subSpans, _, _ := scanJSONValue(raw, pos, false)
			spans = append(spans, subSpans...)
			pos = endPos

		case '"':
			qs := scanQuotedString(raw, pos)
			afterKey := skipASCIIWhitespace(raw, qs.rawEnd)
			if afterKey < len(raw) && raw[afterKey] == ':' && isPasswordKey(qs.decoded) {
				valStart := skipASCIIWhitespace(raw, afterKey+1)
				if valStart < len(raw) {
					valEnd, valIsNull, _, _, ok := scanJSONValue(raw, valStart, false)
					if ok {
						if !valIsNull && valEnd > valStart {
							spans = append(spans, redactSpan{
								start:       valStart,
								end:         valEnd,
								replacement: redactedJSONStr,
							})
						}
						pos = valEnd
						continue
					}
				}
			}
			spans = append(spans, findBearerSpansInDecodedString(qs)...)
			pos = qs.rawEnd

		default:
			segEnd := pos + 1
			for segEnd < len(raw) && raw[segEnd] != '{' && raw[segEnd] != '[' && raw[segEnd] != '"' {
				segEnd++
			}
			spans = append(spans, findBearerSpansInRawText(raw, pos, segEnd)...)
			pos = segEnd
		}
	}
	return spans
}

func scanJSONValue(
	raw string,
	pos int,
	inOperationsArray bool,
) (endPos int, isNull bool, spans []redactSpan, strVal *decodedJSONString, ok bool) {
	pos = skipASCIIWhitespace(raw, pos)
	if pos >= len(raw) {
		return pos, false, nil, nil, false
	}

	switch raw[pos] {
	case '"':
		qs := scanQuotedString(raw, pos)
		return qs.rawEnd, false, findBearerSpansInDecodedString(qs), &qs, true

	case '{':
		endIdx, objSpans := scanJSONObject(raw, pos, inOperationsArray)
		return endIdx, false, objSpans, nil, true

	case '[':
		endIdx, arrSpans := scanJSONArray(raw, pos, inOperationsArray)
		return endIdx, false, arrSpans, nil, true

	case '}', ']', ',', ':':
		return pos, false, nil, nil, false

	default:
		endIdx := pos
		for endIdx < len(raw) && !isASCIIWhitespace(raw[endIdx]) && !isJSONStructural(raw[endIdx]) {
			endIdx++
		}
		prim := raw[pos:endIdx]
		return endIdx, prim == "null", findBearerSpansInRawText(raw, pos, endIdx), nil, endIdx > pos
	}
}

func scanJSONObject(raw string, openBracePos int, inOperationsArray bool) (int, []redactSpan) {
	var members []parsedObjectMember
	var extraSpans []redactSpan

	i := openBracePos + 1
	closedByBrace := false
	for i < len(raw) {
		i = skipWhitespaceAndCommas(raw, i)
		if i >= len(raw) {
			break
		}
		if raw[i] == '}' {
			closedByBrace = true
			i++
			break
		}

		if raw[i] != '"' {
			if raw[i] == '{' || raw[i] == '[' {
				subEnd, _, subSpans, _, _ := scanJSONValue(raw, i, false)
				extraSpans = append(extraSpans, subSpans...)
				i = subEnd
				continue
			}
			segStart := i
			for i < len(raw) && raw[i] != ',' && raw[i] != '}' && raw[i] != '"' && raw[i] != '{' && raw[i] != '[' {
				i++
			}
			extraSpans = append(extraSpans, findBearerSpansInRawText(raw, segStart, i)...)
			continue
		}

		keyQS := scanQuotedString(raw, i)
		afterKey := skipASCIIWhitespace(raw, keyQS.rawEnd)
		if afterKey >= len(raw) || raw[afterKey] != ':' {
			extraSpans = append(extraSpans, findBearerSpansInDecodedString(keyQS)...)
			i = afterKey
			continue
		}

		valStart := skipASCIIWhitespace(raw, afterKey+1)
		if valStart >= len(raw) {
			i = valStart
			break
		}

		memberIsOpsArray := strings.EqualFold(strings.TrimSpace(keyQS.decoded), "operations") && raw[valStart] == '['
		valEnd, valIsNull, valSpans, valStr, valOK := scanJSONValue(raw, valStart, memberIsOpsArray)
		if !valOK {
			i = valStart
			continue
		}

		members = append(members, parsedObjectMember{
			keyDecoded: keyQS.decoded,
			valStart:   valStart,
			valEnd:     valEnd,
			valIsNull:  valIsNull,
			valStr:     valStr,
			valSpans:   valSpans,
		})
		i = valEnd
	}

	isPwPatch := false
	hasClosedNonPwPath := false
	hasOpMember := false
	for idx := range members {
		trimmedKey := strings.TrimSpace(members[idx].keyDecoded)
		if strings.EqualFold(trimmedKey, "op") {
			hasOpMember = true
		}
		if strings.EqualFold(trimmedKey, "path") && members[idx].valStr != nil {
			if isPasswordPatchPath(members[idx].valStr.decoded) {
				isPwPatch = true
			} else if members[idx].valStr.closed {
				hasClosedNonPwPath = true
			}
		}
	}

	unclosedAmbiguousPatchOp := !closedByBrace && (inOperationsArray || hasOpMember) && !hasClosedNonPwPath
	redactPatchValue := isPwPatch || unclosedAmbiguousPatchOp

	var spans []redactSpan
	for idx := range members {
		m := &members[idx]
		if isPasswordKey(m.keyDecoded) || (redactPatchValue && strings.EqualFold(strings.TrimSpace(m.keyDecoded), "value")) {
			if !m.valIsNull && m.valEnd > m.valStart {
				spans = append(spans, redactSpan{
					start:       m.valStart,
					end:         m.valEnd,
					replacement: redactedJSONStr,
				})
			}
			continue
		}
		spans = append(spans, m.valSpans...)
	}
	spans = append(spans, extraSpans...)

	return i, spans
}

func scanJSONArray(raw string, openBracketPos int, inOperationsArray bool) (int, []redactSpan) {
	var spans []redactSpan
	i := openBracketPos + 1
	for i < len(raw) {
		i = skipWhitespaceAndCommas(raw, i)
		if i >= len(raw) {
			break
		}
		if raw[i] == ']' {
			i++
			break
		}
		if raw[i] == '}' {
			break
		}

		elemInOps := inOperationsArray && raw[i] == '{'
		elemEnd, _, elemSpans, _, elemOK := scanJSONValue(raw, i, elemInOps)
		if !elemOK {
			i++
			continue
		}
		spans = append(spans, elemSpans...)
		i = elemEnd
	}
	return i, spans
}

func scanQuotedString(raw string, quotePos int) decodedJSONString {
	capHint := len(raw) - quotePos
	if capHint > 256 {
		capHint = 256
	}
	decoded := make([]byte, 0, capHint)
	offsets := make([]byteRange, 0, capHint)

	var utf8Buf [utf8.UTFMax]byte
	appendDecodedRune := func(r rune, rStart, rEnd int) {
		n := utf8.EncodeRune(utf8Buf[:], r)
		for k := 0; k < n; k++ {
			decoded = append(decoded, utf8Buf[k])
			offsets = append(offsets, byteRange{start: rStart, end: rEnd})
		}
	}

	i := quotePos + 1
	closed := false
	for i < len(raw) {
		c := raw[i]
		if c == '"' {
			closed = true
			i++
			break
		}
		if c != '\\' {
			decoded = append(decoded, c)
			offsets = append(offsets, byteRange{start: i, end: i + 1})
			i++
			continue
		}

		if i+1 >= len(raw) {
			decoded = append(decoded, '\\')
			offsets = append(offsets, byteRange{start: i, end: i + 1})
			i++
			break
		}

		esc := raw[i+1]
		switch esc {
		case '\\', '"', '/':
			decoded = append(decoded, esc)
			offsets = append(offsets, byteRange{start: i, end: i + 2})
			i += 2
		case 'b':
			decoded = append(decoded, '\b')
			offsets = append(offsets, byteRange{start: i, end: i + 2})
			i += 2
		case 'f':
			decoded = append(decoded, '\f')
			offsets = append(offsets, byteRange{start: i, end: i + 2})
			i += 2
		case 'n':
			decoded = append(decoded, '\n')
			offsets = append(offsets, byteRange{start: i, end: i + 2})
			i += 2
		case 'r':
			decoded = append(decoded, '\r')
			offsets = append(offsets, byteRange{start: i, end: i + 2})
			i += 2
		case 't':
			decoded = append(decoded, '\t')
			offsets = append(offsets, byteRange{start: i, end: i + 2})
			i += 2
		case 'u', 'U':
			if i+6 <= len(raw) {
				if r1, valid := parseHex4(raw[i+2 : i+6]); valid {
					if r1 >= 0xD800 && r1 <= 0xDBFF && i+12 <= len(raw) && raw[i+6] == '\\' && (raw[i+7] == 'u' || raw[i+7] == 'U') {
						if r2, valid2 := parseHex4(raw[i+8 : i+12]); valid2 && r2 >= 0xDC00 && r2 <= 0xDFFF {
							appendDecodedRune(utf16.DecodeRune(rune(r1), rune(r2)), i, i+12)
							i += 12
							continue
						}
					}
					appendDecodedRune(rune(r1), i, i+6)
					i += 6
					continue
				}
			}
			decoded = append(decoded, '\\')
			offsets = append(offsets, byteRange{start: i, end: i + 1})
			i++
		default:
			decoded = append(decoded, '\\', esc)
			offsets = append(offsets,
				byteRange{start: i, end: i + 1},
				byteRange{start: i + 1, end: i + 2},
			)
			i += 2
		}
	}

	return decodedJSONString{
		rawStart: quotePos,
		rawEnd:   i,
		closed:   closed,
		decoded:  string(decoded),
		offsets:  offsets,
	}
}

func findBearerSpansInDecodedString(qs decodedJSONString) []redactSpan {
	s := qs.decoded
	if len(s) < 7 || !containsFoldASCII(s, "bearer") {
		return nil
	}

	var spans []redactSpan
	for i := 0; i+6 < len(s); {
		if !matchBearerAt(s, i) {
			i++
			continue
		}
		if i > 0 && isWordChar(s[i-1]) {
			i += 6
			continue
		}

		j := i + 6
		wsStart := j
		for j < len(s) && isASCIIWhitespace(s[j]) {
			j++
		}
		if j == wsStart {
			i += 6
			continue
		}

		tokStart := j
		for j < len(s) && isBearerTokenChar(s[j]) {
			j++
		}
		tokEnd := trimTrailingTokenPunct(s, tokStart, j)
		if tokEnd > tokStart && isLikelyBearerCredential(s[tokStart:tokEnd]) {
			spans = append(spans, redactSpan{
				start:       qs.offsets[tokStart].start,
				end:         qs.offsets[tokEnd-1].end,
				replacement: redactedValue,
			})
			i = j
			continue
		}
		i = tokStart
	}

	return spans
}

func findBearerSpansInRawText(raw string, start, end int) []redactSpan {
	s := raw[start:end]
	if len(s) < 7 || !containsFoldASCII(s, "bearer") {
		return nil
	}

	var spans []redactSpan
	for i := 0; i+6 < len(s); {
		if !matchBearerAt(s, i) {
			i++
			continue
		}
		if i > 0 && isWordChar(s[i-1]) {
			i += 6
			continue
		}

		j := i + 6
		wsStart := j
		for j < len(s) {
			if isASCIIWhitespace(s[j]) {
				j++
				continue
			}
			if s[j] == '\\' && j+1 < len(s) && (s[j+1] == 't' || s[j+1] == 'n' || s[j+1] == 'r') {
				j += 2
				continue
			}
			break
		}
		if j == wsStart {
			i += 6
			continue
		}

		tokStart := j
		for j < len(s) && isBearerTokenChar(s[j]) {
			j++
		}
		tokEnd := trimTrailingTokenPunct(s, tokStart, j)
		if tokEnd > tokStart && isLikelyBearerCredential(s[tokStart:tokEnd]) {
			spans = append(spans, redactSpan{
				start:       start + tokStart,
				end:         start + tokEnd,
				replacement: redactedValue,
			})
			i = j
			continue
		}
		i = tokStart
	}

	return spans
}

func matchBearerAt(s string, i int) bool {
	return asciiLower(s[i]) == 'b' &&
		asciiLower(s[i+1]) == 'e' &&
		asciiLower(s[i+2]) == 'a' &&
		asciiLower(s[i+3]) == 'r' &&
		asciiLower(s[i+4]) == 'e' &&
		asciiLower(s[i+5]) == 'r'
}

func isWordChar(b byte) bool {
	return (b >= 'a' && b <= 'z') ||
		(b >= 'A' && b <= 'Z') ||
		(b >= '0' && b <= '9') ||
		b == '_'
}

func isBearerTokenChar(b byte) bool {
	return (b >= 'a' && b <= 'z') ||
		(b >= 'A' && b <= 'Z') ||
		(b >= '0' && b <= '9') ||
		b == '-' || b == '.' || b == '_' || b == '~' ||
		b == '+' || b == '/' || b == '=' || b == '!' ||
		b == ':' || b == '@'
}

func trimTrailingTokenPunct(s string, start, end int) int {
	for end > start {
		last := s[end-1]
		if last == ':' || last == '.' || last == '!' {
			end--
			continue
		}
		break
	}
	return end
}

func isLikelyBearerCredential(tok string) bool {
	if len(tok) < minBearerTokSize {
		return false
	}

	hasDigit := false
	hasSymbol := false
	hasLower := false
	hasUpperAfterFirst := false

	for i := 0; i < len(tok); i++ {
		c := tok[i]
		switch {
		case c >= '0' && c <= '9':
			hasDigit = true
		case c >= 'a' && c <= 'z':
			hasLower = true
		case c >= 'A' && c <= 'Z':
			if i > 0 {
				hasUpperAfterFirst = true
			}
		default:
			hasSymbol = true
		}
	}

	return hasDigit || hasSymbol || len(tok) >= longAlphaTokSize || (hasLower && hasUpperAfterFirst)
}

func applyRedactSpans(raw string, spans []redactSpan) string {
	sort.Slice(spans, func(i, j int) bool {
		if spans[i].start != spans[j].start {
			return spans[i].start < spans[j].start
		}
		return spans[i].end > spans[j].end
	})

	var b strings.Builder
	b.Grow(len(raw))
	cursor := 0
	applied := 0
	for _, sp := range spans {
		if sp.start < cursor || sp.end <= sp.start || sp.end > len(raw) {
			continue
		}
		b.WriteString(raw[cursor:sp.start])
		b.WriteString(sp.replacement)
		cursor = sp.end
		applied++
	}
	if applied == 0 {
		return raw
	}
	b.WriteString(raw[cursor:])
	return b.String()
}

func isPasswordKey(key string) bool {
	lk := strings.ToLower(strings.TrimSpace(key))
	return lk == "password" || strings.HasSuffix(lk, ":password") || lk == "authorization"
}

func isPasswordPatchPath(path string) bool {
	lp := strings.ToLower(strings.TrimSpace(path))
	return lp == "password" || strings.HasSuffix(lp, ":password")
}

func skipASCIIWhitespace(s string, i int) int {
	for i < len(s) && isASCIIWhitespace(s[i]) {
		i++
	}
	return i
}

func skipWhitespaceAndCommas(s string, i int) int {
	for i < len(s) && (isASCIIWhitespace(s[i]) || s[i] == ',') {
		i++
	}
	return i
}

func isASCIIWhitespace(b byte) bool {
	return b == ' ' || b == '\t' || b == '\n' || b == '\r'
}

func isJSONStructural(b byte) bool {
	return b == '{' || b == '}' || b == '[' || b == ']' || b == ',' || b == ':' || b == '"'
}

func parseHex4(s string) (uint16, bool) {
	var val uint16
	for i := 0; i < 4; i++ {
		nib, ok := hexNibble(s[i])
		if !ok {
			return 0, false
		}
		val = (val << 4) | uint16(nib)
	}
	return val, true
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

func ptrOrNil(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}
