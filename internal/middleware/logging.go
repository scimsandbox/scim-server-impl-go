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

			reqBodyStr := finalizeLoggedBody(string(reqBody), reqTruncated, false)
			respBodyStr := finalizeLoggedBody(rc.body.String(), rc.truncated, true)

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

func finalizeLoggedBody(raw string, captureTruncated bool, isResponse bool) string {
	if raw == "" {
		return ""
	}
	if captureTruncated {
		raw = trimIncompleteTrailingUTF8(raw)
	}

	var redacted string
	if isResponse {
		redacted = redactResponseBody(raw)
	} else {
		redacted = RedactSensitiveBody(raw)
	}

	var out string
	switch {
	case len(redacted) > maxBodyLog:
		out = truncateUTF8(redacted, maxBodyLog) + "...[truncated]"
	case captureTruncated:
		out = redacted + "...[truncated]"
	default:
		out = redacted
	}

	if !utf8.ValidString(out) {
		out = strings.ToValidUTF8(out, "\uFFFD")
	}
	return out
}

func trimIncompleteTrailingUTF8(s string) string {
	if len(s) == 0 || s[len(s)-1] < utf8.RuneSelf {
		return s
	}
	minIdx := len(s) - utf8.UTFMax
	if minIdx < 0 {
		minIdx = 0
	}
	for start := len(s) - 1; start >= minIdx; start-- {
		if utf8.RuneStart(s[start]) {
			if !utf8.FullRuneInString(s[start:]) {
				return s[:start]
			}
			return s
		}
	}
	return s
}

func truncateUTF8(s string, maxBytes int) string {
	if len(s) <= maxBytes {
		return s
	}
	cut := maxBytes
	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}
	return trimIncompleteTrailingUTF8(s[:cut])
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
	rawStart   int
	rawEnd     int
	closed     bool
	hasEscapes bool
	decoded    string
}

type parsedObjectMember struct {
	keyDecoded string
	valStart   int
	valEnd     int
	valIsNull  bool
	hasValStr  bool
	valStr     decodedJSONString
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

func redactResponseBody(raw string) string {
	if raw == "" || !hasSensitiveResponseCandidate(raw) {
		return raw
	}

	spans := collectSensitiveSpans(raw)
	if len(spans) == 0 {
		return raw
	}

	return applyRedactSpans(raw, spans)
}

func hasSensitiveResponseCandidate(s string) bool {
	return containsFoldASCIIAt(s, "password", 4) ||
		containsFoldASCIIAt(s, "authorization", 7) ||
		containsFoldASCIIAt(s, "bearer", 0) ||
		containsUnicodeEscape(s)
}

func hasSensitiveCandidate(s string) bool {
	if hasSensitiveResponseCandidate(s) {
		return true
	}
	return containsFoldASCIIAt(s, "operations", 1) &&
		containsFoldASCIIAt(s, "value", 0) &&
		hasUnclosedJSONContainer(s)
}

func containsUnicodeEscape(s string) bool {
	for i := 0; i < len(s); {
		idx := strings.IndexByte(s[i:], '\\')
		if idx < 0 {
			return false
		}
		pos := i + idx
		if pos+1 < len(s) && (s[pos+1] == 'u' || s[pos+1] == 'U') {
			return true
		}
		i = pos + 1
	}
	return false
}

func hasUnclosedJSONContainer(s string) bool {
	braceDepth := 0
	bracketDepth := 0
	sawContainer := false
	inString := false
	for i := 0; i < len(s); i++ {
		c := s[i]
		if inString {
			if c == '\\' {
				i++
				continue
			}
			if c == '"' {
				inString = false
			}
			continue
		}
		switch c {
		case '"':
			inString = true
		case '{':
			sawContainer = true
			braceDepth++
		case '}':
			if braceDepth > 0 {
				braceDepth--
			}
		case '[':
			sawContainer = true
			bracketDepth++
		case ']':
			if bracketDepth > 0 {
				bracketDepth--
			}
		}
	}
	return inString || (sawContainer && (braceDepth > 0 || bracketDepth > 0))
}

func containsFoldASCII(s, needleLower string) bool {
	return containsFoldASCIIAt(s, needleLower, 0)
}

func containsFoldASCIIAt(s, needleLower string, pivot int) bool {
	n := len(needleLower)
	if len(s) < n {
		return false
	}
	lower := needleLower[pivot]
	upper := lower - ('a' - 'A')
	window := s[pivot : len(s)-n+pivot+1]

	nextLow := strings.IndexByte(window, lower)
	nextUp := strings.IndexByte(window, upper)

	for nextLow >= 0 || nextUp >= 0 {
		var hit int
		if nextLow >= 0 && (nextUp < 0 || nextLow <= nextUp) {
			hit = nextLow
		} else {
			hit = nextUp
		}

		candStart := hit // pivot + hit - pivot == hit
		match := true
		for j := 0; j < n; j++ {
			if asciiLower(s[candStart+j]) != needleLower[j] {
				match = false
				break
			}
		}
		if match {
			return true
		}

		advance := hit + 1
		if nextLow >= 0 && nextLow < advance {
			if rel := strings.IndexByte(window[advance:], lower); rel >= 0 {
				nextLow = advance + rel
			} else {
				nextLow = -1
			}
		}
		if nextUp >= 0 && nextUp < advance {
			if rel := strings.IndexByte(window[advance:], upper); rel >= 0 {
				nextUp = advance + rel
			} else {
				nextUp = -1
			}
		}
	}
	return false
}

func equalFoldASCII(s, lowerTarget string) bool {
	if len(s) != len(lowerTarget) {
		return false
	}
	for i := 0; i < len(s); i++ {
		if asciiLower(s[i]) != lowerTarget[i] {
			return false
		}
	}
	return true
}

func hasSuffixFoldASCII(s, lowerSuffix string) bool {
	if len(s) < len(lowerSuffix) {
		return false
	}
	return equalFoldASCII(s[len(s)-len(lowerSuffix):], lowerSuffix)
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
			endPos, _, subSpans, _, _, _ := scanJSONValue(raw, pos, false)
			spans = append(spans, subSpans...)
			pos = endPos

		case '"':
			qs := scanQuotedString(raw, pos)
			afterKey := skipASCIIWhitespace(raw, qs.rawEnd)
			if afterKey < len(raw) && raw[afterKey] == ':' && isPasswordKey(qs.decoded) {
				valStart := skipASCIIWhitespace(raw, afterKey+1)
				if valStart < len(raw) {
					valEnd, valIsNull, _, _, _, ok := scanJSONValue(raw, valStart, false)
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
			spans = append(spans, findBearerSpansInDecodedString(raw, qs)...)
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
) (endPos int, isNull bool, spans []redactSpan, strVal decodedJSONString, hasStr bool, ok bool) {
	pos = skipASCIIWhitespace(raw, pos)
	if pos >= len(raw) {
		return pos, false, nil, decodedJSONString{}, false, false
	}

	switch raw[pos] {
	case '"':
		qs := scanQuotedString(raw, pos)
		return qs.rawEnd, false, findBearerSpansInDecodedString(raw, qs), qs, true, true

	case '{':
		endIdx, objSpans := scanJSONObject(raw, pos, inOperationsArray)
		return endIdx, false, objSpans, decodedJSONString{}, false, true

	case '[':
		endIdx, arrSpans := scanJSONArray(raw, pos, inOperationsArray)
		return endIdx, false, arrSpans, decodedJSONString{}, false, true

	case '}', ']', ',', ':':
		return pos, false, nil, decodedJSONString{}, false, false

	default:
		endIdx := pos
		for endIdx < len(raw) && !isASCIIWhitespace(raw[endIdx]) && !isJSONStructural(raw[endIdx]) {
			endIdx++
		}
		prim := raw[pos:endIdx]
		return endIdx, prim == "null", findBearerSpansInRawText(raw, pos, endIdx), decodedJSONString{}, false, endIdx > pos
	}
}

func scanJSONObject(raw string, openBracePos int, inOperationsArray bool) (int, []redactSpan) {
	var memberBuf [16]parsedObjectMember
	members := memberBuf[:0]
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
				subEnd, _, subSpans, _, _, _ := scanJSONValue(raw, i, false)
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
			extraSpans = append(extraSpans, findBearerSpansInDecodedString(raw, keyQS)...)
			i = afterKey
			continue
		}

		valStart := skipASCIIWhitespace(raw, afterKey+1)
		if valStart >= len(raw) {
			i = valStart
			break
		}

		memberIsOpsArray := equalFoldASCII(strings.TrimSpace(keyQS.decoded), "operations") && raw[valStart] == '['
		valEnd, valIsNull, valSpans, valStr, hasValStr, valOK := scanJSONValue(raw, valStart, memberIsOpsArray)
		if !valOK {
			i = valStart
			continue
		}

		members = append(members, parsedObjectMember{
			keyDecoded: keyQS.decoded,
			valStart:   valStart,
			valEnd:     valEnd,
			valIsNull:  valIsNull,
			hasValStr:  hasValStr,
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
		if equalFoldASCII(trimmedKey, "op") {
			hasOpMember = true
		}
		if equalFoldASCII(trimmedKey, "path") && members[idx].hasValStr {
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
		if isPasswordKey(m.keyDecoded) || (redactPatchValue && equalFoldASCII(strings.TrimSpace(m.keyDecoded), "value")) {
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
		elemEnd, _, elemSpans, _, _, elemOK := scanJSONValue(raw, i, elemInOps)
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
	start := quotePos + 1
	for i := start; i < len(raw); i++ {
		c := raw[i]
		if c == '"' {
			return decodedJSONString{
				rawStart:   quotePos,
				rawEnd:     i + 1,
				closed:     true,
				hasEscapes: false,
				decoded:    raw[start:i],
			}
		}
		if c == '\\' {
			return scanEscapedQuotedString(raw, quotePos, i)
		}
	}
	return decodedJSONString{
		rawStart:   quotePos,
		rawEnd:     len(raw),
		closed:     false,
		hasEscapes: false,
		decoded:    raw[start:],
	}
}

func scanEscapedQuotedString(raw string, quotePos, firstSlashPos int) decodedJSONString {
	prefixLen := firstSlashPos - (quotePos + 1)
	capHint := len(raw) - quotePos
	if capHint > prefixLen+256 {
		capHint = prefixLen + 256
	}
	decoded := make([]byte, prefixLen, capHint)
	copy(decoded, raw[quotePos+1:firstSlashPos])

	var utf8Buf [utf8.UTFMax]byte
	appendDecodedRune := func(r rune) {
		n := utf8.EncodeRune(utf8Buf[:], r)
		decoded = append(decoded, utf8Buf[:n]...)
	}

	i := firstSlashPos
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
			i++
			continue
		}

		if i+1 >= len(raw) {
			decoded = append(decoded, '\\')
			i++
			break
		}

		esc := raw[i+1]
		switch esc {
		case '\\', '"', '/':
			decoded = append(decoded, esc)
			i += 2
		case 'b':
			decoded = append(decoded, '\b')
			i += 2
		case 'f':
			decoded = append(decoded, '\f')
			i += 2
		case 'n':
			decoded = append(decoded, '\n')
			i += 2
		case 'r':
			decoded = append(decoded, '\r')
			i += 2
		case 't':
			decoded = append(decoded, '\t')
			i += 2
		case 'u', 'U':
			if i+6 <= len(raw) {
				if r1, valid := parseHex4(raw[i+2 : i+6]); valid {
					if r1 >= 0xD800 && r1 <= 0xDBFF && i+12 <= len(raw) && raw[i+6] == '\\' && (raw[i+7] == 'u' || raw[i+7] == 'U') {
						if r2, valid2 := parseHex4(raw[i+8 : i+12]); valid2 && r2 >= 0xDC00 && r2 <= 0xDFFF {
							appendDecodedRune(utf16.DecodeRune(rune(r1), rune(r2)))
							i += 12
							continue
						}
					}
					appendDecodedRune(rune(r1))
					i += 6
					continue
				}
			}
			decoded = append(decoded, '\\')
			i++
		default:
			decoded = append(decoded, '\\', esc)
			i += 2
		}
	}

	return decodedJSONString{
		rawStart:   quotePos,
		rawEnd:     i,
		closed:     closed,
		hasEscapes: true,
		decoded:    string(decoded),
	}
}

func buildEscapedStringOffsets(raw string, quotePos int) []byteRange {
	capHint := len(raw) - quotePos
	if capHint > 256 {
		capHint = 256
	}
	offsets := make([]byteRange, 0, capHint)

	var utf8Buf [utf8.UTFMax]byte
	appendRuneOffsets := func(r rune, rStart, rEnd int) {
		n := utf8.EncodeRune(utf8Buf[:], r)
		for k := 0; k < n; k++ {
			offsets = append(offsets, byteRange{start: rStart, end: rEnd})
		}
	}

	i := quotePos + 1
	for i < len(raw) {
		c := raw[i]
		if c == '"' {
			break
		}
		if c != '\\' {
			offsets = append(offsets, byteRange{start: i, end: i + 1})
			i++
			continue
		}
		if i+1 >= len(raw) {
			offsets = append(offsets, byteRange{start: i, end: i + 1})
			break
		}

		esc := raw[i+1]
		switch esc {
		case '\\', '"', '/', 'b', 'f', 'n', 'r', 't':
			offsets = append(offsets, byteRange{start: i, end: i + 2})
			i += 2
		case 'u', 'U':
			if i+6 <= len(raw) {
				if r1, valid := parseHex4(raw[i+2 : i+6]); valid {
					if r1 >= 0xD800 && r1 <= 0xDBFF && i+12 <= len(raw) && raw[i+6] == '\\' && (raw[i+7] == 'u' || raw[i+7] == 'U') {
						if r2, valid2 := parseHex4(raw[i+8 : i+12]); valid2 && r2 >= 0xDC00 && r2 <= 0xDFFF {
							appendRuneOffsets(utf16.DecodeRune(rune(r1), rune(r2)), i, i+12)
							i += 12
							continue
						}
					}
					appendRuneOffsets(rune(r1), i, i+6)
					i += 6
					continue
				}
			}
			offsets = append(offsets, byteRange{start: i, end: i + 1})
			i++
		default:
			offsets = append(offsets,
				byteRange{start: i, end: i + 1},
				byteRange{start: i + 1, end: i + 2},
			)
			i += 2
		}
	}
	return offsets
}

func findBearerSpansInDecodedString(raw string, qs decodedJSONString) []redactSpan {
	s := qs.decoded
	if len(s) < 7 || !containsFoldASCII(s, "bearer") {
		return nil
	}

	var offsets []byteRange
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
			var rawTokStart, rawTokEnd int
			if !qs.hasEscapes {
				rawTokStart = qs.rawStart + 1 + tokStart
				rawTokEnd = qs.rawStart + 1 + tokEnd
			} else {
				if offsets == nil {
					offsets = buildEscapedStringOffsets(raw, qs.rawStart)
				}
				rawTokStart = offsets[tokStart].start
				rawTokEnd = offsets[tokEnd-1].end
			}
			spans = append(spans, redactSpan{
				start:       rawTokStart,
				end:         rawTokEnd,
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
	tk := strings.TrimSpace(key)
	return equalFoldASCII(tk, "password") ||
		hasSuffixFoldASCII(tk, ":password") ||
		equalFoldASCII(tk, "authorization")
}

func isPasswordPatchPath(path string) bool {
	tp := strings.TrimSpace(path)
	return equalFoldASCII(tp, "password") || hasSuffixFoldASCII(tp, ":password")
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
