package handler

import (
	"fmt"
	"strings"
)

// checkETagMatch evaluates an If-Match header against the resource version per RFC 7232 §3.1 and RFC 7644 §3.14.
// If ifMatch is empty, or "*" (wildcard matching any existing resource representation), it returns true.
// Otherwise, it checks each comma-separated entity-tag token against "*" or the weak ETag representation W/"<version>".
func checkETagMatch(ifMatch string, version int64) bool {
	trimmed := strings.TrimSpace(ifMatch)
	if trimmed == "" || trimmed == "*" {
		return true
	}
	expected := fmt.Sprintf("W/\"%d\"", version)
	for _, part := range strings.Split(trimmed, ",") {
		candidate := strings.TrimSpace(part)
		if candidate == "*" || candidate == expected {
			return true
		}
	}
	return false
}
