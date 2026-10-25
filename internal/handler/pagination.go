package handler

import (
	"net/http"
	"net/url"
	"strings"

	"github.com/google/uuid"
	"github.com/scimsandbox/scim-server-impl-go/internal/scim"
)

// PaginationRequest contains resolved pagination parameters.
type PaginationRequest struct {
	IsCursor   bool
	Offset     int
	Count      int
	StartIndex int
}

// parsePagination parses cursor or index-based pagination parameters from query string and optional JSON body.
// It enforces mutual exclusivity between cursor and startIndex per RFC 9865 §2.
func parsePagination(
	query url.Values,
	body map[string]any,
	wsID uuid.UUID,
	defaultCount int,
) (*PaginationRequest, *scim.ScimError) {
	hasCursor := query.Has("cursor")
	cursorVal := query.Get("cursor")

	hasStartIndex := query.Has("startIndex") && strings.TrimSpace(query.Get("startIndex")) != ""
	startIndexVal := clampInt(query.Get("startIndex"), 1, 1)

	count := clampIntMax(query.Get("count"), defaultCount, 0, 200)

	if body != nil {
		if c, exists := body["cursor"]; exists {
			if str, ok := c.(string); ok {
				hasCursor = true
				cursorVal = str
			} else {
				return nil, scim.NewScimError(http.StatusBadRequest, "invalidCursor", "cursor must be a string")
			}
		}
		if si, exists := body["startIndex"]; exists {
			if num, ok := si.(float64); ok {
				hasStartIndex = true
				startIndexVal = max(1, int(num))
			} else {
				return nil, scim.NewScimError(http.StatusBadRequest, "invalidValue", "startIndex must be an integer")
			}
		}
		if cnt, exists := body["count"]; exists {
			if num, ok := cnt.(float64); ok {
				count = max(0, min(200, int(num)))
			}
		}
	}

	if hasCursor && hasStartIndex {
		return nil, scim.NewScimError(http.StatusBadRequest, "invalidValue", "Cannot specify both cursor and startIndex in the same request")
	}

	if hasCursor {
		offset, err := scim.DecodeCursor(cursorVal, wsID)
		if err != nil {
			if scimErr, ok := err.(*scim.ScimError); ok {
				return nil, scimErr
			}
			return nil, scim.NewScimError(http.StatusBadRequest, "invalidCursor", err.Error())
		}
		return &PaginationRequest{
			IsCursor: true,
			Offset:   offset,
			Count:    count,
		}, nil
	}

	offset := max(0, startIndexVal-1)
	return &PaginationRequest{
		IsCursor:   false,
		Offset:     offset,
		Count:      count,
		StartIndex: startIndexVal,
	}, nil
}

// buildListResponse constructs the standard SCIM ListResponse map, correctly handling
// cursor mode (omitting startIndex, computing previousCursor and nextCursor) and index mode.
func buildListResponse(
	pag *PaginationRequest,
	wsID uuid.UUID,
	totalResults int,
	resources []map[string]any,
) map[string]any {
	if resources == nil {
		resources = []map[string]any{}
	}

	resp := map[string]any{
		"schemas":      []string{"urn:ietf:params:scim:api:messages:2.0:ListResponse"},
		"totalResults": totalResults,
		"itemsPerPage": len(resources),
		"Resources":    resources,
	}

	if !pag.IsCursor {
		resp["startIndex"] = pag.StartIndex
	} else {
		// RFC 9865 §2: In cursor mode, startIndex is omitted.
		// If offset > 0: previousCursor = EncodeCursor(wsID, max(0, offset - count), 3600)
		if pag.Offset > 0 {
			prevOffset := max(0, pag.Offset-pag.Count)
			if prevCur, err := scim.EncodeCursor(wsID, prevOffset, scim.DefaultCursorTimeoutSeconds); err == nil {
				resp["previousCursor"] = prevCur
			}
		}
		// If offset + len(resources) < totalResults: nextCursor = EncodeCursor(wsID, offset + len(resources), 3600)
		if pag.Offset+len(resources) < totalResults {
			nextOffset := pag.Offset + len(resources)
			if nextCur, err := scim.EncodeCursor(wsID, nextOffset, scim.DefaultCursorTimeoutSeconds); err == nil {
				resp["nextCursor"] = nextCur
			}
		}
	}

	return resp
}
