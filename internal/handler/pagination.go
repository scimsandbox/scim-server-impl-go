package handler

import (
	"math"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/google/uuid"
	"github.com/scimsandbox/scim-server-impl-go/internal/scim"
)

// PaginationRequest contains resolved pagination parameters.
type PaginationRequest struct {
	IsCursor     bool
	Offset       int
	Count        int
	StartIndex   int
	PrevPageSize int
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

	startIndexVal := 1
	hasStartIndex := false
	if query.Has("startIndex") {
		rawSI := strings.TrimSpace(query.Get("startIndex"))
		if rawSI != "" {
			hasStartIndex = true
			parsedSI, err := strconv.Atoi(rawSI)
			if err != nil {
				return nil, scim.NewScimError(http.StatusBadRequest, "invalidValue", "Invalid startIndex parameter: must be an integer")
			}
			startIndexVal = max(1, parsedSI)
		}
	}

	count := defaultCount
	hasExplicitCount := false
	rawExplicitCount := 0
	if query.Has("count") {
		rawCount := strings.TrimSpace(query.Get("count"))
		if rawCount != "" {
			parsedCount, err := strconv.Atoi(rawCount)
			if err != nil {
				return nil, scim.NewScimError(http.StatusBadRequest, "invalidValue", "Invalid count parameter: must be an integer")
			}
			hasExplicitCount = true
			rawExplicitCount = parsedCount
			count = max(0, min(200, parsedCount))
		}
	}

	if body != nil {
		if c, exists := body["cursor"]; exists && c != nil {
			if str, ok := c.(string); ok {
				hasCursor = true
				cursorVal = str
			} else {
				return nil, scim.NewScimError(http.StatusBadRequest, "invalidCursor", "cursor must be a string")
			}
		}
		if si, exists := body["startIndex"]; exists && si != nil {
			num, ok := si.(float64)
			if !ok || math.IsNaN(num) || math.IsInf(num, 0) || num != math.Trunc(num) {
				return nil, scim.NewScimError(http.StatusBadRequest, "invalidValue", "startIndex must be an integer")
			}
			hasStartIndex = true
			startIndexVal = max(1, int(num))
		}
		if cnt, exists := body["count"]; exists && cnt != nil {
			num, ok := cnt.(float64)
			if !ok || math.IsNaN(num) || math.IsInf(num, 0) || num != math.Trunc(num) {
				return nil, scim.NewScimError(http.StatusBadRequest, "invalidValue", "count must be an integer")
			}
			hasExplicitCount = true
			rawExplicitCount = int(num)
			count = max(0, min(200, int(num)))
		}
	}

	if hasCursor && hasStartIndex {
		return nil, scim.NewScimError(http.StatusBadRequest, "invalidValue", "Cannot specify both cursor and startIndex in the same request")
	}

	if hasCursor {
		offset, prevPageSize, err := scim.DecodeCursorWithPageSize(cursorVal, wsID)
		if err != nil {
			if scimErr, ok := err.(*scim.ScimError); ok {
				return nil, scimErr
			}
			return nil, scim.NewScimError(http.StatusBadRequest, "invalidCursor", err.Error())
		}
		if hasExplicitCount && rawExplicitCount > 200 {
			return nil, scim.NewScimError(http.StatusBadRequest, "tooMany", "Requested count exceeds maxPageSize (200)")
		}
		return &PaginationRequest{
			IsCursor:     true,
			Offset:       offset,
			Count:        count,
			PrevPageSize: prevPageSize,
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
		if pag.Offset > 0 {
			step := pag.PrevPageSize
			if step <= 0 {
				step = pag.Count
			}
			prevOffset := pag.Offset - step
			if prevOffset < 0 || step <= 0 {
				prevOffset = 0
			}
			if pc, err := scim.EncodeCursorWithPageSize(wsID, prevOffset, step, scim.DefaultCursorTimeoutSeconds); err == nil {
				resp["previousCursor"] = pc
			}
		}
		if len(resources) > 0 {
			nextOffset := pag.Offset + len(resources)
			if nextOffset < totalResults {
				if nc, err := scim.EncodeCursorWithPageSize(wsID, nextOffset, len(resources), scim.DefaultCursorTimeoutSeconds); err == nil {
					resp["nextCursor"] = nc
				}
			}
		}
	}

	return resp
}
