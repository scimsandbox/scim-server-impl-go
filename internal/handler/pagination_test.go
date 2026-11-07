package handler

import (
	"net/http"
	"net/url"
	"testing"

	"github.com/google/uuid"
	"github.com/scimsandbox/scim-server-impl-go/internal/scim"
)

func TestParsePagination_DefaultIndex(t *testing.T) {
	wsID := uuid.New()
	q := url.Values{}

	pag, err := parsePagination(q, nil, wsID, 10)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if pag.IsCursor {
		t.Errorf("expected IsCursor to be false")
	}
	if pag.StartIndex != 1 {
		t.Errorf("expected StartIndex=1, got %d", pag.StartIndex)
	}
	if pag.Offset != 0 {
		t.Errorf("expected Offset=0, got %d", pag.Offset)
	}
	if pag.Count != 10 {
		t.Errorf("expected Count=10, got %d", pag.Count)
	}
}

func TestParsePagination_ExplicitIndex(t *testing.T) {
	wsID := uuid.New()
	q := url.Values{
		"startIndex": []string{"5"},
		"count":      []string{"25"},
	}

	pag, err := parsePagination(q, nil, wsID, 10)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if pag.IsCursor {
		t.Errorf("expected IsCursor to be false")
	}
	if pag.StartIndex != 5 {
		t.Errorf("expected StartIndex=5, got %d", pag.StartIndex)
	}
	if pag.Offset != 4 {
		t.Errorf("expected Offset=4, got %d", pag.Offset)
	}
	if pag.Count != 25 {
		t.Errorf("expected Count=25, got %d", pag.Count)
	}
}

func TestParsePagination_EmptyCursorQuery(t *testing.T) {
	wsID := uuid.New()
	q := url.Values{
		"cursor": []string{""},
		"count":  []string{"1"},
	}

	pag, err := parsePagination(q, nil, wsID, 10)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !pag.IsCursor {
		t.Errorf("expected IsCursor to be true")
	}
	if pag.Offset != 0 {
		t.Errorf("expected Offset=0, got %d", pag.Offset)
	}
	if pag.Count != 1 {
		t.Errorf("expected Count=1, got %d", pag.Count)
	}
}

func TestParsePagination_ValidCursorToken(t *testing.T) {
	wsID := uuid.New()
	token, err := scim.EncodeCursor(wsID, 15, 3600)
	if err != nil {
		t.Fatalf("failed to encode cursor: %v", err)
	}

	q := url.Values{
		"cursor": []string{token},
	}

	pag, scimErr := parsePagination(q, nil, wsID, 10)
	if scimErr != nil {
		t.Fatalf("unexpected error: %v", scimErr)
	}
	if !pag.IsCursor {
		t.Errorf("expected IsCursor to be true")
	}
	if pag.Offset != 15 {
		t.Errorf("expected Offset=15, got %d", pag.Offset)
	}
}

func TestParsePagination_MutualExclusion_Query(t *testing.T) {
	wsID := uuid.New()
	q := url.Values{
		"cursor":     []string{""},
		"startIndex": []string{"1"},
	}

	_, err := parsePagination(q, nil, wsID, 10)
	if err == nil {
		t.Fatalf("expected error for both cursor and startIndex in query, got nil")
	}
	if err.Status != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", err.Status)
	}
	if err.ScimType != "invalidValue" && err.ScimType != "invalidCursor" {
		t.Errorf("scimType = %q, want invalidValue or invalidCursor", err.ScimType)
	}
}

func TestParsePagination_MutualExclusion_QueryAndBody(t *testing.T) {
	wsID := uuid.New()
	token, _ := scim.EncodeCursor(wsID, 5, 3600)
	q := url.Values{
		"startIndex": []string{"2"},
	}
	body := map[string]any{
		"cursor": token,
	}

	_, err := parsePagination(q, body, wsID, 10)
	if err == nil {
		t.Fatalf("expected error for cursor in body and startIndex in query, got nil")
	}
	if err.Status != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", err.Status)
	}
}

func TestParsePagination_MutualExclusion_BodyOnly(t *testing.T) {
	wsID := uuid.New()
	body := map[string]any{
		"cursor":     "",
		"startIndex": float64(1),
	}

	_, err := parsePagination(url.Values{}, body, wsID, 10)
	if err == nil {
		t.Fatalf("expected error for both cursor and startIndex in body, got nil")
	}
	if err.Status != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", err.Status)
	}
}

func TestParsePagination_InvalidCursor(t *testing.T) {
	wsID := uuid.New()
	q := url.Values{
		"cursor": []string{"invalid-opaque-cursor"},
	}

	_, err := parsePagination(q, nil, wsID, 10)
	if err == nil {
		t.Fatalf("expected error for invalid cursor token, got nil")
	}
	if err.Status != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", err.Status)
	}
	if err.ScimType != "invalidCursor" {
		t.Errorf("scimType = %q, want invalidCursor", err.ScimType)
	}
}

func TestParsePagination_NonStringCursorInBody(t *testing.T) {
	wsID := uuid.New()
	body := map[string]any{
		"cursor": 12345,
	}

	_, err := parsePagination(url.Values{}, body, wsID, 10)
	if err == nil {
		t.Fatalf("expected error for non-string cursor, got nil")
	}
	if err.Status != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", err.Status)
	}
	if err.ScimType != "invalidCursor" {
		t.Errorf("scimType = %q, want invalidCursor", err.ScimType)
	}
}

func TestBuildListResponse_IndexMode(t *testing.T) {
	wsID := uuid.New()
	pag := &PaginationRequest{
		IsCursor:   false,
		Offset:     0,
		Count:      10,
		StartIndex: 1,
	}
	resources := []map[string]any{{"id": "user-1"}}

	resp := buildListResponse(pag, wsID, 1, resources)
	if resp["startIndex"] != 1 {
		t.Errorf("startIndex = %v, want 1", resp["startIndex"])
	}
	if _, exists := resp["previousCursor"]; exists {
		t.Errorf("previousCursor should not exist in index mode")
	}
	if _, exists := resp["nextCursor"]; exists {
		t.Errorf("nextCursor should not exist in index mode")
	}
	if resp["totalResults"] != 1 {
		t.Errorf("totalResults = %v, want 1", resp["totalResults"])
	}
	if resp["itemsPerPage"] != 1 {
		t.Errorf("itemsPerPage = %v, want 1", resp["itemsPerPage"])
	}
}

func TestBuildListResponse_CursorInitialPage_CUR01(t *testing.T) {
	wsID := uuid.New()
	pag := &PaginationRequest{
		IsCursor: true,
		Offset:   0,
		Count:    1,
	}
	resources := []map[string]any{{"id": "user-1"}}

	resp := buildListResponse(pag, wsID, 3, resources)

	// In cursor mode, startIndex MUST be omitted (RFC 9865 §2 Table 2)
	if _, exists := resp["startIndex"]; exists {
		t.Errorf("startIndex must be omitted in cursor mode")
	}

	// previousCursor MUST be omitted on the initial page (RFC 9865 §2 Table 2)
	if _, exists := resp["previousCursor"]; exists {
		t.Errorf("previousCursor must be omitted on the initial page")
	}

	// nextCursor MUST be present when more results exist
	nextCur, ok := resp["nextCursor"].(string)
	if !ok || nextCur == "" {
		t.Fatalf("expected nextCursor to be present and non-empty")
	}

	decodedOffset, err := scim.DecodeCursor(nextCur, wsID)
	if err != nil {
		t.Fatalf("failed to decode nextCursor: %v", err)
	}
	if decodedOffset != 1 {
		t.Errorf("decoded nextCursor offset = %d, want 1", decodedOffset)
	}
}

func TestBuildListResponse_CursorMiddlePage(t *testing.T) {
	wsID := uuid.New()
	pag := &PaginationRequest{
		IsCursor: true,
		Offset:   1,
		Count:    1,
	}
	resources := []map[string]any{{"id": "user-2"}}

	resp := buildListResponse(pag, wsID, 3, resources)

	if _, exists := resp["startIndex"]; exists {
		t.Errorf("startIndex must be omitted in cursor mode")
	}

	// previousCursor must be present
	prevCur, ok := resp["previousCursor"].(string)
	if !ok || prevCur == "" {
		t.Fatalf("expected previousCursor to be present")
	}
	prevOffset, err := scim.DecodeCursor(prevCur, wsID)
	if err != nil {
		t.Fatalf("failed to decode previousCursor: %v", err)
	}
	if prevOffset != 0 {
		t.Errorf("previousCursor offset = %d, want 0", prevOffset)
	}

	// nextCursor must be present
	nextCur, ok := resp["nextCursor"].(string)
	if !ok || nextCur == "" {
		t.Fatalf("expected nextCursor to be present")
	}
	nextOffset, err := scim.DecodeCursor(nextCur, wsID)
	if err != nil {
		t.Fatalf("failed to decode nextCursor: %v", err)
	}
	if nextOffset != 2 {
		t.Errorf("nextCursor offset = %d, want 2", nextOffset)
	}
}

func TestBuildListResponse_CursorFinalPage_CUR03(t *testing.T) {
	wsID := uuid.New()
	pag := &PaginationRequest{
		IsCursor: true,
		Offset:   2,
		Count:    1,
	}
	resources := []map[string]any{{"id": "user-3"}}

	resp := buildListResponse(pag, wsID, 3, resources)

	if _, exists := resp["startIndex"]; exists {
		t.Errorf("startIndex must be omitted in cursor mode")
	}

	// previousCursor must be present
	if _, exists := resp["previousCursor"]; !exists {
		t.Errorf("previousCursor must be present on final page when offset > 0")
	}

	// nextCursor MUST be omitted on final page (RFC 9865 §2 Table 2)
	if _, exists := resp["nextCursor"]; exists {
		t.Errorf("nextCursor must be omitted on final page of results")
	}
}

func TestParsePagination_StrictIntegerAndNegativeClamping(t *testing.T) {
	wsID := uuid.New()

	if _, err := parsePagination(url.Values{"count": []string{"not-a-number"}}, nil, wsID, 10); err == nil || err.ScimType != "invalidValue" {
		t.Fatalf("expected 400 invalidValue for non-integer count, got %v", err)
	}

	if _, err := parsePagination(url.Values{"startIndex": []string{"abc"}}, nil, wsID, 10); err == nil || err.ScimType != "invalidValue" {
		t.Fatalf("expected 400 invalidValue for non-integer startIndex, got %v", err)
	}

	if _, err := parsePagination(url.Values{}, map[string]any{"count": 1.5}, wsID, 10); err == nil || err.ScimType != "invalidValue" {
		t.Fatalf("expected 400 invalidValue for fractional count in body, got %v", err)
	}

	pag, err := parsePagination(url.Values{"count": []string{"-1"}, "startIndex": []string{"0"}}, nil, wsID, 10)
	if err != nil {
		t.Fatalf("negative count / zero startIndex should clamp without error, got %v", err)
	}
	if pag.Count != 0 || pag.StartIndex != 1 {
		t.Fatalf("got Count=%d StartIndex=%d, want Count=0 StartIndex=1", pag.Count, pag.StartIndex)
	}
}

// Traced RFC requirements (Group 5):
//   - RFC7644-3.4.2.1-145a1a: maxResults cap (200) clamped on index pagination.
//   - RFC7644-3.12-40cb84: 400 tooMany on excessive cursor count (> maxPageSize).
func TestParsePagination_MaxResultsAndCursorTooMany_Group5(t *testing.T) {
	wsID := uuid.New()

	// Index pagination: count=500 is clamped to maxResults=200
	pag, err := parsePagination(url.Values{"count": []string{"500"}}, nil, wsID, 10)
	if err != nil {
		t.Fatalf("unexpected error on index count=500: %v", err)
	}
	if pag.IsCursor {
		t.Fatalf("expected IsCursor=false")
	}
	if pag.Count != 200 {
		t.Fatalf("index Count = %d, want 200", pag.Count)
	}

	// Cursor pagination (query): count=500 (> maxPageSize 200) -> 400 tooMany
	_, err = parsePagination(url.Values{"cursor": []string{""}, "count": []string{"500"}}, nil, wsID, 10)
	if err == nil {
		t.Fatal("expected 400 tooMany for cursor count=500, got nil")
	}
	if err.Status != http.StatusBadRequest || err.ScimType != "tooMany" {
		t.Fatalf("got status=%d scimType=%q, want 400 tooMany", err.Status, err.ScimType)
	}

	// Cursor pagination (POST /.search body): count=201 (> maxPageSize 200) -> 400 tooMany
	_, err = parsePagination(url.Values{}, map[string]any{"cursor": "", "count": float64(201)}, wsID, 10)
	if err == nil {
		t.Fatal("expected 400 tooMany for POST /.search cursor count=201, got nil")
	}
	if err.Status != http.StatusBadRequest || err.ScimType != "tooMany" {
		t.Fatalf("got status=%d scimType=%q, want 400 tooMany", err.Status, err.ScimType)
	}
}

func TestBuildListResponse_CursorCountZeroOmitsNextCursor(t *testing.T) {
	wsID := uuid.New()
	pag := &PaginationRequest{
		IsCursor: true,
		Offset:   0,
		Count:    0,
	}
	resp := buildListResponse(pag, wsID, 10, []map[string]any{})
	if _, exists := resp["nextCursor"]; exists {
		t.Fatalf("expected nextCursor to be omitted when count=0 (0 resources returned), got %v", resp["nextCursor"])
	}
}

func TestBuildListResponse_PreviousCursorUsesPrevPageSize(t *testing.T) {
	wsID := uuid.New()

	// Page 1: offset=0, count=5 -> 5 resources returned out of 10
	pag1 := &PaginationRequest{
		IsCursor: true,
		Offset:   0,
		Count:    5,
	}
	page1Resources := []map[string]any{
		{"id": "1"}, {"id": "2"}, {"id": "3"}, {"id": "4"}, {"id": "5"},
	}
	resp1 := buildListResponse(pag1, wsID, 10, page1Resources)
	nextCur1, ok := resp1["nextCursor"].(string)
	if !ok || nextCur1 == "" {
		t.Fatalf("expected nextCursor on page 1")
	}

	// Page 2: client uses nextCur1 but changes count=2
	pag2, scimErr := parsePagination(url.Values{
		"cursor": []string{nextCur1},
		"count":  []string{"2"},
	}, nil, wsID, 10)
	if scimErr != nil {
		t.Fatalf("parsePagination failed: %v", scimErr)
	}
	if pag2.Offset != 5 || pag2.PrevPageSize != 5 || pag2.Count != 2 {
		t.Fatalf("got Offset=%d PrevPageSize=%d Count=%d, want Offset=5 PrevPageSize=5 Count=2",
			pag2.Offset, pag2.PrevPageSize, pag2.Count)
	}

	resp2 := buildListResponse(pag2, wsID, 10, []map[string]any{{"id": "6"}, {"id": "7"}})
	prevCur2, ok := resp2["previousCursor"].(string)
	if !ok || prevCur2 == "" {
		t.Fatalf("expected previousCursor on page 2")
	}
	prevOffset, err := scim.DecodeCursor(prevCur2, wsID)
	if err != nil {
		t.Fatalf("DecodeCursor(previousCursor) failed: %v", err)
	}
	if prevOffset != 0 {
		t.Fatalf("previousCursor offset = %d, want 0 (stepped back by PrevPageSize=5, not current Count=2)", prevOffset)
	}
}


