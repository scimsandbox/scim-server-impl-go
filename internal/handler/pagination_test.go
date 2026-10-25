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
