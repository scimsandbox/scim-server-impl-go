package handler

import (
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"regexp"
	"strings"

	"github.com/google/uuid"

	"github.com/scimsandbox/scim-server-impl-go/internal/model"
	"github.com/scimsandbox/scim-server-impl-go/internal/scim"
)

const (
	bulkRequestSchema   = "urn:ietf:params:scim:api:messages:2.0:BulkRequest"
	userCollectionPath  = "/Users/"
	groupCollectionPath = "/Groups/"
	userNotFoundDetail  = "User not found"
	groupNotFoundDetail = "Group not found"
	maxOperations       = 1000
	maxBulkPayloadBytes = 1048576 // 1 MB
	maxPayloadSize      = maxBulkPayloadBytes
)

var bulkIdTokenRe = regexp.MustCompile(`bulkId:([^\s"'/\]\[,]+)`)

type BulkHandler struct {
	userHandler  *UserHandler
	groupHandler *GroupHandler
}

func NewBulkHandler(userHandler *UserHandler, groupHandler *GroupHandler) *BulkHandler {
	return &BulkHandler{
		userHandler:  userHandler,
		groupHandler: groupHandler,
	}
}

type bulkFixupKind int

const (
	bulkFixupGroupMembers bulkFixupKind = iota + 1
	bulkFixupUserManager
)

type deferredBulkFixup struct {
	kind           bulkFixupKind
	origIdx        int
	resourceID     uuid.UUID
	bulkID         string
	deferredMembers []map[string]any
	deferredMgr    any
}

type createdPostRecord struct {
	origIdx      int
	resourceType bulkResourceType
	resourceID   uuid.UUID
	bulkID       string
	depBulkIDs   []string
	rolledBack   bool
}

func (h *BulkHandler) ProcessBulk(w http.ResponseWriter, r *http.Request) {
	wsID, err := resolveWorkspaceID(r)
	if err != nil {
		scim.WriteScimError(w, scim.NewScimError(http.StatusNotFound, "", "Workspace not found"))
		return
	}

	var body map[string]any
	if err := readJSONWithLimit(w, r, maxBulkPayloadBytes, &body); err != nil {
		var maxBytesErr *http.MaxBytesError
		if errors.As(err, &maxBytesErr) {
			scim.WriteScimError(w, scim.NewScimError(http.StatusRequestEntityTooLarge, "",
				fmt.Sprintf("Bulk request exceeds maxPayloadSize (%d bytes)", maxBulkPayloadBytes)))
			return
		}
		scim.WriteScimError(w, scim.NewScimError(http.StatusBadRequest, "invalidSyntax", "Invalid JSON"))
		return
	}

	// Validate schema
	schemas, _ := body["schemas"].([]any)
	validSchema := false
	for _, s := range schemas {
		if s == bulkRequestSchema {
			validSchema = true
			break
		}
	}
	if !validSchema {
		scim.WriteScimError(w, scim.NewScimError(http.StatusBadRequest, "invalidValue",
			"Bulk request must include BulkRequest schema"))
		return
	}

	rawOps, _ := body["Operations"].([]any)
	if rawOps == nil {
		scim.WriteScimError(w, scim.NewScimError(http.StatusBadRequest, "invalidValue",
			"Bulk request must contain Operations"))
		return
	}
	if len(rawOps) > maxOperations {
		scim.WriteScimError(w, scim.NewScimError(http.StatusRequestEntityTooLarge, "",
			fmt.Sprintf("Bulk request exceeds maxOperations (%d)", maxOperations)))
		return
	}

	failOnErrors := 0
	if v, ok := body["failOnErrors"]; ok {
		if n, ok := v.(float64); ok {
			failOnErrors = int(n)
		}
	}

	ops := make([]map[string]any, len(rawOps))
	producerByBulkID := make(map[string]int)
	for i, rawOp := range rawOps {
		opMap, ok := rawOp.(map[string]any)
		if !ok {
			continue
		}
		ops[i] = opMap
		rawMethod, _ := opMap["method"].(string)
		bid, _ := opMap["bulkId"].(string)
		bid = strings.TrimSpace(bid)
		if strings.EqualFold(rawMethod, "POST") && bid != "" {
			if _, exists := producerByBulkID[bid]; !exists {
				producerByBulkID[bid] = i
			}
		}
	}

	producerClosure := computePostProducerClosure(ops, producerByBulkID)
	execOrder := computeBulkExecutionOrder(ops, producerByBulkID)

	bulkIdMap := make(map[string]string)
	indexedResults := make([]map[string]any, len(rawOps))
	var fixups []deferredBulkFixup
	createdPosts := make(map[int]*createdPostRecord)
	completedOps := make(map[int]bool, len(rawOps))
	rolledBackBulkIDs := make(map[string]bool)
	baseURL := buildBaseURL(r)
	errorCount := 0

	for _, origIdx := range execOrder {
		if failOnErrors > 0 && errorCount >= failOnErrors {
			break
		}
		op := ops[origIdx]
		if op == nil {
			completedOps[origIdx] = true
			continue
		}

		var createdRec *createdPostRecord
		res := h.processOperationInternal(r, op, origIdx, wsID, bulkIdMap, producerByBulkID, &fixups, &createdRec)
		indexedResults[origIdx] = res
		if createdRec != nil {
			createdPosts[origIdx] = createdRec
		}
		completedOps[origIdx] = true

		if isErrorResult(res) {
			errorCount++
		}

		// Eagerly resolve any deferred fixups whose entire POST dependency closure has completed
		if len(fixups) > 0 {
			var readyFixups []deferredBulkFixup
			var remainingFixups []deferredBulkFixup
			for _, fx := range fixups {
				ready := true
				for p := range producerClosure[fx.origIdx] {
					if !completedOps[p] {
						ready = false
						break
					}
				}
				if ready {
					readyFixups = append(readyFixups, fx)
				} else {
					remainingFixups = append(remainingFixups, fx)
				}
			}
			if len(readyFixups) > 0 {
				fixups = remainingFixups
				rollbackErrs := h.applyDeferredBulkFixups(r, wsID, baseURL, bulkIdMap, indexedResults, readyFixups, createdPosts, rolledBackBulkIDs)
				errorCount += rollbackErrs
			}
		}

		if failOnErrors > 0 && errorCount >= failOnErrors {
			break
		}
	}

	// Resolve any remaining deferred cyclic bulkId references (e.g. if loop broke early on failOnErrors)
	if len(fixups) > 0 {
		h.applyDeferredBulkFixups(r, wsID, baseURL, bulkIdMap, indexedResults, fixups, createdPosts, rolledBackBulkIDs)
	}

	results := make([]map[string]any, 0, len(rawOps))
	for i := range indexedResults {
		if indexedResults[i] != nil {
			results = append(results, indexedResults[i])
		}
	}

	response := map[string]any{
		"schemas":    []string{"urn:ietf:params:scim:api:messages:2.0:BulkResponse"},
		"Operations": results,
	}

	writeJSON(w, http.StatusOK, response)
}

func computePostProducerClosure(ops []map[string]any, producerByBulkID map[string]int) map[int]map[int]bool {
	directDeps := make(map[int][]int)
	for _, prodIdx := range producerByBulkID {
		op := ops[prodIdx]
		if op == nil {
			continue
		}
		seen := make(map[int]bool)
		for _, ref := range extractBulkIDRefs(op["path"]) {
			if depIdx, ok := producerByBulkID[ref]; ok && !seen[depIdx] {
				seen[depIdx] = true
				directDeps[prodIdx] = append(directDeps[prodIdx], depIdx)
			}
		}
		for _, ref := range extractBulkIDRefs(op["data"]) {
			if depIdx, ok := producerByBulkID[ref]; ok && !seen[depIdx] {
				seen[depIdx] = true
				directDeps[prodIdx] = append(directDeps[prodIdx], depIdx)
			}
		}
	}

	closure := make(map[int]map[int]bool, len(producerByBulkID))
	for _, prodIdx := range producerByBulkID {
		visited := make(map[int]bool)
		queue := []int{prodIdx}
		visited[prodIdx] = true
		for len(queue) > 0 {
			curr := queue[0]
			queue = queue[1:]
			for _, nxt := range directDeps[curr] {
				if !visited[nxt] {
					visited[nxt] = true
					queue = append(queue, nxt)
				}
			}
		}
		closure[prodIdx] = visited
	}
	return closure
}

func computeBulkExecutionOrder(ops []map[string]any, producerByBulkID map[string]int) []int {
	n := len(ops)
	if n <= 1 || len(producerByBulkID) == 0 {
		order := make([]int, n)
		for i := 0; i < n; i++ {
			order[i] = i
		}
		return order
	}

	producerClosure := computePostProducerClosure(ops, producerByBulkID)
	dependents := make([][]int, n)
	inDegree := make([]int, n)
	lastOpForResource := make(map[string]int)

	for i, op := range ops {
		if op == nil {
			continue
		}
		seenProducers := make(map[int]bool)
		addEdge := func(from, to int) {
			if from != to && !seenProducers[from] {
				seenProducers[from] = true
				dependents[from] = append(dependents[from], to)
				inDegree[to]++
			}
		}

		if rawPath, ok := op["path"].(string); ok {
			if segs, err := normalizeBulkPath(rawPath); err == nil && len(segs) >= 2 {
				normPath := strings.ToLower(segs[0]) + "/" + segs[1]
				if prevIdx, exists := lastOpForResource[normPath]; exists {
					addEdge(prevIdx, i)
				}
				lastOpForResource[normPath] = i
			}
		}

		addRefEdges := func(ref string) {
			prodIdx, ok := producerByBulkID[ref]
			if !ok {
				return
			}
			addEdge(prodIdx, i)
			// If operation i is not part of prodIdx's cycle/closure, require the entire
			// POST dependency closure of prodIdx to complete before operation i executes.
			if !producerClosure[prodIdx][i] {
				for p := range producerClosure[prodIdx] {
					addEdge(p, i)
				}
			}
		}

		for _, ref := range extractBulkIDRefs(op["path"]) {
			addRefEdges(ref)
		}
		for _, ref := range extractBulkIDRefs(op["data"]) {
			addRefEdges(ref)
		}
	}

	isPostOp := func(idx int) bool {
		if ops[idx] == nil {
			return false
		}
		m, _ := ops[idx]["method"].(string)
		return strings.EqualFold(strings.TrimSpace(m), "POST")
	}

	scheduled := make([]bool, n)
	order := make([]int, 0, n)

	for len(order) < n {
		chosen := -1
		for i := 0; i < n; i++ {
			if !scheduled[i] && inDegree[i] == 0 {
				chosen = i
				break
			}
		}
		if chosen == -1 {
			// Cycle detected: pick the earliest unscheduled POST operation so Phase 1 can create
			// its resource ID and defer its cyclic reference to Phase 2.
			for i := 0; i < n; i++ {
				if !scheduled[i] && isPostOp(i) {
					chosen = i
					break
				}
			}
			if chosen == -1 {
				for i := 0; i < n; i++ {
					if !scheduled[i] {
						chosen = i
						break
					}
				}
			}
		}

		scheduled[chosen] = true
		order = append(order, chosen)
		for _, dep := range dependents[chosen] {
			if inDegree[dep] > 0 {
				inDegree[dep]--
			}
		}
	}

	return order
}

func extractBulkIDRefs(v any) []string {
	var refs []string
	seen := make(map[string]bool)
	var walk func(any)
	walk = func(val any) {
		switch x := val.(type) {
		case string:
			if strings.HasPrefix(x, "bulkId:") && !strings.ContainsAny(x[7:], " \"'/][,") {
				ref := x[7:]
				if ref != "" && !seen[ref] {
					seen[ref] = true
					refs = append(refs, ref)
				}
				return
			}
			for _, m := range bulkIdTokenRe.FindAllStringSubmatch(x, -1) {
				if len(m) > 1 && m[1] != "" && !seen[m[1]] {
					seen[m[1]] = true
					refs = append(refs, m[1])
				}
			}
		case map[string]any:
			for _, mv := range x {
				walk(mv)
			}
		case []any:
			for _, item := range x {
				walk(item)
			}
		case []string:
			for _, s := range x {
				walk(s)
			}
		}
	}
	walk(v)
	return refs
}

func (h *BulkHandler) processOperation(r *http.Request, op map[string]any, wsID uuid.UUID, bulkIdMap map[string]string) map[string]any {
	return h.processOperationInternal(r, op, -1, wsID, bulkIdMap, nil, nil, nil)
}

func (h *BulkHandler) processOperationInternal(
	r *http.Request,
	op map[string]any,
	origIdx int,
	wsID uuid.UUID,
	bulkIdMap map[string]string,
	producerByBulkID map[string]int,
	fixups *[]deferredBulkFixup,
	createdOut **createdPostRecord,
) map[string]any {
	rawMethod, _ := op["method"].(string)
	method := strings.ToUpper(strings.TrimSpace(rawMethod))
	opPath, _ := op["path"].(string)
	bulkId, _ := op["bulkId"].(string)
	opVersion, _ := op["version"].(string)

	result := make(map[string]any)
	if bulkId != "" {
		result["bulkId"] = bulkId
	}
	result["method"] = method

	defer func() {
		if rv := recover(); rv != nil {
			slog.Error("panic in bulk operation", "method", method, "path", opPath, "error", rv)
			result["status"] = "500"
			result["response"] = buildBulkError("500", "", "Internal server error")
		}
	}()

	baseURL := buildBaseURL(r)

	// Resolve bulkId references in path first so target location can be computed accurately
	if opPath != "" {
		opPath = resolveBulkIdReferences(opPath, bulkIdMap)
	}

	// RFC 7644 §3.7.3: location is REQUIRED in a response except in the event of a POST failure.
	if method == "PUT" || method == "PATCH" || method == "DELETE" {
		if loc := computeBulkTargetLocation(baseURL, method, opPath); loc != "" {
			result["location"] = loc
		}
	}

	if method != "POST" && method != "PUT" && method != "PATCH" && method != "DELETE" {
		result["status"] = "400"
		result["response"] = buildBulkError("400", "invalidValue", "Unsupported method: "+method)
		return result
	}

	if method == "POST" && strings.TrimSpace(bulkId) == "" {
		result["status"] = "400"
		result["response"] = buildBulkError("400", "invalidValue", "bulkId is required for POST operations")
		return result
	}

	var data map[string]any
	if method == "POST" || method == "PUT" || method == "PATCH" {
		rawData, hasData := op["data"]
		dataMap, okMap := rawData.(map[string]any)
		if !hasData || rawData == nil || !okMap || len(dataMap) == 0 {
			result["status"] = "400"
			result["response"] = buildBulkError("400", "invalidSyntax", "data is required for "+method+" bulk operations")
			return result
		}
		allRefs := extractBulkIDRefs(dataMap)
		data = resolveBulkIdInData(dataMap, bulkIdMap)
		if method == "POST" {
			h.handleBulkPost(r, result, origIdx, opPath, data, allRefs, wsID, baseURL, bulkId, bulkIdMap, producerByBulkID, fixups, createdOut)
			return result
		}
	}

	switch method {
	case "PUT":
		h.handleBulkPut(r, result, opPath, data, opVersion, wsID, baseURL)
	case "PATCH":
		h.handleBulkPatch(r, result, opPath, data, opVersion, wsID, baseURL)
	case "DELETE":
		h.handleBulkDelete(r, result, opPath, opVersion, wsID)
	}

	return result
}

func computeBulkTargetLocation(baseURL, method, resolvedPath string) string {
	if method == "POST" {
		return ""
	}
	if target, err := parseBulkTarget(resolvedPath, true); err == nil {
		if target.resourceType == bulkResourceUsers {
			return baseURL + userCollectionPath + target.id.String()
		}
		return baseURL + groupCollectionPath + target.id.String()
	}
	if segments, err := normalizeBulkPath(resolvedPath); err == nil && len(segments) > 0 {
		seg0 := segments[0]
		if strings.EqualFold(seg0, "Users") {
			seg0 = "Users"
		} else if strings.EqualFold(seg0, "Groups") {
			seg0 = "Groups"
		}
		rest := append([]string{seg0}, segments[1:]...)
		return baseURL + "/" + strings.Join(rest, "/")
	}
	trimmed := strings.Trim(strings.TrimSpace(resolvedPath), "/")
	if trimmed != "" {
		return baseURL + "/" + trimmed
	}
	return ""
}

func (h *BulkHandler) handleBulkPost(
	r *http.Request,
	result map[string]any,
	origIdx int,
	rawPath string,
	data map[string]any,
	allDataBulkRefs []string,
	wsID uuid.UUID,
	baseURL string,
	bulkId string,
	bulkIdMap map[string]string,
	producerByBulkID map[string]int,
	fixups *[]deferredBulkFixup,
	createdOut **createdPostRecord,
) {
	target, err := parseBulkTarget(rawPath, false)
	if err != nil {
		setBulkError(result, err)
		return
	}

	switch target.resourceType {
	case bulkResourceUsers:
		phase1Data := data
		var deferredMgr any
		hasDeferredMgr := false
		if fixups != nil && len(producerByBulkID) > 0 {
			phase1Data, deferredMgr, hasDeferredMgr = extractDeferredUserManager(data, producerByBulkID, bulkId)
		}
		user, err := h.createUserInternal(r, wsID, baseURL, phase1Data)
		if err != nil {
			setBulkError(result, err)
			return
		}
		result["status"] = "201"
		result["location"] = baseURL + userCollectionPath + user.ID.String()
		result["version"] = fmt.Sprintf("W/\"%d\"", user.Version)
		if bulkId != "" {
			bulkIdMap[bulkId] = user.ID.String()
		}
		if createdOut != nil {
			*createdOut = &createdPostRecord{
				origIdx:      origIdx,
				resourceType: bulkResourceUsers,
				resourceID:   user.ID,
				bulkID:       bulkId,
				depBulkIDs:   allDataBulkRefs,
			}
		}
		if hasDeferredMgr && fixups != nil {
			*fixups = append(*fixups, deferredBulkFixup{
				kind:        bulkFixupUserManager,
				origIdx:     origIdx,
				resourceID:  user.ID,
				bulkID:      bulkId,
				deferredMgr: deferredMgr,
			})
		}

	case bulkResourceGroups:
		phase1Data := data
		var deferredMembers []map[string]any
		if fixups != nil && len(producerByBulkID) > 0 {
			phase1Data, deferredMembers = extractDeferredGroupMembers(data, producerByBulkID, bulkId)
		}
		group, err := h.createGroupInternal(r, wsID, phase1Data)
		if err != nil {
			setBulkError(result, err)
			return
		}
		result["status"] = "201"
		result["location"] = baseURL + groupCollectionPath + group.ID.String()
		result["version"] = fmt.Sprintf("W/\"%d\"", group.Version)
		if bulkId != "" {
			bulkIdMap[bulkId] = group.ID.String()
		}
		if createdOut != nil {
			*createdOut = &createdPostRecord{
				origIdx:      origIdx,
				resourceType: bulkResourceGroups,
				resourceID:   group.ID,
				bulkID:       bulkId,
				depBulkIDs:   allDataBulkRefs,
			}
		}
		if len(deferredMembers) > 0 && fixups != nil {
			*fixups = append(*fixups, deferredBulkFixup{
				kind:            bulkFixupGroupMembers,
				origIdx:         origIdx,
				resourceID:      group.ID,
				bulkID:          bulkId,
				deferredMembers: deferredMembers,
			})
		}
	}
}

func extractDeferredGroupMembers(data map[string]any, producerByBulkID map[string]int, selfBulkID string) (map[string]any, []map[string]any) {
	rawMembers, ok := data["members"].([]any)
	if !ok || len(rawMembers) == 0 {
		return data, nil
	}
	immediate := make([]any, 0, len(rawMembers))
	var deferred []map[string]any
	for _, m := range rawMembers {
		if mm, ok := m.(map[string]any); ok {
			valStr, _ := mm["value"].(string)
			if strings.HasPrefix(valStr, "bulkId:") {
				ref := valStr[7:]
				if ref != "" && ref != selfBulkID {
					if _, declared := producerByBulkID[ref]; declared {
						deferred = append(deferred, mm)
						continue
					}
				}
			}
		}
		immediate = append(immediate, m)
	}
	if len(deferred) == 0 {
		return data, nil
	}
	cloned := make(map[string]any, len(data))
	for k, v := range data {
		cloned[k] = v
	}
	cloned["members"] = immediate
	return cloned, deferred
}

func extractDeferredUserManager(data map[string]any, producerByBulkID map[string]int, selfBulkID string) (map[string]any, any, bool) {
	var entKey string
	var entMap map[string]any
	for k, v := range data {
		if strings.EqualFold(k, scim.EnterpriseSchemaURN) {
			if m, ok := v.(map[string]any); ok {
				entKey = k
				entMap = m
			}
			break
		}
	}
	if entMap == nil {
		return data, nil, false
	}
	rawMgr, exists := entMap["manager"]
	if !exists || rawMgr == nil {
		return data, nil, false
	}
	mgrVal := ""
	switch mv := rawMgr.(type) {
	case string:
		mgrVal = mv
	case map[string]any:
		mgrVal, _ = mv["value"].(string)
	}
	if !strings.HasPrefix(mgrVal, "bulkId:") {
		return data, nil, false
	}
	ref := mgrVal[7:]
	if ref == "" || ref == selfBulkID {
		return data, nil, false
	}
	if _, declared := producerByBulkID[ref]; !declared {
		return data, nil, false
	}

	clonedData := make(map[string]any, len(data))
	for k, v := range data {
		clonedData[k] = v
	}
	clonedEnt := make(map[string]any, len(entMap))
	for k, v := range entMap {
		if !strings.EqualFold(k, "manager") {
			clonedEnt[k] = v
		}
	}
	clonedData[entKey] = clonedEnt
	return clonedData, rawMgr, true
}

func (h *BulkHandler) applyDeferredBulkFixups(
	r *http.Request,
	wsID uuid.UUID,
	baseURL string,
	bulkIdMap map[string]string,
	indexedResults []map[string]any,
	fixups []deferredBulkFixup,
	createdPosts map[int]*createdPostRecord,
	rolledBackBulkIDs map[string]bool,
) int {
	if rolledBackBulkIDs == nil {
		rolledBackBulkIDs = make(map[string]bool)
	}
	rollbackErrors := 0

	rollbackRecord := func(rec *createdPostRecord, err error) {
		if rec == nil || rec.rolledBack {
			return
		}
		rec.rolledBack = true
		if rec.bulkID != "" {
			delete(bulkIdMap, rec.bulkID)
			rolledBackBulkIDs[rec.bulkID] = true
		}
		if rec.resourceType == bulkResourceGroups {
			if h.groupHandler != nil {
				if h.groupHandler.membershipRepo != nil {
					_ = h.groupHandler.membershipRepo.DeleteByMemberValue(r.Context(), rec.resourceID)
					_ = h.groupHandler.membershipRepo.DeleteByGroupID(r.Context(), rec.resourceID)
				}
				if h.groupHandler.groupRepo != nil {
					_ = h.groupHandler.groupRepo.Delete(r.Context(), rec.resourceID, wsID)
				}
			}
		} else if rec.resourceType == bulkResourceUsers {
			if h.userHandler != nil {
				if h.userHandler.membershipRepo != nil {
					_ = h.userHandler.membershipRepo.DeleteByMemberValue(r.Context(), rec.resourceID)
				}
				if h.userHandler.userRepo != nil {
					_ = h.userHandler.userRepo.Delete(r.Context(), rec.resourceID, wsID)
				}
			}
		}
		if rec.origIdx >= 0 && rec.origIdx < len(indexedResults) && indexedResults[rec.origIdx] != nil {
			res := indexedResults[rec.origIdx]
			wasError := isErrorResult(res)
			delete(res, "location")
			delete(res, "version")
			setBulkError(res, err)
			if !wasError && isErrorResult(res) {
				rollbackErrors++
			}
		}
	}

	for _, fx := range fixups {
		rec := createdPosts[fx.origIdx]
		if rec != nil && rec.rolledBack {
			continue
		}
		switch fx.kind {
		case bulkFixupGroupMembers:
			seen := make(map[string]bool)
			var fixErr error
			for _, rawMember := range fx.deferredMembers {
				resolvedMember := resolveBulkIdInData(rawMember, bulkIdMap)
				mv, _ := resolvedMember["value"].(string)
				if mv != "" {
					if mu, pErr := uuid.Parse(mv); pErr == nil {
						mv = mu.String()
					}
					if seen[mv] {
						continue
					}
					seen[mv] = true
				}
				if err := h.groupHandler.addMemberTx(r.Context(), nil, fx.resourceID, wsID, resolvedMember); err != nil {
					fixErr = err
					break
				}
			}
			if fixErr != nil {
				rollbackRecord(rec, fixErr)
			}

		case bulkFixupUserManager:
			resolvedMgr := resolveValue(fx.deferredMgr, bulkIdMap)
			mgrIDStr := ""
			mgrRefStr := ""
			switch mv := resolvedMgr.(type) {
			case string:
				mgrIDStr = mv
			case map[string]any:
				mgrIDStr, _ = mv["value"].(string)
				mgrRefStr, _ = mv["$ref"].(string)
			}
			mgrUUID, parseErr := uuid.Parse(strings.TrimSpace(mgrIDStr))
			if parseErr != nil {
				rollbackRecord(rec, scim.NewScimError(http.StatusBadRequest, "invalidValue", "Invalid manager reference: "+mgrIDStr))
				continue
			}
			user, uErr := h.userHandler.userRepo.FindByIDAndWorkspaceID(r.Context(), fx.resourceID, wsID)
			if uErr != nil || user == nil {
				rollbackRecord(rec, scim.NewScimError(http.StatusInternalServerError, "", "Failed to resolve deferred user manager"))
				continue
			}
			valCopy := mgrUUID.String()
			user.EnterpriseManagerValue = &valCopy
			if mgrRefStr != "" {
				user.EnterpriseManagerRef = &mgrRefStr
			}
			h.userHandler.resolveManagerMetadata(r.Context(), user, wsID, baseURL)
			if err := h.userHandler.userRepo.Update(r.Context(), user); err != nil {
				rollbackRecord(rec, scim.NewScimError(http.StatusInternalServerError, "", "Failed to update deferred user manager"))
				continue
			}
			if fx.origIdx >= 0 && fx.origIdx < len(indexedResults) && indexedResults[fx.origIdx] != nil {
				indexedResults[fx.origIdx]["version"] = fmt.Sprintf("W/\"%d\"", user.Version)
			}
		}
	}

	// Cascade rollback to any Phase-1 POST whose data depended on a rolled-back bulkId
	if len(rolledBackBulkIDs) > 0 {
		changed := true
		for changed {
			changed = false
			for _, rec := range createdPosts {
				if rec.rolledBack {
					continue
				}
				for _, dep := range rec.depBulkIDs {
					if rolledBackBulkIDs[dep] {
						rollbackRecord(rec, scim.NewScimError(http.StatusBadRequest, "invalidValue", "Referenced bulkId failed: "+dep))
						changed = true
						break
					}
				}
			}
		}
	}

	return rollbackErrors
}

func (h *BulkHandler) handleBulkPut(r *http.Request, result map[string]any, rawPath string, data map[string]any, opVersion string, wsID uuid.UUID, baseURL string) {
	target, err := parseBulkTarget(rawPath, true)
	if err != nil {
		setBulkError(result, err)
		return
	}

	switch target.resourceType {
	case bulkResourceUsers:
		ver, err := h.replaceUserInternal(r, wsID, target.id, baseURL, data, opVersion)
		if err != nil {
			setBulkError(result, err)
			return
		}
		result["status"] = "200"
		result["location"] = baseURL + userCollectionPath + target.id.String()
		result["version"] = fmt.Sprintf("W/\"%d\"", ver)
	case bulkResourceGroups:
		ver, err := h.replaceGroupInternal(r, wsID, target.id, data, opVersion)
		if err != nil {
			setBulkError(result, err)
			return
		}
		result["status"] = "200"
		result["location"] = baseURL + groupCollectionPath + target.id.String()
		result["version"] = fmt.Sprintf("W/\"%d\"", ver)
	}
}

func (h *BulkHandler) handleBulkPatch(r *http.Request, result map[string]any, rawPath string, data map[string]any, opVersion string, wsID uuid.UUID, baseURL string) {
	target, err := parseBulkTarget(rawPath, true)
	if err != nil {
		setBulkError(result, err)
		return
	}

	ops, _ := data["Operations"].([]any)
	if len(ops) == 0 {
		setBulkError(result, scim.NewScimError(http.StatusBadRequest, "invalidValue", "PATCH Operations is required"))
		return
	}
	operations := make([]map[string]any, 0, len(ops))
	for _, o := range ops {
		m, ok := o.(map[string]any)
		if !ok {
			setBulkError(result, scim.NewScimError(http.StatusBadRequest, "invalidSyntax", "Invalid PATCH operation"))
			return
		}
		operations = append(operations, m)
	}

	switch target.resourceType {
	case bulkResourceUsers:
		ver, err := h.patchUserInternal(r, wsID, target.id, baseURL, operations, opVersion)
		if err != nil {
			setBulkError(result, err)
			return
		}
		result["status"] = "200"
		result["location"] = baseURL + userCollectionPath + target.id.String()
		result["version"] = fmt.Sprintf("W/\"%d\"", ver)
	case bulkResourceGroups:
		ver, err := h.patchGroupInternal(r, wsID, target.id, operations, opVersion)
		if err != nil {
			setBulkError(result, err)
			return
		}
		result["status"] = "200"
		result["location"] = baseURL + groupCollectionPath + target.id.String()
		result["version"] = fmt.Sprintf("W/\"%d\"", ver)
	}
}

func (h *BulkHandler) handleBulkDelete(r *http.Request, result map[string]any, rawPath string, opVersion string, wsID uuid.UUID) {
	target, err := parseBulkTarget(rawPath, true)
	if err != nil {
		setBulkError(result, err)
		return
	}

	switch target.resourceType {
	case bulkResourceUsers:
		err := h.deleteUserInternal(r, wsID, target.id, opVersion)
		if err != nil {
			setBulkError(result, err)
			return
		}
		result["status"] = "204"
	case bulkResourceGroups:
		err := h.deleteGroupInternal(r, wsID, target.id, opVersion)
		if err != nil {
			setBulkError(result, err)
			return
		}
		result["status"] = "204"
	}
}

// Internal helpers that delegate to UserHandler and GroupHandler execute* methods

func (h *BulkHandler) createUserInternal(r *http.Request, wsID uuid.UUID, baseURL string, data map[string]any) (*model.ScimUser, error) {
	return h.userHandler.executeCreateUser(r.Context(), wsID, baseURL, data)
}

func (h *BulkHandler) createGroupInternal(r *http.Request, wsID uuid.UUID, data map[string]any) (*model.ScimGroup, error) {
	return h.groupHandler.executeCreateGroup(r.Context(), wsID, data)
}

func (h *BulkHandler) replaceUserInternal(r *http.Request, wsID, userID uuid.UUID, baseURL string, data map[string]any, opVersion string) (int64, error) {
	user, err := h.userHandler.executeReplaceUser(r.Context(), wsID, userID, baseURL, data, opVersion)
	if err != nil {
		return 0, err
	}
	return user.Version, nil
}

func (h *BulkHandler) replaceGroupInternal(r *http.Request, wsID, groupID uuid.UUID, data map[string]any, opVersion string) (int64, error) {
	group, err := h.groupHandler.executeReplaceGroup(r.Context(), wsID, groupID, data, opVersion)
	if err != nil {
		return 0, err
	}
	return group.Version, nil
}

func (h *BulkHandler) patchUserInternal(r *http.Request, wsID, userID uuid.UUID, baseURL string, operations []map[string]any, opVersion string) (int64, error) {
	user, err := h.userHandler.executePatchUser(r.Context(), wsID, userID, baseURL, operations, opVersion)
	if err != nil {
		return 0, err
	}
	return user.Version, nil
}

func (h *BulkHandler) patchGroupInternal(r *http.Request, wsID, groupID uuid.UUID, operations []map[string]any, opVersion string) (int64, error) {
	group, err := h.groupHandler.executePatchGroup(r.Context(), wsID, groupID, operations, opVersion)
	if err != nil {
		return 0, err
	}
	return group.Version, nil
}

func (h *BulkHandler) deleteUserInternal(r *http.Request, wsID, userID uuid.UUID, opVersion string) error {
	return h.userHandler.executeDeleteUser(r.Context(), wsID, userID, opVersion)
}

func (h *BulkHandler) deleteGroupInternal(r *http.Request, wsID, groupID uuid.UUID, opVersion string) error {
	return h.groupHandler.executeDeleteGroup(r.Context(), wsID, groupID, opVersion)
}

// Helpers

type bulkResourceType int

const (
	bulkResourceUnknown bulkResourceType = iota
	bulkResourceUsers
	bulkResourceGroups
)

type bulkPathTarget struct {
	resourceType bulkResourceType
	id           uuid.UUID
}

func normalizeBulkPath(rawPath string) ([]string, error) {
	trimmed := strings.TrimSpace(rawPath)
	if trimmed == "" {
		return nil, nil
	}
	stripped := strings.Trim(trimmed, "/")
	if stripped == "" {
		return []string{}, nil
	}
	rawSegments := strings.Split(stripped, "/")
	segments := make([]string, 0, len(rawSegments))
	for _, seg := range rawSegments {
		if seg == "" {
			continue // collapse multiple consecutive slashes
		}
		if seg == "." || seg == ".." {
			return nil, &scim.ScimError{
				Status:   http.StatusBadRequest,
				ScimType: "invalidPath",
				Detail:   "Path traversal segments ('.' or '..') are not allowed: " + rawPath,
			}
		}
		segments = append(segments, seg)
	}
	return segments, nil
}

func parseBulkTarget(rawPath string, isItemRequired bool) (*bulkPathTarget, error) {
	segments, err := normalizeBulkPath(rawPath)
	if err != nil {
		return nil, err
	}
	if len(segments) == 0 {
		return nil, &scim.ScimError{
			Status:   http.StatusBadRequest,
			ScimType: "invalidPath",
			Detail:   "Bulk path cannot be empty: " + rawPath,
		}
	}

	var rType bulkResourceType
	if strings.EqualFold(segments[0], "Users") {
		rType = bulkResourceUsers
	} else if strings.EqualFold(segments[0], "Groups") {
		rType = bulkResourceGroups
	} else {
		return nil, &scim.ScimError{
			Status:   http.StatusBadRequest,
			ScimType: "invalidValue",
			Detail:   "Unknown resource path: " + rawPath,
		}
	}

	if isItemRequired {
		if len(segments) != 2 || segments[1] == "" {
			return nil, &scim.ScimError{
				Status:   http.StatusBadRequest,
				ScimType: "invalidPath",
				Detail:   "Bulk path must include resource ID: " + rawPath,
			}
		}
		if len(segments[1]) != 36 {
			return nil, &scim.ScimError{
				Status:   http.StatusBadRequest,
				ScimType: "invalidValue",
				Detail:   "Invalid resource ID: " + segments[1],
			}
		}
		id, err := uuid.Parse(segments[1])
		if err != nil {
			return nil, &scim.ScimError{
				Status:   http.StatusBadRequest,
				ScimType: "invalidValue",
				Detail:   "Invalid resource ID: " + segments[1],
			}
		}
		return &bulkPathTarget{resourceType: rType, id: id}, nil
	}

	if len(segments) != 1 {
		return nil, &scim.ScimError{
			Status:   http.StatusBadRequest,
			ScimType: "invalidPath",
			Detail:   "Bulk POST must specify a resource type endpoint: " + rawPath,
		}
	}

	return &bulkPathTarget{resourceType: rType}, nil
}

func resolveBulkIdReferences(s string, bulkIdMap map[string]string) string {
	if len(bulkIdMap) == 0 || !strings.Contains(s, "bulkId:") {
		return s
	}
	if strings.HasPrefix(s, "bulkId:") {
		if resolved, ok := bulkIdMap[s[7:]]; ok {
			return resolved
		}
	}
	return bulkIdTokenRe.ReplaceAllStringFunc(s, func(match string) string {
		key := match[7:]
		if resolved, ok := bulkIdMap[key]; ok {
			return resolved
		}
		return match
	})
}

func resolveBulkIdInData(data map[string]any, bulkIdMap map[string]string) map[string]any {
	resolved := make(map[string]any, len(data))
	for k, v := range data {
		resolved[k] = resolveValue(v, bulkIdMap)
	}
	return resolved
}

func resolveValue(value any, bulkIdMap map[string]string) any {
	switch v := value.(type) {
	case string:
		return resolveBulkIdReferences(v, bulkIdMap)
	case map[string]any:
		return resolveBulkIdInData(v, bulkIdMap)
	case []any:
		result := make([]any, len(v))
		for i, item := range v {
			result[i] = resolveValue(item, bulkIdMap)
		}
		return result
	default:
		return value
	}
}

func isErrorResult(result map[string]any) bool {
	status, _ := result["status"].(string)
	if status == "" {
		return false
	}
	if len(status) > 0 && status[0] >= '4' {
		return true
	}
	return false
}

func setBulkError(result map[string]any, err error) {
	var se *scim.ScimError
	if errors.As(err, &se) {
		result["status"] = fmt.Sprintf("%d", se.Status)
		result["response"] = buildBulkError(fmt.Sprintf("%d", se.Status), se.ScimType, se.Detail)
	} else {
		result["status"] = "500"
		result["response"] = buildBulkError("500", "", "Internal server error")
	}
}

func buildBulkError(status, scimType, detail string) map[string]any {
	err := map[string]any{
		"schemas": []string{"urn:ietf:params:scim:api:messages:2.0:Error"},
		"status":  status,
	}
	if scimType != "" {
		err["scimType"] = scimType
	}
	if detail != "" {
		err["detail"] = detail
	}
	return err
}
