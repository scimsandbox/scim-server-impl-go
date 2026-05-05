package scim

import (
	"fmt"
	"regexp"
	"strings"
	"unicode"
)

// FilterResult holds a SQL WHERE clause fragment and its parameter values.
type FilterResult struct {
	SQL  string
	Args []any
}

const (
	entityTypeUser  = "user"
	entityTypeGroup = "group"

	filterOpAnd = "and"
	filterOpOr  = "or"
	filterOpNot = "not"
	filterOpPr  = "pr"
	filterOpEq  = "eq"
	filterOpNe  = "ne"
	filterOpCo  = "co"
	filterOpSw  = "sw"
	filterOpEw  = "ew"
	filterOpGt  = "gt"
	filterOpGe  = "ge"
	filterOpLt  = "lt"
	filterOpLe  = "le"

	attrUsername              = "username"
	attrDisplayName           = "displayname"
	attrExternalID            = "externalid"
	attrProfileURL            = "profileurl"
	attrNameFamilyName        = "name.familyname"
	attrNameGivenName         = "name.givenname"
	attrNameFormatted         = "name.formatted"
	attrNameMiddleName        = "name.middlename"
	attrNameHonorificPrefix   = "name.honorificprefix"
	attrNameHonorificSuffix   = "name.honorificsuffix"
	attrNickname              = "nickname"
	attrTitle                 = "title"
	attrUserType              = "usertype"
	attrPreferredLanguage     = "preferredlanguage"
	attrLocale                = "locale"
	attrTimeZone              = "timezone"
	attrActive                = "active"
	attrMetaCreated           = "meta.created"
	attrMetaLastModified      = "meta.lastmodified"
	attrID                    = "id"
	attrEmployeeNumber        = "employeenumber"
	attrCostCenter            = "costcenter"
	attrOrganization          = "organization"
	attrDivision              = "division"
	attrDepartment            = "department"
	attrManagerValue          = "manager.value"
	attrManagerDisplayName    = "manager.displayname"
	attrMembersValue          = "members.value"
	attrEmailsValue           = "emails.value"
	attrEmailsType            = "emails.type"
	attrPhoneNumbersValue     = "phonenumbers.value"
	attrPhoneNumbersType      = "phonenumbers.type"
	attrImsValue              = "ims.value"
	attrImsType               = "ims.type"
	attrAddressesType         = "addresses.type"
	attrPhotosValue           = "photos.value"
	attrPhotosType            = "photos.type"
	attrRolesValue            = "roles.value"
	attrEntitlementsValue     = "entitlements.value"
	attrX509CertificatesValue = "x509certificates.value"

	jsonCollectionEmails           = "emails"
	jsonCollectionPhoneNumbers     = "phonenumbers"
	jsonCollectionAddresses        = "addresses"
	jsonCollectionIms              = "ims"
	jsonCollectionPhotos           = "photos"
	jsonCollectionEntitlements     = "entitlements"
	jsonCollectionRoles            = "roles"
	jsonCollectionX509Certificates = "x509certificates"

	sqlUserName                 = "user_name"
	sqlNameFamilyName           = "name_family_name"
	sqlNameGivenName            = "name_given_name"
	sqlNameFormatted            = "name_formatted"
	sqlNameMiddleName           = "name_middle_name"
	sqlNameHonorificPrefix      = "name_honorific_prefix"
	sqlNameHonorificSuffix      = "name_honorific_suffix"
	sqlDisplayName              = "display_name"
	sqlExternalID               = "external_id"
	sqlNickName                 = "nick_name"
	sqlProfileURL               = "profile_url"
	sqlTitle                    = "title"
	sqlUserType                 = "user_type"
	sqlPreferredLanguage        = "preferred_language"
	sqlLocale                   = "locale"
	sqlTimeZone                 = "timezone"
	sqlActive                   = "active"
	sqlCreatedAt                = "created_at"
	sqlLastModified             = "last_modified"
	sqlID                       = "id"
	sqlEnterpriseEmployeeNumber = "enterprise_employee_number"
	sqlEnterpriseCostCenter     = "enterprise_cost_center"
	sqlEnterpriseOrganization   = "enterprise_organization"
	sqlEnterpriseDivision       = "enterprise_division"
	sqlEnterpriseDepartment     = "enterprise_department"
	sqlEnterpriseManagerValue   = "enterprise_manager_value"
	sqlEnterpriseManagerDisplay = "enterprise_manager_display"
	sqlMemberValue              = "member_value"

	sqlLowerPrefix             = "LOWER("
	sqlLowerLikeSeparator      = ") LIKE LOWER("
	sqlLike                    = " LIKE "
	sqlTextCast                = "::text"
	sqlTextLike                = sqlTextCast + sqlLike
	sqlTextLowerLikeSeparator  = sqlTextCast + sqlLowerLikeSeparator
	sqlIsNotNull               = " IS NOT NULL"
	sqlIsNotNullAnd            = sqlIsNotNull + " AND "
	sqlTextNotEqualsEmptyArray = sqlTextCast + " != '[]'"
)

// ParseUserFilter parses a SCIM filter string and returns a SQL WHERE clause
// for scim_users. The parameter placeholders start at $startParam.
func ParseUserFilter(filter string, startParam int) (*FilterResult, error) {
	if filter == "" {
		return nil, nil
	}
	p := &filterParser{
		tokens:     tokenize(filter),
		pos:        0,
		paramIdx:   startParam,
		entityType: entityTypeUser,
	}
	result, err := p.parseOrExpression()
	if err != nil {
		return nil, NewScimError(400, "invalidFilter", "Invalid filter: "+err.Error())
	}
	return result, nil
}

// ParseGroupFilter parses a SCIM filter for scim_groups.
func ParseGroupFilter(filter string, startParam int) (*FilterResult, error) {
	if filter == "" {
		return nil, nil
	}
	p := &filterParser{
		tokens:     tokenize(filter),
		pos:        0,
		paramIdx:   startParam,
		entityType: entityTypeGroup,
	}
	result, err := p.parseOrExpression()
	if err != nil {
		return nil, NewScimError(400, "invalidFilter", "Invalid filter: "+err.Error())
	}
	return result, nil
}

// ResolveUserSortAttribute maps SCIM sort attribute names to SQL column names.
func ResolveUserSortAttribute(sortBy string) string {
	attr := stripURNPrefix(sortBy)
	switch strings.ToLower(attr) {
	case attrUsername:
		return sqlUserName
	case attrNameFamilyName:
		return sqlNameFamilyName
	case attrNameGivenName:
		return sqlNameGivenName
	case attrDisplayName:
		return sqlDisplayName
	case attrTitle:
		return sqlTitle
	case attrMetaCreated:
		return sqlCreatedAt
	case attrMetaLastModified:
		return sqlLastModified
	case attrExternalID:
		return sqlExternalID
	case attrActive:
		return sqlActive
	default:
		return sqlUserName
	}
}

// ResolveGroupSortAttribute maps SCIM sort attribute names to SQL column names for groups.
func ResolveGroupSortAttribute(sortBy string) string {
	attr := stripURNPrefix(sortBy)
	switch strings.ToLower(attr) {
	case attrDisplayName:
		return sqlDisplayName
	case attrMetaCreated:
		return sqlCreatedAt
	case attrMetaLastModified:
		return sqlLastModified
	case attrExternalID:
		return sqlExternalID
	default:
		return sqlDisplayName
	}
}

// ── Token types ───────────────────────────────────────

type tokenType int

const (
	tokenWord tokenType = iota
	tokenString
	tokenLParen
	tokenRParen
)

type token struct {
	typ tokenType
	val string
}

var tokenRegex = regexp.MustCompile(`"(?:[^"\\]|\\.)*"|[()]|[^\s()]+`)

func tokenize(filter string) []token {
	matches := tokenRegex.FindAllString(filter, -1)
	tokens := make([]token, 0, len(matches))
	for _, m := range matches {
		if m == "(" {
			tokens = append(tokens, token{typ: tokenLParen, val: "("})
		} else if m == ")" {
			tokens = append(tokens, token{typ: tokenRParen, val: ")"})
		} else if len(m) >= 2 && m[0] == '"' && m[len(m)-1] == '"' {
			tokens = append(tokens, token{typ: tokenString, val: m[1 : len(m)-1]})
		} else {
			tokens = append(tokens, token{typ: tokenWord, val: m})
		}
	}
	return tokens
}

// ── Case-insensitive attribute set ──────────────────

var caseInsensitiveAttrs = map[string]bool{
	attrUsername:              true,
	attrDisplayName:           true,
	attrExternalID:            true,
	attrNameFamilyName:        true,
	attrNameGivenName:         true,
	attrNameFormatted:         true,
	attrNameMiddleName:        true,
	attrNameHonorificPrefix:   true,
	attrNameHonorificSuffix:   true,
	attrNickname:              true,
	attrTitle:                 true,
	attrUserType:              true,
	attrPreferredLanguage:     true,
	attrLocale:                true,
	attrTimeZone:              true,
	attrEmailsValue:           true,
	attrEmailsType:            true,
	attrPhoneNumbersValue:     true,
	attrPhoneNumbersType:      true,
	attrImsValue:              true,
	attrImsType:               true,
	attrAddressesType:         true,
	attrPhotosValue:           true,
	attrPhotosType:            true,
	attrRolesValue:            true,
	attrEntitlementsValue:     true,
	attrX509CertificatesValue: true,
}

// ── URN prefix handling ─────────────────────────────

const (
	coreUserURN       = "urn:ietf:params:scim:schemas:core:2.0:User:"
	coreGroupURN      = "urn:ietf:params:scim:schemas:core:2.0:Group:"
	enterpriseURN     = "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User:"
	enterpriseURNBase = "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User"
)

func stripURNPrefix(attr string) string {
	if strings.HasPrefix(attr, coreUserURN) {
		return attr[len(coreUserURN):]
	}
	if strings.HasPrefix(attr, coreGroupURN) {
		return attr[len(coreGroupURN):]
	}
	if strings.HasPrefix(attr, enterpriseURN) {
		return attr[len(enterpriseURN):]
	}
	return attr
}

// ── Parser ──────────────────────────────────────────

type filterParser struct {
	tokens     []token
	pos        int
	paramIdx   int
	entityType string // "user" or "group"
}

func (p *filterParser) peek() *token {
	if p.pos >= len(p.tokens) {
		return nil
	}
	return &p.tokens[p.pos]
}

func (p *filterParser) next() *token {
	if p.pos >= len(p.tokens) {
		return nil
	}
	t := &p.tokens[p.pos]
	p.pos++
	return t
}

func (p *filterParser) nextParam() string {
	s := fmt.Sprintf("$%d", p.paramIdx)
	p.paramIdx++
	return s
}

func (p *filterParser) parseOrExpression() (*FilterResult, error) {
	left, err := p.parseAndExpression()
	if err != nil {
		return nil, err
	}

	for {
		t := p.peek()
		if t == nil || t.typ != tokenWord || !strings.EqualFold(t.val, filterOpOr) {
			break
		}
		p.next() // consume "or"
		right, err := p.parseAndExpression()
		if err != nil {
			return nil, err
		}
		left = &FilterResult{
			SQL:  "(" + left.SQL + " OR " + right.SQL + ")",
			Args: append(left.Args, right.Args...),
		}
	}
	return left, nil
}

func (p *filterParser) parseAndExpression() (*FilterResult, error) {
	left, err := p.parseNotExpression()
	if err != nil {
		return nil, err
	}

	for {
		t := p.peek()
		if t == nil || t.typ != tokenWord || !strings.EqualFold(t.val, filterOpAnd) {
			break
		}
		p.next() // consume "and"
		right, err := p.parseNotExpression()
		if err != nil {
			return nil, err
		}
		left = &FilterResult{
			SQL:  "(" + left.SQL + " AND " + right.SQL + ")",
			Args: append(left.Args, right.Args...),
		}
	}
	return left, nil
}

func (p *filterParser) parseNotExpression() (*FilterResult, error) {
	t := p.peek()
	if t != nil && t.typ == tokenWord && strings.EqualFold(t.val, filterOpNot) {
		p.next() // consume "not"

		// Expect opening paren after NOT
		lp := p.peek()
		if lp != nil && lp.typ == tokenLParen {
			p.next() // consume "("
			inner, err := p.parseOrExpression()
			if err != nil {
				return nil, err
			}
			rp := p.next() // consume ")"
			if rp == nil || rp.typ != tokenRParen {
				return nil, fmt.Errorf("expected ')' after NOT expression")
			}
			return &FilterResult{
				SQL:  "NOT (" + inner.SQL + ")",
				Args: inner.Args,
			}, nil
		}

		inner, err := p.parseAtom()
		if err != nil {
			return nil, err
		}
		return &FilterResult{
			SQL:  "NOT (" + inner.SQL + ")",
			Args: inner.Args,
		}, nil
	}
	return p.parseAtom()
}

func (p *filterParser) parseAtom() (*FilterResult, error) {
	t := p.peek()
	if t == nil {
		return nil, fmt.Errorf("unexpected end of filter")
	}

	// Grouped expression
	if t.typ == tokenLParen {
		p.next() // consume "("
		inner, err := p.parseOrExpression()
		if err != nil {
			return nil, err
		}
		rp := p.next()
		if rp == nil || rp.typ != tokenRParen {
			return nil, fmt.Errorf("expected ')'")
		}
		return inner, nil
	}

	// Value path filter: emails[type eq "work"].value
	if t.typ == tokenWord && strings.Contains(t.val, "[") {
		return p.parseValuePathFilter()
	}

	// Regular comparison: attrName op value
	if t.typ != tokenWord {
		return nil, fmt.Errorf("expected attribute name, got: %s", t.val)
	}
	attrName := p.next().val
	attrName = stripURNPrefix(attrName)

	// Check for "pr" (present) operator
	opToken := p.peek()
	if opToken == nil {
		return nil, fmt.Errorf("expected operator after '%s'", attrName)
	}
	if opToken.typ == tokenWord && strings.EqualFold(opToken.val, filterOpPr) {
		p.next() // consume "pr"
		col, err := p.resolveColumn(attrName)
		if err != nil {
			return nil, err
		}
		if isJSONColumn(attrName) {
			return &FilterResult{SQL: col + sqlIsNotNullAnd + col + sqlTextNotEqualsEmptyArray, Args: nil}, nil
		}
		return &FilterResult{SQL: col + sqlIsNotNull, Args: nil}, nil
	}

	// Regular operator
	op := p.next()
	if op == nil || op.typ != tokenWord {
		return nil, fmt.Errorf("expected operator after '%s'", attrName)
	}
	operator := strings.ToLower(op.val)

	// Value
	valToken := p.next()
	if valToken == nil {
		return nil, fmt.Errorf("expected value after '%s %s'", attrName, operator)
	}
	value := valToken.val

	return p.buildComparison(attrName, operator, value)
}

func (p *filterParser) parseValuePathFilter() (*FilterResult, error) {
	// Parse something like: emails[type eq "work"].value eq "example@example.com"
	raw := p.next().val // e.g., "emails[type"
	bracketIdx := strings.Index(raw, "[")
	collectionAttr := raw[:bracketIdx]
	filterStart := raw[bracketIdx+1:]

	// Collect tokens until we find "]" or something ending with "]"
	filterParts := []string{filterStart}
	for {
		t := p.peek()
		if t == nil {
			return nil, fmt.Errorf("unterminated value path filter")
		}
		val := t.val
		if strings.HasSuffix(val, "]") {
			p.next()
			val = strings.TrimSuffix(val, "]")
			if val != "" {
				filterParts = append(filterParts, val)
			}
			break
		}
		if t.typ == tokenString {
			filterParts = append(filterParts, `"`+val+`"`)
		} else {
			filterParts = append(filterParts, val)
		}
		p.next()
	}
	// filterParts is the inner filter (e.g. ["type", "eq", "work"])

	// Check for sub-attribute after "]" (e.g. ".value")
	// The "." should be part of the next token, or...
	// Actually, the tokenizer would give us ".value" as a separate token
	var subAttr string
	t := p.peek()
	if t != nil && t.typ == tokenWord && strings.HasPrefix(t.val, ".") {
		subAttr = t.val[1:]
		p.next()
	}

	// Now we need operator + value for the outer comparison
	opToken := p.peek()
	if opToken == nil || opToken.typ != tokenWord {
		// Just a path filter without outer comparison (pr-style)
		col := p.resolveJSONColumn(collectionAttr)
		innerFilter := strings.Join(filterParts, " ")
		return p.buildJSONContainsFilter(col, collectionAttr, innerFilter, subAttr, "", "")
	}

	operator := strings.ToLower(opToken.val)

	// If the next token is a logical keyword, this is a standalone value path filter
	if operator == filterOpAnd || operator == filterOpOr || operator == filterOpNot {
		col := p.resolveJSONColumn(collectionAttr)
		innerFilter := strings.Join(filterParts, " ")
		return p.buildJSONContainsFilter(col, collectionAttr, innerFilter, subAttr, "", "")
	}

	if operator == filterOpPr {
		p.next()
		col := p.resolveJSONColumn(collectionAttr)
		innerFilter := strings.Join(filterParts, " ")
		return p.buildJSONContainsFilter(col, collectionAttr, innerFilter, subAttr, filterOpPr, "")
	}

	// Regular comparison
	p.next() // consume operator
	valToken := p.next()
	if valToken == nil {
		return nil, fmt.Errorf("expected value")
	}
	value := valToken.val

	col := p.resolveJSONColumn(collectionAttr)
	innerFilter := strings.Join(filterParts, " ")
	return p.buildJSONContainsFilter(col, collectionAttr, innerFilter, subAttr, operator, value)
}

func (p *filterParser) resolveColumn(attr string) (string, error) {
	// Handle enterprise extension prefix
	if strings.HasPrefix(attr, enterpriseURNBase+":") {
		attr = attr[len(enterpriseURN):]
		return p.resolveEnterpriseColumn(attr)
	}

	lower := strings.ToLower(attr)

	// JSON collection attributes → use LIKE-based filtering
	if isJSONCollection(lower) {
		return p.resolveJSONColumn(attr), nil
	}

	switch lower {
	// User attributes
	case attrUsername:
		return sqlUserName, nil
	case attrExternalID:
		return sqlExternalID, nil
	case attrNameFormatted:
		return sqlNameFormatted, nil
	case attrNameFamilyName:
		return sqlNameFamilyName, nil
	case attrNameGivenName:
		return sqlNameGivenName, nil
	case attrNameMiddleName:
		return sqlNameMiddleName, nil
	case attrNameHonorificPrefix:
		return sqlNameHonorificPrefix, nil
	case attrNameHonorificSuffix:
		return sqlNameHonorificSuffix, nil
	case attrDisplayName:
		return sqlDisplayName, nil
	case attrNickname:
		return sqlNickName, nil
	case attrProfileURL:
		return sqlProfileURL, nil
	case attrTitle:
		return sqlTitle, nil
	case attrUserType:
		return sqlUserType, nil
	case attrPreferredLanguage:
		return sqlPreferredLanguage, nil
	case attrLocale:
		return sqlLocale, nil
	case attrTimeZone:
		return sqlTimeZone, nil
	case attrActive:
		return sqlActive, nil
	case attrMetaCreated:
		return sqlCreatedAt, nil
	case attrMetaLastModified:
		return sqlLastModified, nil
	case attrID:
		return sqlID, nil
	// Enterprise extension
	case attrEmployeeNumber,
		"urn:ietf:params:scim:schemas:extension:enterprise:2.0:user:employeenumber":
		return sqlEnterpriseEmployeeNumber, nil
	case attrCostCenter:
		return sqlEnterpriseCostCenter, nil
	case attrOrganization:
		return sqlEnterpriseOrganization, nil
	case attrDivision:
		return sqlEnterpriseDivision, nil
	case attrDepartment:
		return sqlEnterpriseDepartment, nil
	case attrManagerValue:
		return sqlEnterpriseManagerValue, nil
	case attrManagerDisplayName:
		return sqlEnterpriseManagerDisplay, nil
	// Group attributes
	case attrMembersValue:
		return sqlMemberValue, nil
	default:
		return "", fmt.Errorf("unknown attribute: %s", attr)
	}
}

func (p *filterParser) resolveEnterpriseColumn(attr string) (string, error) {
	switch strings.ToLower(attr) {
	case attrEmployeeNumber:
		return sqlEnterpriseEmployeeNumber, nil
	case attrCostCenter:
		return sqlEnterpriseCostCenter, nil
	case attrOrganization:
		return sqlEnterpriseOrganization, nil
	case attrDivision:
		return sqlEnterpriseDivision, nil
	case attrDepartment:
		return sqlEnterpriseDepartment, nil
	case attrManagerValue:
		return sqlEnterpriseManagerValue, nil
	case attrManagerDisplayName:
		return sqlEnterpriseManagerDisplay, nil
	default:
		return "", fmt.Errorf("unknown enterprise attribute: %s", attr)
	}
}

func isJSONCollection(attr string) bool {
	switch strings.ToLower(attr) {
	case jsonCollectionEmails, jsonCollectionPhoneNumbers, jsonCollectionAddresses, jsonCollectionIms, jsonCollectionPhotos,
		jsonCollectionEntitlements, jsonCollectionRoles, jsonCollectionX509Certificates:
		return true
	}
	return false
}

func isJSONColumn(attr string) bool {
	parts := strings.SplitN(attr, ".", 2)
	return isJSONCollection(strings.ToLower(parts[0]))
}

func (p *filterParser) resolveJSONColumn(attr string) string {
	switch strings.ToLower(attr) {
	case jsonCollectionEmails:
		return jsonCollectionEmails
	case jsonCollectionPhoneNumbers:
		return "phone_numbers"
	case jsonCollectionAddresses:
		return jsonCollectionAddresses
	case jsonCollectionIms:
		return jsonCollectionIms
	case jsonCollectionPhotos:
		return jsonCollectionPhotos
	case jsonCollectionEntitlements:
		return jsonCollectionEntitlements
	case jsonCollectionRoles:
		return jsonCollectionRoles
	case jsonCollectionX509Certificates:
		return "x509_certificates"
	default:
		return attr
	}
}

func (p *filterParser) buildComparison(attr, operator, value string) (*FilterResult, error) {
	// Handle JSON sub-attribute paths like emails.value
	parts := strings.SplitN(attr, ".", 2)
	if len(parts) == 2 && isJSONCollection(parts[0]) {
		col := p.resolveJSONColumn(parts[0])
		return p.buildJSONAttributeFilter(col, parts[0], parts[1], operator, value)
	}

	col, err := p.resolveColumn(attr)
	if err != nil {
		return nil, err
	}

	isCaseInsensitive := caseInsensitiveAttrs[strings.ToLower(attr)]

	switch operator {
	case filterOpEq:
		if strings.EqualFold(value, "true") || strings.EqualFold(value, "false") {
			param := p.nextParam()
			boolVal := strings.EqualFold(value, "true")
			return &FilterResult{SQL: col + " = " + param, Args: []any{boolVal}}, nil
		}
		param := p.nextParam()
		if isCaseInsensitive {
			return &FilterResult{SQL: sqlLowerPrefix + col + ") = " + sqlLowerPrefix + param + ")", Args: []any{value}}, nil
		}
		return &FilterResult{SQL: col + " = " + param, Args: []any{value}}, nil

	case filterOpNe:
		param := p.nextParam()
		if isCaseInsensitive {
			return &FilterResult{SQL: "(" + sqlLowerPrefix + col + ") != " + sqlLowerPrefix + param + ") OR " + col + " IS NULL)", Args: []any{value}}, nil
		}
		return &FilterResult{SQL: "(" + col + " != " + param + " OR " + col + " IS NULL)", Args: []any{value}}, nil

	case filterOpCo:
		param := p.nextParam()
		escaped := escapeLikeValue(value)
		if isCaseInsensitive {
			return &FilterResult{SQL: sqlLowerPrefix + col + sqlLowerLikeSeparator + param + ")", Args: []any{"%" + escaped + "%"}}, nil
		}
		return &FilterResult{SQL: col + sqlLike + param, Args: []any{"%" + escaped + "%"}}, nil

	case filterOpSw:
		param := p.nextParam()
		escaped := escapeLikeValue(value)
		if isCaseInsensitive {
			return &FilterResult{SQL: sqlLowerPrefix + col + sqlLowerLikeSeparator + param + ")", Args: []any{escaped + "%"}}, nil
		}
		return &FilterResult{SQL: col + sqlLike + param, Args: []any{escaped + "%"}}, nil

	case filterOpEw:
		param := p.nextParam()
		escaped := escapeLikeValue(value)
		if isCaseInsensitive {
			return &FilterResult{SQL: sqlLowerPrefix + col + sqlLowerLikeSeparator + param + ")", Args: []any{"%" + escaped}}, nil
		}
		return &FilterResult{SQL: col + sqlLike + param, Args: []any{"%" + escaped}}, nil

	case filterOpGt:
		param := p.nextParam()
		return &FilterResult{SQL: col + " > " + param, Args: []any{value}}, nil

	case filterOpGe:
		param := p.nextParam()
		return &FilterResult{SQL: col + " >= " + param, Args: []any{value}}, nil

	case filterOpLt:
		param := p.nextParam()
		return &FilterResult{SQL: col + " < " + param, Args: []any{value}}, nil

	case filterOpLe:
		param := p.nextParam()
		return &FilterResult{SQL: col + " <= " + param, Args: []any{value}}, nil

	default:
		return nil, fmt.Errorf("unsupported operator: %s", operator)
	}
}

func (p *filterParser) buildJSONAttributeFilter(col, collectionName, subAttr, operator, value string) (*FilterResult, error) {
	// For JSON columns, we use casting to text and LIKE patterns
	// This matches the Java implementation's approach
	param := p.nextParam()
	isCaseInsensitive := caseInsensitiveAttrs[strings.ToLower(collectionName+"."+subAttr)]

	switch operator {
	case filterOpEq:
		escaped := escapeLikeValue(value)
		pattern := fmt.Sprintf(`%%"%s"%%`, escaped)
		if subAttr == "value" || subAttr == "type" || subAttr == "display" {
			// Match JSON key-value pair
			pattern = fmt.Sprintf(`%%"%s":"%s"%%`, subAttr, escaped)
		}
		if isCaseInsensitive {
			return &FilterResult{SQL: sqlLowerPrefix + col + sqlTextLowerLikeSeparator + param + ")", Args: []any{pattern}}, nil
		}
		return &FilterResult{SQL: col + sqlTextLike + param, Args: []any{pattern}}, nil

	case filterOpCo:
		escaped := escapeLikeValue(value)
		pattern := fmt.Sprintf(`%%"%s":"%%%s%%"%%`, subAttr, escaped)
		if isCaseInsensitive {
			return &FilterResult{SQL: sqlLowerPrefix + col + sqlTextLowerLikeSeparator + param + ")", Args: []any{pattern}}, nil
		}
		return &FilterResult{SQL: col + sqlTextLike + param, Args: []any{pattern}}, nil

	case filterOpSw:
		escaped := escapeLikeValue(value)
		pattern := fmt.Sprintf(`%%"%s":"%s%%"%%`, subAttr, escaped)
		if isCaseInsensitive {
			return &FilterResult{SQL: sqlLowerPrefix + col + sqlTextLowerLikeSeparator + param + ")", Args: []any{pattern}}, nil
		}
		return &FilterResult{SQL: col + sqlTextLike + param, Args: []any{pattern}}, nil

	case filterOpEw:
		escaped := escapeLikeValue(value)
		pattern := fmt.Sprintf(`%%"%s":"%%%s"%%`, subAttr, escaped)
		if isCaseInsensitive {
			return &FilterResult{SQL: sqlLowerPrefix + col + sqlTextLowerLikeSeparator + param + ")", Args: []any{pattern}}, nil
		}
		return &FilterResult{SQL: col + sqlTextLike + param, Args: []any{pattern}}, nil

	case filterOpPr:
		return &FilterResult{SQL: col + sqlIsNotNullAnd + col + sqlTextNotEqualsEmptyArray, Args: nil}, nil

	default:
		return nil, fmt.Errorf("unsupported operator for JSON attribute: %s", operator)
	}
}

func (p *filterParser) buildJSONContainsFilter(col, _, innerFilter, subAttr, operator, value string) (*FilterResult, error) {
	// This handles value path filters like emails[type eq "work"].value eq "user@example.com"
	// We combine inner filter + outer comparison into a LIKE pattern on the JSON text
	param := p.nextParam()

	if operator == "" || operator == filterOpPr {
		// Just check if the collection has a matching element
		// Parse inner filter to extract key=value
		innerParts := parseSimpleEqFilter(innerFilter)
		if innerParts == nil {
			return &FilterResult{SQL: col + sqlIsNotNullAnd + col + sqlTextNotEqualsEmptyArray, Args: nil}, nil
		}
		pattern := fmt.Sprintf(`%%"%s":"%s"%%`, innerParts[0], escapeLikeValue(innerParts[1]))
		return &FilterResult{SQL: sqlLowerPrefix + col + sqlTextLowerLikeSeparator + param + ")", Args: []any{pattern}}, nil
	}

	// For combined filters, we use a simpler approach:
	// Check if the stringified JSON contains the expected patterns
	innerParts := parseSimpleEqFilter(innerFilter)
	outerEscaped := escapeLikeValue(value)

	if innerParts != nil && subAttr != "" {
		// Combined: emails[type eq "work"].value eq "user@example.com"
		// Build a pattern that matches both conditions in the same JSON object
		innerPattern := fmt.Sprintf(`"%s":"%s"`, innerParts[0], escapeLikeValue(innerParts[1]))
		var outerPattern string
		switch operator {
		case filterOpEq:
			outerPattern = fmt.Sprintf(`"%s":"%s"`, subAttr, outerEscaped)
		case filterOpCo:
			outerPattern = fmt.Sprintf(`"%s":"%%%s%%"`, subAttr, outerEscaped)
		case filterOpSw:
			outerPattern = fmt.Sprintf(`"%s":"%s%%"`, subAttr, outerEscaped)
		case filterOpEw:
			outerPattern = fmt.Sprintf(`"%s":"%%%s"`, subAttr, outerEscaped)
		default:
			return nil, fmt.Errorf("unsupported operator in value path filter: %s", operator)
		}
		pattern := "%%" + innerPattern + "%%" + outerPattern + "%%"
		return &FilterResult{SQL: sqlLowerPrefix + col + sqlTextLowerLikeSeparator + param + ")", Args: []any{pattern}}, nil
	}

	// Fallback: just search for value in JSON text
	pattern := "%%" + outerEscaped + "%%"
	return &FilterResult{SQL: sqlLowerPrefix + col + sqlTextLowerLikeSeparator + param + ")", Args: []any{pattern}}, nil
}

// parseSimpleEqFilter extracts [key, value] from a simple "key eq value" filter.
func parseSimpleEqFilter(filter string) []string {
	filter = strings.TrimSpace(filter)
	parts := strings.SplitN(filter, " ", 3)
	if len(parts) != 3 {
		return nil
	}
	if !strings.EqualFold(parts[1], filterOpEq) {
		return nil
	}
	value := strings.Trim(parts[2], `"`)
	return []string{parts[0], value}
}

func escapeLikeValue(value string) string {
	var b strings.Builder
	for _, c := range value {
		switch c {
		case '%', '_', '\\':
			b.WriteRune('\\')
			b.WriteRune(c)
		default:
			if !unicode.IsPrint(c) {
				continue
			}
			b.WriteRune(c)
		}
	}
	return b.String()
}
