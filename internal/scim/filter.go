package scim

import (
	"fmt"
	"regexp"
	"strings"
	"time"
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
	"emails.display":           true,
	attrPhoneNumbersValue:     true,
	attrPhoneNumbersType:      true,
	"phonenumbers.display":     true,
	attrImsValue:              true,
	attrImsType:               true,
	"ims.display":              true,
	attrAddressesType:         true,
	"addresses.formatted":      true,
	"addresses.streetaddress":  true,
	"addresses.locality":       true,
	"addresses.region":         true,
	"addresses.postalcode":     true,
	"addresses.country":        true,
	attrPhotosValue:           true,
	attrPhotosType:            true,
	"photos.display":           true,
	attrRolesValue:            true,
	"roles.display":            true,
	attrEntitlementsValue:     true,
	"entitlements.display":     true,
	attrX509CertificatesValue: true,
	"x509certificates.display": true,
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

type innerToken struct {
	val      string
	isString bool
}

type innerClause struct {
	attr string
	op   string
	val  string
}

func (p *filterParser) parseValuePathFilter() (*FilterResult, error) {
	// Parse something like: emails[type eq "work"].value eq "example@example.com"
	raw := p.next().val // e.g., "emails[type"
	bracketIdx := strings.Index(raw, "[")
	collectionAttr := raw[:bracketIdx]
	filterStart := raw[bracketIdx+1:]

	if !isJSONCollection(collectionAttr) {
		if strings.EqualFold(collectionAttr, "members") {
			return nil, fmt.Errorf("value path filters on 'members' are not supported")
		}
		return nil, fmt.Errorf("attribute '%s' is not a multi-valued complex attribute", collectionAttr)
	}

	var innerTokens []innerToken
	var subAttr string

	if closeIdx := strings.Index(filterStart, "]"); closeIdx >= 0 {
		before := filterStart[:closeIdx]
		if before != "" {
			innerTokens = append(innerTokens, innerToken{val: before, isString: false})
		}
		after := filterStart[closeIdx+1:]
		if strings.HasPrefix(after, ".") {
			subAttr = after[1:]
		}
	} else {
		if filterStart != "" {
			innerTokens = append(innerTokens, innerToken{val: filterStart, isString: false})
		}
		for {
			t := p.peek()
			if t == nil {
				return nil, fmt.Errorf("unterminated value path filter")
			}
			p.next()
			if t.typ != tokenString {
				if closeIdx := strings.Index(t.val, "]"); closeIdx >= 0 {
					before := t.val[:closeIdx]
					if before != "" {
						innerTokens = append(innerTokens, innerToken{val: before, isString: false})
					}
					after := t.val[closeIdx+1:]
					if strings.HasPrefix(after, ".") {
						subAttr = after[1:]
					}
					break
				}
				innerTokens = append(innerTokens, innerToken{val: t.val, isString: false})
			} else {
				innerTokens = append(innerTokens, innerToken{val: t.val, isString: true})
			}
		}
	}

	// Check for sub-attribute after "]" if not already extracted (e.g. ".value" as a separate token)
	if subAttr == "" {
		t := p.peek()
		if t != nil && t.typ == tokenWord && strings.HasPrefix(t.val, ".") {
			subAttr = t.val[1:]
			p.next()
		}
	}

	// Reject multi-clause inner filters (and/or/not)
	for _, tok := range innerTokens {
		if !tok.isString {
			lower := strings.ToLower(tok.val)
			if lower == filterOpAnd || lower == filterOpOr || lower == filterOpNot || tok.val == "(" || tok.val == ")" {
				return nil, fmt.Errorf("multi-clause inner filters in value paths are not supported")
			}
		}
	}

	var clause *innerClause
	if len(innerTokens) == 2 {
		attr := innerTokens[0].val
		op := strings.ToLower(innerTokens[1].val)
		if op != filterOpPr {
			return nil, fmt.Errorf("expected 'pr' operator in 2-token inner filter, got: %s", innerTokens[1].val)
		}
		if _, _, err := resolveSubAttribute(collectionAttr, attr); err != nil {
			return nil, err
		}
		clause = &innerClause{attr: attr, op: op}
	} else if len(innerTokens) == 3 {
		attr := innerTokens[0].val
		op := strings.ToLower(innerTokens[1].val)
		val := innerTokens[2].val
		_, isBool, err := resolveSubAttribute(collectionAttr, attr)
		if err != nil {
			return nil, err
		}
		if isBool {
			if op != filterOpEq && op != filterOpNe && op != filterOpPr {
				return nil, fmt.Errorf("comparison operator '%s' is not supported for boolean attribute '%s'", op, attr)
			}
			if !strings.EqualFold(val, "true") && !strings.EqualFold(val, "false") {
				return nil, fmt.Errorf("invalid boolean value for attribute '%s': %s", attr, val)
			}
		}
		clause = &innerClause{attr: attr, op: op, val: val}
	} else if len(innerTokens) == 1 {
		attr := innerTokens[0].val
		if _, _, err := resolveSubAttribute(collectionAttr, attr); err != nil {
			return nil, err
		}
		clause = &innerClause{attr: attr, op: filterOpPr}
	} else if len(innerTokens) > 0 {
		return nil, fmt.Errorf("invalid inner filter in value path")
	}

	if subAttr != "" {
		if _, _, err := resolveSubAttribute(collectionAttr, subAttr); err != nil {
			return nil, err
		}
	}

	col := p.resolveJSONColumn(collectionAttr)

	// Now we need operator + value for the outer comparison
	opToken := p.peek()
	if opToken == nil || opToken.typ != tokenWord {
		// Just a path filter without outer comparison (pr-style)
		return p.buildJSONContainsFilter(col, collectionAttr, clause, subAttr, "", "")
	}

	operator := strings.ToLower(opToken.val)

	// If the next token is a logical keyword, this is a standalone value path filter
	if operator == filterOpAnd || operator == filterOpOr || operator == filterOpNot {
		return p.buildJSONContainsFilter(col, collectionAttr, clause, subAttr, "", "")
	}

	if subAttr != "" {
		_, isBool, _ := resolveSubAttribute(collectionAttr, subAttr)
		if isBool {
			if operator != filterOpPr && operator != filterOpEq && operator != filterOpNe {
				return nil, fmt.Errorf("comparison operator '%s' is not supported for boolean attribute '%s'", operator, subAttr)
			}
		}
	}

	if operator == filterOpPr {
		p.next()
		return p.buildJSONContainsFilter(col, collectionAttr, clause, subAttr, filterOpPr, "")
	}

	// Regular comparison
	p.next() // consume operator
	valToken := p.next()
	if valToken == nil {
		return nil, fmt.Errorf("expected value")
	}
	value := valToken.val

	if subAttr != "" {
		_, isBool, _ := resolveSubAttribute(collectionAttr, subAttr)
		if isBool {
			if !strings.EqualFold(value, "true") && !strings.EqualFold(value, "false") {
				return nil, fmt.Errorf("invalid boolean value for attribute '%s': %s", subAttr, value)
			}
		}
	}

	return p.buildJSONContainsFilter(col, collectionAttr, clause, subAttr, operator, value)
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

	lowerAttr := strings.ToLower(attr)

	// Validate boolean attributes: only eq and ne are supported per RFC 7644 §3.4.2.2
	if isBooleanAttr(lowerAttr) {
		if operator != filterOpEq && operator != filterOpNe {
			return nil, fmt.Errorf("comparison operator '%s' is not supported for boolean attribute '%s'", operator, attr)
		}
		if !strings.EqualFold(value, "true") && !strings.EqualFold(value, "false") {
			return nil, fmt.Errorf("invalid boolean value for attribute '%s': %s", attr, value)
		}
	}

	// Validate dateTime attributes per RFC 7643 §2.3.5
	if lowerAttr == attrMetaCreated || lowerAttr == attrMetaLastModified {
		if operator == filterOpCo || operator == filterOpSw || operator == filterOpEw {
			return nil, fmt.Errorf("comparison operator '%s' is not supported for dateTime attribute '%s'", operator, attr)
		}
		t, err := parseDateTime(value)
		if err != nil {
			return nil, fmt.Errorf("invalid dateTime format for attribute '%s': %s", attr, value)
		}
		// Normalize to UTC string before SQL binding to avoid session timezone dependency
		value = t.UTC().Format(time.RFC3339Nano)
	}

	isCaseInsensitive := caseInsensitiveAttrs[strings.ToLower(attr)]

	switch operator {
	case filterOpEq:
		if isBooleanAttr(lowerAttr) {
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
		if isBooleanAttr(lowerAttr) {
			boolVal := strings.EqualFold(value, "true")
			return &FilterResult{SQL: "(" + col + " != " + param + " OR " + col + " IS NULL)", Args: []any{boolVal}}, nil
		}
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

func resolveSubAttribute(collectionAttr, subAttr string) (string, bool, error) {
	colLower := strings.ToLower(collectionAttr)
	subLower := strings.ToLower(subAttr)

	switch colLower {
	case jsonCollectionEmails, jsonCollectionPhoneNumbers, jsonCollectionIms, jsonCollectionPhotos,
		jsonCollectionEntitlements, jsonCollectionRoles, jsonCollectionX509Certificates:
		switch subLower {
		case "value":
			return "value", false, nil
		case "type":
			return "type", false, nil
		case "display":
			return "display", false, nil
		case "primary":
			return "primaryFlag", true, nil
		default:
			return "", false, fmt.Errorf("unknown sub-attribute '%s' for '%s'", subAttr, collectionAttr)
		}
	case jsonCollectionAddresses:
		switch subLower {
		case "formatted":
			return "formatted", false, nil
		case "streetaddress":
			return "streetAddress", false, nil
		case "locality":
			return "locality", false, nil
		case "region":
			return "region", false, nil
		case "postalcode":
			return "postalCode", false, nil
		case "country":
			return "country", false, nil
		case "type":
			return "type", false, nil
		case "primary":
			return "primaryFlag", true, nil
		default:
			return "", false, fmt.Errorf("unknown sub-attribute '%s' for '%s'", subAttr, collectionAttr)
		}
	default:
		return "", false, fmt.Errorf("attribute '%s' is not a multi-valued complex attribute", collectionAttr)
	}
}

func (p *filterParser) buildJSONAttributeFilter(col, collectionName, subAttr, operator, value string) (*FilterResult, error) {
	jsonKey, isBool, err := resolveSubAttribute(collectionName, subAttr)
	if err != nil {
		return nil, err
	}

	if isBool {
		if operator != filterOpEq && operator != filterOpPr {
			return nil, fmt.Errorf("comparison operator '%s' is not supported for boolean attribute '%s.%s'", operator, collectionName, subAttr)
		}
		if operator == filterOpEq {
			if !strings.EqualFold(value, "true") && !strings.EqualFold(value, "false") {
				return nil, fmt.Errorf("invalid boolean value for attribute '%s.%s': %s", collectionName, subAttr, value)
			}
		}
	}

	// For JSON columns, we use casting to text and LIKE patterns
	// This matches the Java implementation's approach
	param := p.nextParam()
	isCaseInsensitive := caseInsensitiveAttrs[strings.ToLower(collectionName+"."+subAttr)]

	switch operator {
	case filterOpEq:
		var pattern string
		if isBool {
			pattern = fmt.Sprintf(`%%"primaryFlag":%s%%`, strings.ToLower(value))
		} else {
			// Match JSON key-value pair
			pattern = fmt.Sprintf(`%%"%s":"%s"%%`, jsonKey, escapeLikeValue(value))
		}
		if isCaseInsensitive {
			return &FilterResult{SQL: sqlLowerPrefix + col + sqlTextLowerLikeSeparator + param + ")", Args: []any{pattern}}, nil
		}
		return &FilterResult{SQL: col + sqlTextLike + param, Args: []any{pattern}}, nil

	case filterOpCo:
		escaped := escapeLikeValue(value)
		pattern := fmt.Sprintf(`%%"%s":"%%%s%%"%%`, jsonKey, escaped)
		if isCaseInsensitive {
			return &FilterResult{SQL: sqlLowerPrefix + col + sqlTextLowerLikeSeparator + param + ")", Args: []any{pattern}}, nil
		}
		return &FilterResult{SQL: col + sqlTextLike + param, Args: []any{pattern}}, nil

	case filterOpSw:
		escaped := escapeLikeValue(value)
		pattern := fmt.Sprintf(`%%"%s":"%s%%"%%`, jsonKey, escaped)
		if isCaseInsensitive {
			return &FilterResult{SQL: sqlLowerPrefix + col + sqlTextLowerLikeSeparator + param + ")", Args: []any{pattern}}, nil
		}
		return &FilterResult{SQL: col + sqlTextLike + param, Args: []any{pattern}}, nil

	case filterOpEw:
		escaped := escapeLikeValue(value)
		pattern := fmt.Sprintf(`%%"%s":"%%%s"%%`, jsonKey, escaped)
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

func (p *filterParser) buildElemCondition(collectionAttr, attr, op, val string) (string, []any, error) {
	jsonKey, isBool, err := resolveSubAttribute(collectionAttr, attr)
	if err != nil {
		return "", nil, err
	}

	if isBool {
		if op != filterOpEq && op != filterOpNe && op != filterOpPr {
			return "", nil, fmt.Errorf("comparison operator '%s' is not supported for boolean attribute '%s'", op, attr)
		}
		if op == filterOpPr {
			return fmt.Sprintf("(elem->>'%s') IS NOT NULL", jsonKey), nil, nil
		}
		if !strings.EqualFold(val, "true") && !strings.EqualFold(val, "false") {
			return "", nil, fmt.Errorf("invalid boolean value for attribute '%s': %s", attr, val)
		}
		param := p.nextParam()
		boolStr := strings.ToLower(val)
		if op == filterOpEq {
			return fmt.Sprintf("(elem->>'%s') = %s", jsonKey, param), []any{boolStr}, nil
		}
		// filterOpNe
		return fmt.Sprintf("((elem->>'%s') != %s OR (elem->>'%s') IS NULL)", jsonKey, param, jsonKey), []any{boolStr}, nil
	}

	switch op {
	case filterOpPr:
		return fmt.Sprintf("((elem->>'%s') IS NOT NULL AND (elem->>'%s') != '')", jsonKey, jsonKey), nil, nil
	case filterOpEq:
		param := p.nextParam()
		return fmt.Sprintf("LOWER(elem->>'%s') = LOWER(%s)", jsonKey, param), []any{val}, nil
	case filterOpNe:
		param := p.nextParam()
		return fmt.Sprintf("((elem->>'%s') IS NULL OR LOWER(elem->>'%s') != LOWER(%s))", jsonKey, jsonKey, param), []any{val}, nil
	case filterOpCo:
		param := p.nextParam()
		escaped := escapeLikeValue(val)
		return fmt.Sprintf("LOWER(elem->>'%s') LIKE LOWER(%s)", jsonKey, param), []any{"%" + escaped + "%"}, nil
	case filterOpSw:
		param := p.nextParam()
		escaped := escapeLikeValue(val)
		return fmt.Sprintf("LOWER(elem->>'%s') LIKE LOWER(%s)", jsonKey, param), []any{escaped + "%"}, nil
	case filterOpEw:
		param := p.nextParam()
		escaped := escapeLikeValue(val)
		return fmt.Sprintf("LOWER(elem->>'%s') LIKE LOWER(%s)", jsonKey, param), []any{"%" + escaped}, nil
	case filterOpGt:
		param := p.nextParam()
		return fmt.Sprintf("LOWER(elem->>'%s') > LOWER(%s)", jsonKey, param), []any{val}, nil
	case filterOpGe:
		param := p.nextParam()
		return fmt.Sprintf("LOWER(elem->>'%s') >= LOWER(%s)", jsonKey, param), []any{val}, nil
	case filterOpLt:
		param := p.nextParam()
		return fmt.Sprintf("LOWER(elem->>'%s') < LOWER(%s)", jsonKey, param), []any{val}, nil
	case filterOpLe:
		param := p.nextParam()
		return fmt.Sprintf("LOWER(elem->>'%s') <= LOWER(%s)", jsonKey, param), []any{val}, nil
	default:
		return "", nil, fmt.Errorf("unsupported operator in value path filter: %s", op)
	}
}

func (p *filterParser) buildJSONContainsFilter(col, collectionAttr string, clause *innerClause, subAttr, operator, value string) (*FilterResult, error) {
	var conds []string
	var args []any

	if clause != nil && clause.attr != "" {
		c, a, err := p.buildElemCondition(collectionAttr, clause.attr, clause.op, clause.val)
		if err != nil {
			return nil, err
		}
		conds = append(conds, c)
		args = append(args, a...)
	}

	if subAttr != "" {
		op := operator
		if op == "" {
			op = filterOpPr
		}
		c, a, err := p.buildElemCondition(collectionAttr, subAttr, op, value)
		if err != nil {
			return nil, err
		}
		conds = append(conds, c)
		args = append(args, a...)
	}

	if len(conds) == 0 {
		return &FilterResult{SQL: col + sqlIsNotNullAnd + col + sqlTextNotEqualsEmptyArray, Args: nil}, nil
	}

	whereClause := strings.Join(conds, " AND ")
	sql := fmt.Sprintf("(%s IS NOT NULL AND jsonb_typeof(%s::jsonb) = 'array' AND %s::text != '[]' AND EXISTS (SELECT 1 FROM jsonb_array_elements(%s::jsonb) AS elem WHERE %s))",
		col, col, col, col, whereClause)

	return &FilterResult{
		SQL:  sql,
		Args: args,
	}, nil
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

func isBooleanAttr(attr string) bool {
	return strings.ToLower(attr) == attrActive
}

// parseDateTime parses date and dateTime strings per RFC 7643 §2.3.5 (which recommends RFC 3339 / ISO 8601).
// Accepts RFC 3339 strings with timezone offset, as well as zoneless local datetimes (interpreted as UTC).
// Date-only strings without a time component are rejected per RFC 7643 §2.3.5.
func parseDateTime(s string) (time.Time, error) {
	formats := []string{
		time.RFC3339,
		"2006-01-02T15:04:05.999999999",
		"2006-01-02 15:04:05.999999999",
	}
	for _, f := range formats {
		if t, err := time.ParseInLocation(f, s, time.UTC); err == nil {
			return t.UTC(), nil
		}
	}
	return time.Time{}, fmt.Errorf("invalid dateTime format: %s", s)
}

func isValidDateTime(s string) bool {
	_, err := parseDateTime(s)
	return err == nil
}
