package scim

// ServiceProviderConfig returns the SCIM ServiceProviderConfig per RFC 7643 §5.
func ServiceProviderConfig() map[string]any {
	return map[string]any{
		"schemas":          []string{"urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig"},
		"documentationUri": "https://datatracker.ietf.org/doc/html/rfc7644",
		"patch":            map[string]any{"supported": true},
		"bulk": map[string]any{
			"supported":      true,
			"maxOperations":  1000,
			"maxPayloadSize": 1048576,
		},
		"filter": map[string]any{
			"supported":  true,
			"maxResults": 200,
		},
		"pagination": map[string]any{
			"cursor":                true,
			"index":                 true,
			"defaultPaginationMode": "index",
			"defaultPageSize":       10,
			"maxPageSize":           200,
			"cursorTimeout":         3600,
		},
		"changePassword": map[string]any{"supported": false},
		"sort":           map[string]any{"supported": true},
		"etag":           map[string]any{"supported": true},
		"authenticationSchemes": []map[string]any{{
			"type":        "oauthbearertoken",
			"name":        "OAuth Bearer Token",
			"description": "Authentication scheme using the OAuth Bearer Token Standard",
			"specUri":     "http://www.rfc-editor.org/info/rfc6750",
		}},
	}
}

// AllSchemas returns all six SCIM schema definitions.
func AllSchemas() []map[string]any {
	return []map[string]any{
		userSchema(),
		groupSchema(),
		enterpriseUserSchema(),
		serviceProviderConfigSchema(),
		resourceTypeSchema(),
		schemaSchema(),
	}
}

// GetSchemaByID returns a single schema definition by its URN ID, or nil.
func GetSchemaByID(id string) map[string]any {
	for _, s := range AllSchemas() {
		if s["id"] == id {
			return s
		}
	}
	return nil
}

// ResourceTypes returns the User and Group resource type definitions.
func ResourceTypes(baseURL string) []map[string]any {
	return []map[string]any{
		{
			"schemas":     []string{"urn:ietf:params:scim:schemas:core:2.0:ResourceType"},
			"id":          "User",
			"name":        "User",
			"description": "User Account",
			"endpoint":    "/Users",
			"schema":      "urn:ietf:params:scim:schemas:core:2.0:User",
			"schemaExtensions": []map[string]any{{
				"schema":   "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User",
				"required": false,
			}},
			"meta": map[string]any{
				"resourceType": "ResourceType",
				"location":     baseURL + "/ResourceTypes/User",
			},
		},
		{
			"schemas":          []string{"urn:ietf:params:scim:schemas:core:2.0:ResourceType"},
			"id":               "Group",
			"name":             "Group",
			"description":      "Group",
			"endpoint":         "/Groups",
			"schema":           "urn:ietf:params:scim:schemas:core:2.0:Group",
			"schemaExtensions": []map[string]any{},
			"meta": map[string]any{
				"resourceType": "ResourceType",
				"location":     baseURL + "/ResourceTypes/Group",
			},
		},
	}
}

// GetResourceTypeByID returns a single resource type by id or name.
func GetResourceTypeByID(id, baseURL string) map[string]any {
	for _, rt := range ResourceTypes(baseURL) {
		if rt["id"] == id || rt["name"] == id {
			return rt
		}
	}
	return nil
}

// ── Schema definitions ─────────────────────────────────

const coreSchemaURN = "urn:ietf:params:scim:schemas:core:2.0:Schema"

func userSchema() map[string]any {
	attrs := []map[string]any{
		withReturned(withCaseExact(attr("id", "string", true, "readOnly", "server",
			"A unique identifier for a SCIM resource", false)), "always"),
		withCaseExact(attr("externalId", "string", false, "readWrite", "server",
			"An identifier for the resource as defined by the provisioning client", false)),
		attr("userName", "string", true, "readWrite", "server",
			"Unique identifier for the User", false),
		withSubAttributes(attr("name", "complex", false, "readWrite", "none",
			"The components of the user's real name", false),
			attr("formatted", "string", false, "readWrite", "none", "The full name", false),
			attr("familyName", "string", false, "readWrite", "none", "The family name", false),
			attr("givenName", "string", false, "readWrite", "none", "The given name", false),
			attr("middleName", "string", false, "readWrite", "none", "The middle name", false),
			attr("honorificPrefix", "string", false, "readWrite", "none", "The honorific prefix", false),
			attr("honorificSuffix", "string", false, "readWrite", "none", "The honorific suffix", false),
		),
		attr("displayName", "string", false, "readWrite", "none",
			"The name displayed for the user", false),
		attr("nickName", "string", false, "readWrite", "none",
			"The casual way to address the user", false),
		withRefTypes(withCaseExact(attr("profileUrl", "reference", false, "readWrite", "none",
			"A URI that is a URL to the user's online profile", false)), "external"),
		attr("title", "string", false, "readWrite", "none", "The user's title", false),
		attr("userType", "string", false, "readWrite", "none", "The type of user", false),
		attr("preferredLanguage", "string", false, "readWrite", "none",
			"Preferred written or spoken language", false),
		attr("locale", "string", false, "readWrite", "none", "User's default location", false),
		attr("timezone", "string", false, "readWrite", "none", "The User's time zone", false),
		attr("active", "boolean", false, "readWrite", "none",
			"A Boolean value indicating the User's administrative status", false),
		withReturned(attr("password", "string", false, "writeOnly", "none",
			"The User's cleartext password", false), "never"),
		withSubAttributes(attr("emails", "complex", false, "readWrite", "none",
			"Email addresses for the user", true), emailsSubAttributes()...),
		withSubAttributes(attr("phoneNumbers", "complex", false, "readWrite", "none",
			"Phone numbers for the user", true), phoneNumbersSubAttributes()...),
		withSubAttributes(attr("ims", "complex", false, "readWrite", "none",
			"Instant messaging addresses for the user", true), imsSubAttributes()...),
		withSubAttributes(attr("photos", "complex", false, "readWrite", "none",
			"URLs of photos of the User", true), photosSubAttributes()...),
		withSubAttributes(attr("addresses", "complex", false, "readWrite", "none",
			"Physical mailing addresses for this User", true), addressesSubAttributes()...),
		withSubAttributes(attr("entitlements", "complex", false, "readWrite", "none",
			"A list of entitlements for the User", true), entitlementsSubAttributes()...),
		withSubAttributes(attr("roles", "complex", false, "readWrite", "none",
			"A list of roles for the User", true), rolesSubAttributes()...),
		withSubAttributes(attr("x509Certificates", "complex", false, "readWrite", "none",
			"A list of certificates issued to the User", true), x509CertificatesSubAttributes()...),
		withSubAttributes(attr("groups", "complex", false, "readOnly", "none",
			"A list of groups to which the user belongs", true), groupsSubAttributes()...),
	}

	return map[string]any{
		"schemas":    []string{coreSchemaURN},
		"id":         "urn:ietf:params:scim:schemas:core:2.0:User",
		"name":       "User",
		"description": "User Account",
		"attributes": attrs,
		"meta": map[string]any{
			"resourceType": "Schema",
			"location":     "/Schemas/urn:ietf:params:scim:schemas:core:2.0:User",
		},
	}
}

func groupSchema() map[string]any {
	attrs := []map[string]any{
		withReturned(withCaseExact(attr("id", "string", true, "readOnly", "server",
			"Unique identifier", false)), "always"),
		withCaseExact(attr("externalId", "string", false, "readWrite", "server",
			"External identifier", false)),
		attr("displayName", "string", true, "readWrite", "none",
			"A human-readable name for the Group", false),
		withSubAttributes(attr("members", "complex", false, "readWrite", "none",
			"A list of members of the Group", true), membersSubAttributes()...),
	}

	return map[string]any{
		"schemas":    []string{coreSchemaURN},
		"id":         "urn:ietf:params:scim:schemas:core:2.0:Group",
		"name":       "Group",
		"description": "Group",
		"attributes": attrs,
		"meta": map[string]any{
			"resourceType": "Schema",
			"location":     "/Schemas/urn:ietf:params:scim:schemas:core:2.0:Group",
		},
	}
}

func enterpriseUserSchema() map[string]any {
	managerRef := withCaseExact(attr("$ref", "reference", true, "readWrite", "none", "Manager URI", false))
	managerRef["referenceTypes"] = []string{"User"}

	attrs := []map[string]any{
		attr("employeeNumber", "string", false, "readWrite", "none", "Employee number", false),
		attr("costCenter", "string", false, "readWrite", "none", "Cost center", false),
		attr("organization", "string", false, "readWrite", "none", "Organization", false),
		attr("division", "string", false, "readWrite", "none", "Division", false),
		attr("department", "string", false, "readWrite", "none", "Department", false),
		withSubAttributes(attr("manager", "complex", false, "readWrite", "none", "The user's manager", false),
			withCaseExact(attr("value", "string", true, "readWrite", "none", "Manager user id", false)),
			managerRef,
			attr("displayName", "string", false, "readOnly", "none", "Manager display name", false),
		),
	}

	return map[string]any{
		"schemas":    []string{coreSchemaURN},
		"id":         "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User",
		"name":       "EnterpriseUser",
		"description": "Enterprise User Extension",
		"attributes": attrs,
		"meta": map[string]any{
			"resourceType": "Schema",
			"location":     "/Schemas/urn:ietf:params:scim:schemas:extension:enterprise:2.0:User",
		},
	}
}

func serviceProviderConfigSchema() map[string]any {
	docURI := withCaseExact(attr("documentationUri", "reference", false, "readOnly", "none",
		"Service provider documentation", false))
	docURI["referenceTypes"] = []string{"external"}

	patch := withSubAttributes(attr("patch", "complex", true, "readOnly", "none", "PATCH configuration", false),
		attr("supported", "boolean", true, "readOnly", "none", "Whether PATCH is supported", false))

	bulk := withSubAttributes(attr("bulk", "complex", true, "readOnly", "none", "Bulk configuration", false),
		attr("supported", "boolean", true, "readOnly", "none", "Whether bulk is supported", false),
		attr("maxOperations", "integer", true, "readOnly", "none", "Maximum operations", false),
		attr("maxPayloadSize", "integer", true, "readOnly", "none", "Maximum payload size", false))

	filter := withSubAttributes(attr("filter", "complex", true, "readOnly", "none", "Filter configuration", false),
		attr("supported", "boolean", true, "readOnly", "none", "Whether filtering is supported", false),
		attr("maxResults", "integer", true, "readOnly", "none", "Maximum results", false))

	paginationMode := attr("defaultPaginationMode", "string", false, "readOnly", "none", "Default pagination mode", false)
	paginationMode["canonicalValues"] = []string{"cursor", "index"}
	delete(paginationMode, "uniqueness")

	pagination := withSubAttributes(attr("pagination", "complex", false, "readOnly", "none", "Pagination configuration", false),
		attr("cursor", "boolean", true, "readOnly", "none", "Cursor pagination supported", false),
		attr("index", "boolean", true, "readOnly", "none", "Index pagination supported", false),
		paginationMode,
		attr("defaultPageSize", "integer", false, "readOnly", "none", "Default page size", false),
		attr("maxPageSize", "integer", false, "readOnly", "none", "Max page size", false),
		attr("cursorTimeout", "integer", false, "readOnly", "none", "Cursor timeout", false))

	changePassword := withSubAttributes(attr("changePassword", "complex", true, "readOnly", "none",
		"Change password configuration", false),
		attr("supported", "boolean", true, "readOnly", "none", "Whether changePassword is supported", false))

	sort := withSubAttributes(attr("sort", "complex", true, "readOnly", "none", "Sort configuration", false),
		attr("supported", "boolean", true, "readOnly", "none", "Whether sorting is supported", false))

	etag := withSubAttributes(attr("etag", "complex", true, "readOnly", "none", "ETag configuration", false),
		attr("supported", "boolean", true, "readOnly", "none", "Whether ETags are supported", false))

	schemeType := attr("type", "string", true, "readOnly", "none", "Scheme type", false)
	schemeType["canonicalValues"] = []string{"httpbasic", "httpdigest", "oauth", "oauth2", "oauthbearertoken"}
	specURI := withCaseExact(attr("specUri", "reference", false, "readOnly", "none", "Specification URI", false))
	specURI["referenceTypes"] = []string{"external"}
	authDocURI := withCaseExact(attr("documentationUri", "reference", false, "readOnly", "none", "Documentation URI", false))
	authDocURI["referenceTypes"] = []string{"external"}

	authSchemes := withSubAttributes(attr("authenticationSchemes", "complex", true, "readOnly", "none",
		"Authentication schemes", true),
		schemeType,
		attr("name", "string", true, "readOnly", "none", "Scheme name", false),
		attr("description", "string", true, "readOnly", "none", "Scheme description", false),
		specURI,
		authDocURI)

	attrs := []map[string]any{docURI, patch, bulk, filter, pagination, changePassword, sort, etag, authSchemes}

	return map[string]any{
		"schemas":    []string{coreSchemaURN},
		"id":         "urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig",
		"name":       "ServiceProviderConfig",
		"description": "Schema for representing the service provider's configuration",
		"attributes": attrs,
		"meta": map[string]any{
			"resourceType": "Schema",
			"location":     "/Schemas/urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig",
		},
	}
}

func resourceTypeSchema() map[string]any {
	endpoint := withCaseExact(attr("endpoint", "reference", true, "readOnly", "server", "Resource type endpoint", false))
	endpoint["referenceTypes"] = []string{"uri"}

	schemaRef := withCaseExact(attr("schema", "reference", true, "readOnly", "none", "Resource schema URI", false))
	schemaRef["referenceTypes"] = []string{"uri"}

	schemaExtRef := withCaseExact(attr("schema", "reference", true, "readOnly", "none", "Extension schema URI", false))
	schemaExtRef["referenceTypes"] = []string{"uri"}

	schemaExtensions := withSubAttributes(
		withCaseExact(attr("schemaExtensions", "complex", true, "readOnly", "none", "Schema extensions", true)),
		schemaExtRef,
		attr("required", "boolean", true, "readOnly", "none", "Whether extension is required", false))

	attrs := []map[string]any{
		attr("name", "string", true, "readOnly", "server", "Resource type name", false),
		attr("description", "string", false, "readOnly", "none", "Resource type description", false),
		endpoint,
		schemaRef,
		schemaExtensions,
	}

	return map[string]any{
		"schemas":    []string{coreSchemaURN},
		"id":         "urn:ietf:params:scim:schemas:core:2.0:ResourceType",
		"name":       "ResourceType",
		"description": "Schema for representing resource types",
		"attributes": attrs,
		"meta": map[string]any{
			"resourceType": "Schema",
			"location":     "/Schemas/urn:ietf:params:scim:schemas:core:2.0:ResourceType",
		},
	}
}

func schemaSchema() map[string]any {
	innerSubAttributes := []map[string]any{
		withCaseExact(attr("name", "string", true, "readOnly", "none", "Attribute name", false)),
		attr("type", "string", true, "readOnly", "none", "Attribute type", false),
		attr("multiValued", "boolean", true, "readOnly", "none", "Multi-valued flag", false),
		attr("description", "string", false, "readOnly", "none", "Attribute description", false),
		attr("required", "boolean", false, "readOnly", "none", "Required flag", false),
		withCaseExact(attr("canonicalValues", "string", false, "readOnly", "none", "Canonical values", true)),
		attr("caseExact", "boolean", false, "readOnly", "none", "Case exact flag", false),
		withCaseExact(attr("mutability", "string", false, "readOnly", "none", "Mutability", false)),
		withCaseExact(attr("returned", "string", false, "readOnly", "none", "Returned behavior", false)),
		withCaseExact(attr("uniqueness", "string", false, "readOnly", "none", "Uniqueness", false)),
		withCaseExact(attr("referenceTypes", "string", false, "readOnly", "none", "Reference types", true)),
	}

	subAttributesAttr := attr("subAttributes", "complex", false, "readOnly", "none", "Sub-attributes", true)
	subAttributesAttr["subAttributes"] = innerSubAttributes

	typeAttr := attr("type", "string", true, "readOnly", "none", "Attribute type", false)
	typeAttr["canonicalValues"] = []string{"string", "boolean", "decimal", "integer", "dateTime", "reference", "complex", "binary"}

	mutabilityAttr := withCaseExact(attr("mutability", "string", false, "readOnly", "none", "Mutability", false))
	mutabilityAttr["canonicalValues"] = []string{"readOnly", "readWrite", "immutable", "writeOnly"}

	returnedAttr := withCaseExact(attr("returned", "string", false, "readOnly", "none", "Returned behavior", false))
	returnedAttr["canonicalValues"] = []string{"always", "never", "default", "request"}

	uniquenessAttr := withCaseExact(attr("uniqueness", "string", false, "readOnly", "none", "Uniqueness", false))
	uniquenessAttr["canonicalValues"] = []string{"none", "server", "global"}

	attributeSubAttributes := []map[string]any{
		withCaseExact(attr("name", "string", true, "readOnly", "none", "Attribute name", false)),
		typeAttr,
		attr("multiValued", "boolean", true, "readOnly", "none", "Multi-valued flag", false),
		attr("description", "string", false, "readOnly", "none", "Attribute description", false),
		attr("required", "boolean", false, "readOnly", "none", "Required flag", false),
		withCaseExact(attr("canonicalValues", "string", false, "readOnly", "none", "Canonical values", true)),
		attr("caseExact", "boolean", false, "readOnly", "none", "Case exact flag", false),
		mutabilityAttr,
		returnedAttr,
		uniquenessAttr,
		withCaseExact(attr("referenceTypes", "string", false, "readOnly", "none", "Reference types", true)),
		subAttributesAttr,
	}

	attributes := withSubAttributes(attr("attributes", "complex", true, "readOnly", "none",
		"Schema attribute definitions", true), attributeSubAttributes...)

	attrs := []map[string]any{
		attr("name", "string", true, "readOnly", "none", "Schema name", false),
		attr("description", "string", false, "readOnly", "none", "Schema description", false),
		attributes,
	}

	return map[string]any{
		"schemas":    []string{coreSchemaURN},
		"id":         coreSchemaURN,
		"name":       "Schema",
		"description": "Schema for representing schemas",
		"attributes": attrs,
		"meta": map[string]any{
			"resourceType": "Schema",
			"location":     "/Schemas/urn:ietf:params:scim:schemas:core:2.0:Schema",
		},
	}
}

// ── Helpers ──────────────────────────────────────────────

func attr(name, attrType string, required bool, mutability, uniqueness, description string, multiValued bool) map[string]any {
	a := map[string]any{
		"name":        name,
		"type":        attrType,
		"multiValued": multiValued,
		"description": description,
		"required":    required,
		"mutability":  mutability,
		"returned":    "default",
	}
	if attrType == "string" || attrType == "reference" {
		a["caseExact"] = false
		a["uniqueness"] = uniqueness
	}
	return a
}

func withCaseExact(a map[string]any) map[string]any {
	a["caseExact"] = true
	return a
}

func withReturned(a map[string]any, returned string) map[string]any {
	a["returned"] = returned
	return a
}

func withSubAttributes(a map[string]any, subs ...map[string]any) map[string]any {
	a["subAttributes"] = subs
	return a
}

func withRefTypes(a map[string]any, types ...string) map[string]any {
	a["referenceTypes"] = types
	return a
}

// ── Sub-attribute definitions for multi-valued types ──────

func emailsSubAttributes() []map[string]any {
	t := attr("type", "string", false, "readWrite", "none", "The type label", false)
	t["canonicalValues"] = []string{"work", "home", "other"}
	return []map[string]any{
		attr("value", "string", false, "readWrite", "none", "The value", false),
		t,
		attr("display", "string", false, "readWrite", "none", "Human-readable name", false),
		attr("primary", "boolean", false, "readWrite", "none", "Primary indicator", false),
	}
}

func phoneNumbersSubAttributes() []map[string]any {
	t := attr("type", "string", false, "readWrite", "none", "The type label", false)
	t["canonicalValues"] = []string{"work", "home", "mobile", "fax", "pager", "other"}
	return []map[string]any{
		attr("value", "string", false, "readWrite", "none", "The value", false),
		t,
		attr("display", "string", false, "readWrite", "none", "Human-readable name", false),
		attr("primary", "boolean", false, "readWrite", "none", "Primary indicator", false),
	}
}

func imsSubAttributes() []map[string]any {
	t := attr("type", "string", false, "readWrite", "none", "The type label", false)
	t["canonicalValues"] = []string{"aim", "gtalk", "icq", "xmpp", "skype", "qq", "msn", "yahoo"}
	return []map[string]any{
		attr("value", "string", false, "readWrite", "none", "The value", false),
		t,
		attr("display", "string", false, "readWrite", "none", "Human-readable name", false),
		attr("primary", "boolean", false, "readWrite", "none", "Primary indicator", false),
	}
}

func photosSubAttributes() []map[string]any {
	v := withCaseExact(attr("value", "reference", false, "readWrite", "none", "The value", false))
	v["referenceTypes"] = []string{"external"}
	t := attr("type", "string", false, "readWrite", "none", "The type label", false)
	t["canonicalValues"] = []string{"photo", "thumbnail"}
	return []map[string]any{
		v,
		t,
		attr("display", "string", false, "readWrite", "none", "Human-readable name", false),
		attr("primary", "boolean", false, "readWrite", "none", "Primary indicator", false),
	}
}

func addressesSubAttributes() []map[string]any {
	t := attr("type", "string", false, "readWrite", "none", "Address type (work, home, other)", false)
	t["canonicalValues"] = []string{"work", "home", "other"}
	return []map[string]any{
		attr("formatted", "string", false, "readWrite", "none", "Full mailing address", false),
		attr("streetAddress", "string", false, "readWrite", "none", "Street address", false),
		attr("locality", "string", false, "readWrite", "none", "City or locality", false),
		attr("region", "string", false, "readWrite", "none", "State or region", false),
		attr("postalCode", "string", false, "readWrite", "none", "Postal code", false),
		attr("country", "string", false, "readWrite", "none", "Country", false),
		t,
		attr("primary", "boolean", false, "readWrite", "none", "Primary address indicator", false),
	}
}

func entitlementsSubAttributes() []map[string]any {
	return []map[string]any{
		attr("value", "string", false, "readWrite", "none", "The value", false),
		attr("type", "string", false, "readWrite", "none", "The type label", false),
		attr("display", "string", false, "readWrite", "none", "Human-readable name", false),
		attr("primary", "boolean", false, "readWrite", "none", "Primary indicator", false),
	}
}

func rolesSubAttributes() []map[string]any {
	return []map[string]any{
		attr("value", "string", false, "readWrite", "none", "The value", false),
		attr("type", "string", false, "readWrite", "none", "The type label", false),
		attr("display", "string", false, "readWrite", "none", "Human-readable name", false),
		attr("primary", "boolean", false, "readWrite", "none", "Primary indicator", false),
	}
}

func x509CertificatesSubAttributes() []map[string]any {
	v := attr("value", "binary", false, "readWrite", "none", "The value", false)
	v["caseExact"] = true
	return []map[string]any{
		v,
		attr("type", "string", false, "readWrite", "none", "The type label", false),
		attr("display", "string", false, "readWrite", "none", "Human-readable name", false),
		attr("primary", "boolean", false, "readWrite", "none", "Primary indicator", false),
	}
}

func groupsSubAttributes() []map[string]any {
	ref := withCaseExact(attr("$ref", "reference", false, "readOnly", "none", "Group URI", false))
	ref["referenceTypes"] = []string{"Group"}
	t := attr("type", "string", false, "readOnly", "none", "Membership type", false)
	t["canonicalValues"] = []string{"direct", "indirect"}
	return []map[string]any{
		attr("value", "string", false, "readOnly", "none", "Group id", false),
		ref,
		attr("display", "string", false, "readOnly", "none", "Group displayName", false),
		t,
	}
}

func membersSubAttributes() []map[string]any {
	ref := withCaseExact(attr("$ref", "reference", false, "immutable", "none", "Member URI", false))
	ref["referenceTypes"] = []string{"User", "Group"}
	t := attr("type", "string", false, "immutable", "none", "Member type (User or Group)", false)
	t["canonicalValues"] = []string{"User", "Group"}
	return []map[string]any{
		attr("value", "string", false, "immutable", "none", "Member identifier", false),
		ref,
		attr("display", "string", false, "readOnly", "none", "Member display name", false),
		t,
	}
}
