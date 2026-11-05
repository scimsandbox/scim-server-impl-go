package scim

import (
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"fmt"
	"regexp"
	"strings"
	"unicode"

	"golang.org/x/text/unicode/norm"
)

var (
	compactE164Regex = regexp.MustCompile(`^\+[1-9][0-9]{1,14}$`)
	sepRunRegex      = regexp.MustCompile(`[\s.()-]+`)
)

// NormalizeNFC normalizes a string to Unicode Normalization Form C (NFC) per RFC 7644 §7.8.
func NormalizeNFC(s string) string {
	if s == "" {
		return s
	}
	return norm.NFC.String(s)
}

// CanonicalizeEmail trims surrounding whitespace, normalizes to NFC, and lowercases the domain part.
func CanonicalizeEmail(raw string) string {
	s := NormalizeNFC(strings.TrimSpace(raw))
	at := strings.LastIndexByte(s, '@')
	if at > 0 && at < len(s)-1 {
		return s[:at+1] + strings.ToLower(s[at+1:])
	}
	return s
}

// CanonicalizePhoneNumber canonicalizes formatted international phone numbers and tel: URIs
// to RFC 3966 global tel: format while preserving compact E.164 and local numbers.
func CanonicalizePhoneNumber(raw string) string {
	s := strings.TrimSpace(raw)
	if s == "" {
		return ""
	}
	if strings.HasPrefix(strings.ToLower(s), "tel:") {
		body := strings.TrimSpace(s[4:])
		body = strings.ReplaceAll(body, "(", "")
		body = strings.ReplaceAll(body, ")", "")
		body = sepRunRegex.ReplaceAllString(body, "-")
		body = strings.ReplaceAll(body, "+-", "+")
		body = strings.Trim(body, "-")
		return "tel:" + body
	}
	if compactE164Regex.MatchString(s) {
		return s
	}
	if strings.HasPrefix(s, "+") {
		cleaned := strings.ReplaceAll(s, "(", "")
		cleaned = strings.ReplaceAll(cleaned, ")", "")
		cleaned = sepRunRegex.ReplaceAllString(cleaned, "-")
		cleaned = strings.ReplaceAll(cleaned, "+-", "+")
		cleaned = strings.Trim(cleaned, "-")
		return "tel:" + cleaned
	}
	return NormalizeNFC(s)
}

// CanonicalizeIM strips all Unicode whitespace and lowercases instant messaging identifiers.
func CanonicalizeIM(raw string) string {
	var b strings.Builder
	for _, r := range NormalizeNFC(raw) {
		if !unicode.IsSpace(r) {
			b.WriteRune(unicode.ToLower(r))
		}
	}
	return b.String()
}

// ValidateX509CertificateValue validates that an x509Certificates.value is strict RFC 4648 Base64
// and, if ASN.1 DER encoded, does not contain multiple concatenated or sequence-wrapped X.509 certificates.
func ValidateX509CertificateValue(val string) error {
	if val == "" {
		return NewScimError(400, "invalidValue", "x509Certificates value must not be empty")
	}
	if strings.ContainsAny(val, " \t\r\n") || strings.Contains(val, "-----") {
		return NewScimError(400, "invalidValue", "x509Certificates value must be strict base64 DER without PEM headers or whitespace")
	}
	der, err := base64.StdEncoding.Strict().DecodeString(val)
	if err != nil {
		return NewScimError(400, "invalidValue", "Invalid base64 encoding for x509Certificates value")
	}
	if len(der) == 0 {
		return NewScimError(400, "invalidValue", "Decoded x509Certificates value is empty")
	}

	if der[0] == 0x30 {
		var first asn1.RawValue
		rest, asnErr := asn1.Unmarshal(der, &first)
		if asnErr == nil {
			if len(rest) > 0 {
				if isDERCertificateStructure(first.FullBytes) {
					return NewScimError(400, "invalidValue", "x509Certificates value must contain a single DER certificate, not multiple concatenated certificates")
				}
			} else if !isDERCertificateStructure(der) && len(first.Bytes) > 0 && first.Bytes[0] == 0x30 {
				inner := first.Bytes
				certCount := 0
				for len(inner) > 0 {
					var elem asn1.RawValue
					nextRest, eErr := asn1.Unmarshal(inner, &elem)
					if eErr != nil || !isDERCertificateStructure(elem.FullBytes) {
						certCount = 0
						break
					}
					certCount++
					inner = nextRest
				}
				if certCount > 1 {
					return NewScimError(400, "invalidValue", "x509Certificates value must not be a sequence of multiple certificates")
				}
			}
		}
	}
	return nil
}

// isDERCertificateStructure checks whether b conforms to the RFC 5280 §4.1.1 ASN.1 DER
// Certificate structure: SEQUENCE { tbsCertificate SEQUENCE, signatureAlgorithm SEQUENCE, signatureValue BIT STRING }.
// Checking the ASN.1 structure in addition to crypto/x509 ensures certificates using explicit EC
// domain parameters (SpecifiedECDomain) or custom OIDs unsupported by Go's x509 parser are still recognized.
func isDERCertificateStructure(b []byte) bool {
	if len(b) == 0 {
		return false
	}
	if _, err := x509.ParseCertificate(b); err == nil {
		return true
	}
	var outer asn1.RawValue
	rest, err := asn1.Unmarshal(b, &outer)
	if err != nil || len(rest) != 0 || outer.Class != asn1.ClassUniversal || outer.Tag != asn1.TagSequence || !outer.IsCompound {
		return false
	}

	var tbs asn1.RawValue
	rem1, err1 := asn1.Unmarshal(outer.Bytes, &tbs)
	if err1 != nil || len(rem1) == 0 || tbs.Class != asn1.ClassUniversal || tbs.Tag != asn1.TagSequence || !tbs.IsCompound {
		return false
	}

	var sigAlg asn1.RawValue
	rem2, err2 := asn1.Unmarshal(rem1, &sigAlg)
	if err2 != nil || len(rem2) == 0 || sigAlg.Class != asn1.ClassUniversal || sigAlg.Tag != asn1.TagSequence || !sigAlg.IsCompound {
		return false
	}

	var sigVal asn1.RawValue
	rem3, err3 := asn1.Unmarshal(rem2, &sigVal)
	if err3 != nil || len(rem3) != 0 || sigVal.Class != asn1.ClassUniversal || sigVal.Tag != asn1.TagBitString {
		return false
	}

	return true
}

// ValidateSinglePrimary verifies that at most one element in an incoming multi-valued item slice
// specifies primary=true, and that any present primary attribute is a strict boolean.
func ValidateSinglePrimary(items []map[string]any) error {
	primaryCount := 0
	for _, m := range items {
		if pRaw, exists := m["primary"]; exists && pRaw != nil {
			b, ok := pRaw.(bool)
			if !ok {
				return NewScimError(400, "invalidValue", fmt.Sprintf("Attribute 'primary' must be a boolean, got %T", pRaw))
			}
			if b {
				primaryCount++
			}
		}
	}
	if primaryCount > 1 {
		return NewScimError(400, "invalidValue", "At most one element in a multi-valued attribute may have primary=true")
	}
	return nil
}
