package scim

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"math/big"
	"testing"
	"time"
)

func generateTestDERCert(t *testing.T, cn string) []byte {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}
	return der
}

// generateExplicitECParamsDERCert builds a valid RFC 5280 §4.1.1 ASN.1 DER Certificate
// whose SubjectPublicKeyInfo uses explicit EC domain parameters (SpecifiedECDomain SEQUENCE)
// rather than a namedCurve OID, which Go's crypto/x509.ParseCertificate rejects.
func generateExplicitECParamsDERCert(t *testing.T, serial int64) []byte {
	t.Helper()
	type algID struct {
		Algorithm  asn1.ObjectIdentifier
		Parameters asn1.RawValue `asn1:"optional"`
	}
	type explicitECDomain struct {
		Version int
		FieldID struct {
			FieldType  asn1.ObjectIdentifier
			Parameters *big.Int
		}
	}
	type validity struct {
		NotBefore time.Time
		NotAfter  time.Time
	}
	type spki struct {
		Algorithm algID
		PublicKey asn1.BitString
	}
	type tbsCert struct {
		SerialNumber       *big.Int
		SignatureAlgorithm algID
		Issuer             asn1.RawValue
		Validity           validity
		Subject            asn1.RawValue
		PublicKey          spki
	}
	type derCert struct {
		TBS                tbsCert
		SignatureAlgorithm algID
		SignatureValue     asn1.BitString
	}

	nameBytes, err := asn1.Marshal(pkix.Name{CommonName: "explicit-ec.example.com"}.ToRDNSequence())
	if err != nil {
		t.Fatalf("marshal name: %v", err)
	}
	ecParamsBytes, err := asn1.Marshal(explicitECDomain{
		Version: 1,
		FieldID: struct {
			FieldType  asn1.ObjectIdentifier
			Parameters *big.Int
		}{
			FieldType:  asn1.ObjectIdentifier{1, 2, 840, 10045, 1, 1},
			Parameters: big.NewInt(23),
		},
	})
	if err != nil {
		t.Fatalf("marshal explicit ec params: %v", err)
	}

	ecdsaSHA256 := algID{Algorithm: asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 2}}
	cert := derCert{
		TBS: tbsCert{
			SerialNumber:       big.NewInt(serial),
			SignatureAlgorithm: ecdsaSHA256,
			Issuer:             asn1.RawValue{FullBytes: nameBytes},
			Validity: validity{
				NotBefore: time.Now().UTC().Add(-time.Hour),
				NotAfter:  time.Now().UTC().Add(time.Hour),
			},
			Subject: asn1.RawValue{FullBytes: nameBytes},
			PublicKey: spki{
				Algorithm: algID{
					Algorithm:  asn1.ObjectIdentifier{1, 2, 840, 10045, 2, 1},
					Parameters: asn1.RawValue{FullBytes: ecParamsBytes},
				},
				PublicKey: asn1.BitString{Bytes: []byte{0x04, 0x01, 0x02}, BitLength: 24},
			},
		},
		SignatureAlgorithm: ecdsaSHA256,
		SignatureValue:     asn1.BitString{Bytes: []byte{0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01}, BitLength: 64},
	}

	der, err := asn1.Marshal(cert)
	if err != nil {
		t.Fatalf("marshal explicit-EC cert: %v", err)
	}
	if _, parseErr := x509.ParseCertificate(der); parseErr == nil {
		t.Fatal("expected crypto/x509.ParseCertificate to fail on explicit SpecifiedECDomain parameters")
	}
	return der
}

func TestNormalizeNFC(t *testing.T) {
	nfd := "J\u006fse\u0301"
	nfc := "Jos\u00e9"
	if got := NormalizeNFC(nfd); got != nfc {
		t.Fatalf("NormalizeNFC(%q) = %q, want %q", nfd, got, nfc)
	}
	if got := NormalizeNFC("plain-ascii@example.com"); got != "plain-ascii@example.com" {
		t.Fatalf("NormalizeNFC altered ASCII input: %q", got)
	}
}

func TestCanonicalizeEmail(t *testing.T) {
	if got := CanonicalizeEmail("  Alice.Smith@EXAMPLE.COM "); got != "Alice.Smith@example.com" {
		t.Fatalf("CanonicalizeEmail = %q, want %q", got, "Alice.Smith@example.com")
	}
}

func TestCanonicalizePhoneNumber(t *testing.T) {
	tests := []struct {
		in   string
		want string
	}{
		{"+1 (201) 555-0123", "tel:+1-201-555-0123"},
		{"+155733333333", "+155733333333"},
		{"123-456", "123-456"},
		{"tel:+1-201-555-0123", "tel:+1-201-555-0123"},
	}
	for _, tc := range tests {
		if got := CanonicalizePhoneNumber(tc.in); got != tc.want {
			t.Errorf("CanonicalizePhoneNumber(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestCanonicalizeIM(t *testing.T) {
	if got := CanonicalizeIM("  User @ Gmail.com "); got != "user@gmail.com" {
		t.Fatalf("CanonicalizeIM = %q, want user@gmail.com", got)
	}
	if got := CanonicalizeIM("xmpp:Alice@Example.com"); got != "xmpp:alice@example.com" {
		t.Fatalf("CanonicalizeIM = %q, want xmpp:alice@example.com", got)
	}
}

func TestValidateX509CertificateValue(t *testing.T) {
	if err := ValidateX509CertificateValue("!!!not-base64!!!"); err == nil {
		t.Fatal("expected error for invalid base64 certificate")
	}

	// Arbitrary valid base64 binary (including 33-byte random payloads and leading 0x30 non-cert bytes) is allowed
	random33 := make([]byte, 33)
	if _, err := rand.Read(random33); err != nil {
		t.Fatalf("rand.Read: %v", err)
	}
	if err := ValidateX509CertificateValue(base64.StdEncoding.EncodeToString(random33)); err != nil {
		t.Fatalf("unexpected error for 33-byte random binary base64: %v", err)
	}
	randomLeading30 := append([]byte{0x30, 0x03, 0x02, 0x01, 0x05}, random33...)
	if err := ValidateX509CertificateValue(base64.StdEncoding.EncodeToString(randomLeading30)); err != nil {
		t.Fatalf("unexpected error for non-certificate 0x30-prefixed binary base64: %v", err)
	}

	// Single valid DER X.509 certificate succeeds
	cert1 := generateTestDERCert(t, "cert-one.example.com")
	if err := ValidateX509CertificateValue(base64.StdEncoding.EncodeToString(cert1)); err != nil {
		t.Fatalf("unexpected error for single valid DER certificate: %v", err)
	}

	// Two concatenated DER X.509 certificates must be rejected (RFC 7643 §4.1.2)
	cert2 := generateTestDERCert(t, "cert-two.example.com")
	concat := append(append([]byte(nil), cert1...), cert2...)
	if err := ValidateX509CertificateValue(base64.StdEncoding.EncodeToString(concat)); err == nil {
		t.Fatal("expected error for concatenated DER certificates, got nil")
	}

	// Outer ASN.1 SEQUENCE wrapping multiple DER certificates must also be rejected
	seqBytes, err := asn1.Marshal([]asn1.RawValue{
		{FullBytes: cert1},
		{FullBytes: cert2},
	})
	if err != nil {
		t.Fatalf("marshal cert sequence: %v", err)
	}
	if err := ValidateX509CertificateValue(base64.StdEncoding.EncodeToString(seqBytes)); err == nil {
		t.Fatal("expected error for ASN.1 SEQUENCE of multiple DER certificates, got nil")
	}

	// Explicit EC domain parameter (SpecifiedECDomain) DER certificates unsupported by Go's crypto/x509:
	// single cert succeeds, while concatenated and SEQUENCE OF Certificate are rejected.
	expCert1 := generateExplicitECParamsDERCert(t, 101)
	expCert2 := generateExplicitECParamsDERCert(t, 102)
	if err := ValidateX509CertificateValue(base64.StdEncoding.EncodeToString(expCert1)); err != nil {
		t.Fatalf("unexpected error for single explicit-EC DER certificate: %v", err)
	}
	expConcat := append(append([]byte(nil), expCert1...), expCert2...)
	if err := ValidateX509CertificateValue(base64.StdEncoding.EncodeToString(expConcat)); err == nil {
		t.Fatal("expected error for concatenated explicit-EC DER certificates, got nil")
	}
	expSeq, err := asn1.Marshal([]asn1.RawValue{
		{FullBytes: expCert1},
		{FullBytes: expCert2},
	})
	if err != nil {
		t.Fatalf("marshal explicit-EC cert sequence: %v", err)
	}
	if err := ValidateX509CertificateValue(base64.StdEncoding.EncodeToString(expSeq)); err == nil {
		t.Fatal("expected error for ASN.1 SEQUENCE of explicit-EC DER certificates, got nil")
	}
}

func TestValidateSinglePrimary(t *testing.T) {
	okItems := []map[string]any{
		{"value": "a@example.com", "primary": true},
		{"value": "b@example.com", "primary": false},
	}
	if err := ValidateSinglePrimary(okItems); err != nil {
		t.Fatalf("unexpected error for single primary: %v", err)
	}

	twoPrimaries := []map[string]any{
		{"value": "a@example.com", "primary": true},
		{"value": "b@example.com", "primary": true},
	}
	if err := ValidateSinglePrimary(twoPrimaries); err == nil {
		t.Fatal("expected error when two elements have primary=true")
	}

	nonBoolPrimary := []map[string]any{
		{"value": "a@example.com", "primary": "true"},
	}
	if err := ValidateSinglePrimary(nonBoolPrimary); err == nil {
		t.Fatal("expected error when primary is non-boolean string")
	}
}
