/*
Copyright 2026.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package controller

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"strings"
	"testing"
	"time"
)

// validPEM is a real-world TrustCor root certificate (expires 2029-12-31).
const validPEM = `-----BEGIN CERTIFICATE-----
MIIEMDCCAxigAwIBAgIJANqb7HHzA7AZMA0GCSqGSIb3DQEBCwUAMIGkMQswCQYD
VQQGEwJQQTEPMA0GA1UECAwGUGFuYW1hMRQwEgYDVQQHDAtQYW5hbWEgQ2l0eTEk
MCIGA1UECgwbVHJ1c3RDb3IgU3lzdGVtcyBTLiBkZSBSLkwuMScwJQYDVQQLDB5U
cnVzdENvciBDZXJ0aWZpY2F0ZSBBdXRob3JpdHkxHzAdBgNVBAMMFlRydXN0Q29y
IFJvb3RDZXJ0IENBLTEwHhcNMTYwMjA0MTIzMjE2WhcNMjkxMjMxMTcyMzE2WjCB
pDELMAkGA1UEBhMCUEExDzANBgNVBAgMBlBhbmFtYTEUMBIGA1UEBwwLUGFuYW1h
IENpdHkxJDAiBgNVBAoMG1RydXN0Q29yIFN5c3RlbXMgUy4gZGUgUi5MLjEnMCUG
A1UECwweVHJ1c3RDb3IgQ2VydGlmaWNhdGUgQXV0aG9yaXR5MR8wHQYDVQQDDBZU
cnVzdENvciBSb290Q2VydCBDQS0xMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIB
CgKCAQEAv463leLCJhJrMxnHQFgKq1mqjQCj/IDHUHuO1CAmujIS2CNUSSUQIpid
RtLByZ5OGy4sDjjzGiVoHKZaBeYei0i/mJZ0PmnK6bV4pQa81QBeCQryJ3pS/C3V
seq0iWEk8xoT26nPUu0MJLq5nux+AHT6k61sKZKuUbS701e/s/OojZz0JEsq1pme
9J7+wH5COucLlVPat2gOkEz7cD+PSiyU8ybdY2mplNgQTsVHCJCZGxdNuWxu72CV
EY4hgLW9oHPY0LJ3xEXqWib7ZnZ2+AYfYW0PVcWDtxBWcgYHpfOxGgMFZA6dWorW
hnAbJN7+KIor0Gqw/Hqi3LJ5DotlDwIDAQABo2MwYTAdBgNVHQ4EFgQU7mtJPHo/
DeOxCbeKyKsZn3MzUOcwHwYDVR0jBBgwFoAU7mtJPHo/DeOxCbeKyKsZn3MzUOcw
DwYDVR0TAQH/BAUwAwEB/zAOBgNVHQ8BAf8EBAMCAYYwDQYJKoZIhvcNAQELBQAD
ggEBACUY1JGPE+6PHh0RU9otRCkZoB5rMZ5NDp6tPVxBb5UrJKF5mDo4Nvu7Zp5I
/5CQ7z3UuJu0h3U/IJvOcs+hVcFNZKIZBqEHMwwLKeXx6quj7LUKdJDHfXLy11yf
ke+Ri7fc7Waiz45mO7yfOgLgJ90WmMCV1Aqk5IGadZQ1nJBfiDcGrVmVCrDRZ9MZ
yonnMlo2HD6CqFqTvsbQZJG2z9m2GM/bftJlo6bEjhcxwft+dtvTheNYsnd6djts
L1Ac59v2Z3kf9YKVmgenFK+P3CghZwnS1k1aHBkcjndcw5QkPTJrS37UeJSDvjdN
zl/HHk484IkzlQsPpTLWPFp5LBk=
-----END CERTIFICATE-----
`

// generateSelfSignedPEM creates a self-signed certificate PEM with the given
// validity window. Useful for producing expired or far-future test certs.
func generateSelfSignedPEM(t *testing.T, notBefore, notAfter time.Time) []byte {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate private key: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test-cert"},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageCertSign,
		IsCA:                  true,
		BasicConstraintsValid: true,
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("failed to create certificate: %v", err)
	}

	return pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: derBytes,
	})
}

// ---------------------------------------------------------------------------
// getCertsFromPEM tests
// ---------------------------------------------------------------------------

func TestGetCertsFromPEM_ValidSingleCert(t *testing.T) {
	cab := &caBundle{}
	err := cab.getCertsFromPEM([]byte(validPEM))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(cab.certs) != 1 {
		t.Fatalf("expected 1 cert, got %d", len(cab.certs))
	}
	if cab.certs[0].cert.Subject.CommonName != "TrustCor RootCert CA-1" {
		t.Errorf("unexpected CN: %s", cab.certs[0].cert.Subject.CommonName)
	}
}

func TestGetCertsFromPEM_ValidMultipleCerts(t *testing.T) {
	now := time.Now()
	cert1 := generateSelfSignedPEM(t, now.Add(-1*time.Hour), now.Add(10*365*24*time.Hour))
	cert2 := generateSelfSignedPEM(t, now.Add(-2*time.Hour), now.Add(10*365*24*time.Hour))

	combined := append(cert1, cert2...)

	cab := &caBundle{}
	err := cab.getCertsFromPEM(combined)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(cab.certs) != 2 {
		t.Fatalf("expected 2 certs, got %d", len(cab.certs))
	}
}

func TestGetCertsFromPEM_InvalidBlockType(t *testing.T) {
	privKeyPEM := []byte(`-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEIOlahWCjbH4UqSYP3tqOmP6MuEnMxOPHsYulrfWZ/3aV
-----END PRIVATE KEY-----
`)
	cab := &caBundle{}
	err := cab.getCertsFromPEM(privKeyPEM)
	if err == nil {
		t.Fatal("expected error for non-CERTIFICATE block, got nil")
	}
	if !strings.Contains(err.Error(), "PRIVATE KEY") {
		t.Errorf("error should mention the invalid block type, got: %v", err)
	}
}

func TestGetCertsFromPEM_InvalidX509Data(t *testing.T) {
	// A CERTIFICATE block with garbage bytes inside.
	garbage := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: []byte("this is not valid DER data"),
	})

	cab := &caBundle{}
	err := cab.getCertsFromPEM(garbage)
	if err == nil {
		t.Fatal("expected error for invalid X.509 data, got nil")
	}
	if !strings.Contains(err.Error(), "invalid certificate") {
		t.Errorf("error should mention invalid certificate, got: %v", err)
	}
}

func TestGetCertsFromPEM_NilInput(t *testing.T) {
	cab := &caBundle{}
	err := cab.getCertsFromPEM(nil)
	if err == nil {
		t.Fatal("expected error for nil input, got nil")
	}
	if !strings.Contains(err.Error(), "nil") {
		t.Errorf("error should mention nil, got: %v", err)
	}
}

func TestGetCertsFromPEM_EmptyInput(t *testing.T) {
	cab := &caBundle{}
	err := cab.getCertsFromPEM([]byte(""))
	if err != nil {
		t.Fatalf("unexpected error for empty input: %v", err)
	}
	if len(cab.certs) != 0 {
		t.Errorf("expected 0 certs for empty input, got %d", len(cab.certs))
	}
}

func TestGetCertsFromPEM_NoPEMBlocks(t *testing.T) {
	// Non-empty but contains no PEM blocks (just plain text).
	cab := &caBundle{}
	err := cab.getCertsFromPEM([]byte("hello world, no PEM here"))
	if err != nil {
		t.Fatalf("unexpected error for input with no PEM blocks: %v", err)
	}
	if len(cab.certs) != 0 {
		t.Errorf("expected 0 certs, got %d", len(cab.certs))
	}
}

func TestGetCertsFromPEM_Deduplication(t *testing.T) {
	// The same valid PEM certificate concatenated twice.
	doubled := append([]byte(validPEM), []byte(validPEM)...)

	cab := &caBundle{}
	err := cab.getCertsFromPEM(doubled)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(cab.certs) != 1 {
		t.Fatalf("expected 1 cert after dedup, got %d", len(cab.certs))
	}
}

func TestGetCertsFromPEM_DeduplicationAcrossCalls(t *testing.T) {
	// Calling getCertsFromPEM twice with the same data should still deduplicate.
	cab := &caBundle{}
	if err := cab.getCertsFromPEM([]byte(validPEM)); err != nil {
		t.Fatalf("first call: unexpected error: %v", err)
	}
	if err := cab.getCertsFromPEM([]byte(validPEM)); err != nil {
		t.Fatalf("second call: unexpected error: %v", err)
	}
	if len(cab.certs) != 1 {
		t.Fatalf("expected 1 cert after dedup across calls, got %d", len(cab.certs))
	}
}

func TestGetCertsFromPEM_ExpiredCertSkipped(t *testing.T) {
	// Generate a certificate that expired yesterday.
	now := time.Now()
	expiredPEM := generateSelfSignedPEM(t, now.Add(-48*time.Hour), now.Add(-24*time.Hour))

	cab := &caBundle{}
	err := cab.getCertsFromPEM(expiredPEM)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(cab.certs) != 0 {
		t.Fatalf("expected 0 certs (expired should be skipped), got %d", len(cab.certs))
	}
}

func TestGetCertsFromPEM_MixedExpiredAndValid(t *testing.T) {
	now := time.Now()
	expiredPEM := generateSelfSignedPEM(t, now.Add(-48*time.Hour), now.Add(-24*time.Hour))
	combined := append(expiredPEM, []byte(validPEM)...)

	cab := &caBundle{}
	err := cab.getCertsFromPEM(combined)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(cab.certs) != 1 {
		t.Fatalf("expected 1 cert (only the valid one), got %d", len(cab.certs))
	}
	if cab.certs[0].cert.Subject.CommonName != "TrustCor RootCert CA-1" {
		t.Errorf("expected the valid cert to remain, got CN=%s", cab.certs[0].cert.Subject.CommonName)
	}
}

// ---------------------------------------------------------------------------
// encodePEM tests
// ---------------------------------------------------------------------------

func TestEncodePEM_RoundTrip(t *testing.T) {
	// Parse the valid cert, encode it, parse again, compare.
	cab := &caBundle{}
	if err := cab.getCertsFromPEM([]byte(validPEM)); err != nil {
		t.Fatalf("initial parse failed: %v", err)
	}

	encoded := cab.encodePEM()
	if len(encoded) == 0 {
		t.Fatal("encodePEM returned empty output")
	}

	cab2 := &caBundle{}
	if err := cab2.getCertsFromPEM(encoded); err != nil {
		t.Fatalf("round-trip parse failed: %v", err)
	}

	if len(cab2.certs) != len(cab.certs) {
		t.Fatalf("cert count mismatch after round-trip: original=%d, decoded=%d",
			len(cab.certs), len(cab2.certs))
	}

	if cab.certs[0].hash != cab2.certs[0].hash {
		t.Error("certificate hash mismatch after round-trip")
	}
}

func TestEncodePEM_MultipleCerts(t *testing.T) {
	now := time.Now()
	cert1 := generateSelfSignedPEM(t, now.Add(-1*time.Hour), now.Add(10*365*24*time.Hour))
	cert2 := generateSelfSignedPEM(t, now.Add(-2*time.Hour), now.Add(10*365*24*time.Hour))
	combined := append(cert1, cert2...)

	cab := &caBundle{}
	if err := cab.getCertsFromPEM(combined); err != nil {
		t.Fatalf("initial parse failed: %v", err)
	}
	if len(cab.certs) != 2 {
		t.Fatalf("expected 2 certs, got %d", len(cab.certs))
	}

	encoded := cab.encodePEM()

	cab2 := &caBundle{}
	if err := cab2.getCertsFromPEM(encoded); err != nil {
		t.Fatalf("round-trip parse failed: %v", err)
	}
	if len(cab2.certs) != 2 {
		t.Fatalf("expected 2 certs after round-trip, got %d", len(cab2.certs))
	}
}

func TestEncodePEM_EmptyBundle(t *testing.T) {
	cab := &caBundle{}
	encoded := cab.encodePEM()
	if encoded != nil {
		t.Errorf("expected nil for empty bundle, got %d bytes", len(encoded))
	}
}

func TestEncodePEM_ProducesValidPEMBlocks(t *testing.T) {
	cab := &caBundle{}
	if err := cab.getCertsFromPEM([]byte(validPEM)); err != nil {
		t.Fatalf("parse failed: %v", err)
	}

	encoded := cab.encodePEM()

	// Verify each PEM block can be decoded and is of type CERTIFICATE.
	rest := encoded
	blockCount := 0
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		blockCount++
		if block.Type != "CERTIFICATE" {
			t.Errorf("expected CERTIFICATE block type, got %q", block.Type)
		}
	}
	if blockCount != 1 {
		t.Errorf("expected 1 PEM block, got %d", blockCount)
	}
}

// ---------------------------------------------------------------------------
// encodePEM / getCertsFromPEM: raw bytes preservation
// ---------------------------------------------------------------------------

func TestEncodePEM_PreservesRawCertBytes(t *testing.T) {
	cab := &caBundle{}
	if err := cab.getCertsFromPEM([]byte(validPEM)); err != nil {
		t.Fatalf("parse failed: %v", err)
	}

	// Grab the raw DER bytes from the parsed cert.
	originalRaw := cab.certs[0].cert.Raw

	encoded := cab.encodePEM()
	block, _ := pem.Decode(encoded)
	if block == nil {
		t.Fatal("failed to decode PEM from encodePEM output")
	}

	if !bytes.Equal(block.Bytes, originalRaw) {
		t.Error("encoded DER bytes do not match original raw bytes")
	}
}

// ---------------------------------------------------------------------------
// caBundle hash field
// ---------------------------------------------------------------------------

func TestCaBundleCert_HashMatchesDER(t *testing.T) {
	cab := &caBundle{}
	if err := cab.getCertsFromPEM([]byte(validPEM)); err != nil {
		t.Fatalf("parse failed: %v", err)
	}

	block, _ := pem.Decode([]byte(validPEM))
	if block == nil {
		t.Fatal("failed to decode validPEM")
	}
	expectedHash := sha256.Sum256(block.Bytes)

	if cab.certs[0].hash != expectedHash {
		t.Error("stored hash does not match SHA256 of DER bytes")
	}
}

// ---------------------------------------------------------------------------
// getOperatorCABundle override
// ---------------------------------------------------------------------------

func TestGetOperatorCABundle_Override(t *testing.T) {
	// Save the original so we can restore it after the test.
	original := getOperatorCABundle
	t.Cleanup(func() { getOperatorCABundle = original })

	expectedData := []byte("mock-ca-bundle-data")
	getOperatorCABundle = func() ([]byte, error) {
		return expectedData, nil
	}

	data, err := getOperatorCABundle()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !bytes.Equal(data, expectedData) {
		t.Errorf("expected %q, got %q", expectedData, data)
	}
}

func TestGetOperatorCABundle_OverrideError(t *testing.T) {
	original := getOperatorCABundle
	t.Cleanup(func() { getOperatorCABundle = original })

	getOperatorCABundle = func() ([]byte, error) {
		return nil, errMockCABundle
	}

	data, err := getOperatorCABundle()
	if err == nil {
		t.Fatal("expected error from overridden getOperatorCABundle, got nil")
	}
	if data != nil {
		t.Errorf("expected nil data on error, got %d bytes", len(data))
	}
}

// errMockCABundle is a sentinel error for testing getOperatorCABundle overrides.
var errMockCABundle = &mockError{msg: "mock CA bundle error"}

type mockError struct{ msg string }

func (e *mockError) Error() string { return e.msg }
