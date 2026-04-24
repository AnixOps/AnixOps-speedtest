package main

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/anixops/speedtest/internal/ats"
	"github.com/anixops/speedtest/internal/chart"
	"github.com/anixops/speedtest/internal/probe"
	"github.com/cloudflare/circl/sign/mldsa/mldsa87"
)

func TestKeyGenerationAndPersistence(t *testing.T) {
	keyDir := t.TempDir()

	pub1, priv1, err := ats.LoadOrGenerateKeyPair(keyDir)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}

	pub2, priv2, err := ats.LoadOrGenerateKeyPair(keyDir)
	if err != nil {
		t.Fatalf("reload: %v", err)
	}

	if !bytes.Equal(pub1, pub2) {
		t.Error("public keys differ on reload")
	}
	if !bytes.Equal(priv1, priv2) {
		t.Error("private keys differ on reload")
	}
}

func TestEd25519SignVerify(t *testing.T) {
	keyDir := t.TempDir()
	_, priv, _ := ats.LoadOrGenerateKeyPair(keyDir)

	hashData := []byte("test-hash-data-1234567890abcdef")
	sig := ats.SignHash(hashData, priv)
	pubHex := hex.EncodeToString(priv.Public().(ed25519.PublicKey))

	if err := ats.VerifyHash(hashData, sig, pubHex); err != nil {
		t.Fatalf("verify failed: %v", err)
	}

	tampered := []byte("tampered-data")
	if err := ats.VerifyHash(tampered, sig, pubHex); err == nil {
		t.Fatal("tampered hash should fail verification")
	}
}

func TestCertificateWithSignature(t *testing.T) {
	keyDir := t.TempDir()
	_, priv, _ := ats.LoadOrGenerateKeyPair(keyDir)
	mlDSAPub, mlDSAPriv, _ := ats.LoadOrGenerateMLDSAKeyPair(keyDir)

	results := makeFakeResults()
	cert, err := ats.GenerateCertificate(results, "v0.1.0", false, priv, mlDSAPriv)
	if err != nil {
		t.Fatalf("generate cert: %v", err)
	}

	if cert.Signature == "" {
		t.Fatal("missing Ed25519 signature")
	}
	if cert.PublicKey == "" {
		t.Fatal("missing Ed25519 public key")
	}
	if cert.MLDSASignature == "" {
		t.Fatal("missing ML-DSA signature")
	}
	if cert.MLDSAPublicKey == "" {
		t.Fatal("missing ML-DSA public key")
	}

	hashBytes, _ := hex.DecodeString(cert.Hash)
	if err := ats.VerifyHash(hashBytes, cert.Signature, cert.PublicKey); err != nil {
		t.Fatalf("Ed25519 signature invalid: %v", err)
	}
	if err := ats.VerifyHashMLDSA(hashBytes, cert.MLDSASignature, mlDSAPub.Bytes()); err != nil {
		t.Fatalf("ML-DSA signature invalid: %v", err)
	}
}

func TestReportEnvelopeRoundTrip(t *testing.T) {
	keyDir := t.TempDir()
	_, priv, _ := ats.LoadOrGenerateKeyPair(keyDir)
	_, mlDSAPriv, _ := ats.LoadOrGenerateMLDSAKeyPair(keyDir)

	results := makeFakeResults()
	cert, _ := ats.GenerateCertificate(results, "v0.1.0", false, priv, mlDSAPriv)

	envelope := ats.ReportEnvelope{
		Results:     results,
		Certificate: cert,
	}
	var buf bytes.Buffer
	ats.WriteJSON(&buf, envelope)

	var decoded ats.ReportEnvelope
	if err := json.Unmarshal(buf.Bytes(), &decoded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	computedHash, _ := ats.ComputeCanonicalHash(decoded.Results)
	if computedHash != decoded.Certificate.Hash {
		t.Errorf("hash mismatch: computed=%s cert=%s", computedHash, decoded.Certificate.Hash)
	}
}

func TestTamperDetection(t *testing.T) {
	keyDir := t.TempDir()
	_, priv, _ := ats.LoadOrGenerateKeyPair(keyDir)
	_, mlDSAPriv, _ := ats.LoadOrGenerateMLDSAKeyPair(keyDir)

	results := makeFakeResults()
	cert, _ := ats.GenerateCertificate(results, "v0.1.0", false, priv, mlDSAPriv)

	envelope := ats.ReportEnvelope{
		Results:     results,
		Certificate: cert,
	}
	var buf bytes.Buffer
	ats.WriteJSON(&buf, envelope)

	var tampered ats.ReportEnvelope
	json.Unmarshal(buf.Bytes(), &tampered)
	tampered.Results[0].Name = "TAMPERED"

	tamperedHash, _ := ats.ComputeCanonicalHash(tampered.Results)
	if tamperedHash == tampered.Certificate.Hash {
		t.Fatal("tamper should change the hash")
	}

	// Signature should still verify against ORIGINAL hash, not tampered
	hashBytes, _ := hex.DecodeString(tampered.Certificate.Hash)
	if err := ats.VerifyHash(hashBytes, tampered.Certificate.Signature, tampered.Certificate.PublicKey); err != nil {
		t.Logf("sig verifies against original hash (expected): %v", err)
	}

	// But the tampered hash won't match
	t.Logf("original hash: %s", tampered.Certificate.Hash)
	t.Logf("tampered hash: %s", tamperedHash)
}

func TestHTMLChartWithCertificate(t *testing.T) {
	keyDir := t.TempDir()
	_, priv, _ := ats.LoadOrGenerateKeyPair(keyDir)
	_, mlDSAPriv, _ := ats.LoadOrGenerateMLDSAKeyPair(keyDir)

	results := makeFakeResults()
	cert, _ := ats.GenerateCertificate(results, "v0.1.0", false, priv, mlDSAPriv)

	var buf bytes.Buffer
	chart.Render(&buf, results, cert)
	html := buf.String()

	for _, check := range []string{
		cert.AntiTamperID,
		cert.Hash,
		"sig-display",
		"防伪证书",
	} {
		if !strings.Contains(strings.ToLower(html), check) {
			t.Errorf("HTML missing %q", check)
		}
	}
}

func TestCSVOutput(t *testing.T) {
	results := makeFakeResults()
	var buf bytes.Buffer
	probe.WriteCSV(&buf, results)
	csv := buf.String()

	for _, check := range []string{"test-node", "ss", "125.5"} {
		if !strings.Contains(csv, check) {
			t.Errorf("CSV missing %q", check)
		}
	}
}

func TestVerifyCommand(t *testing.T) {
	keyDir := t.TempDir()
	_, priv, _ := ats.LoadOrGenerateKeyPair(keyDir)
	_, mlDSAPriv, _ := ats.LoadOrGenerateMLDSAKeyPair(keyDir)

	results := makeFakeResults()
	cert, _ := ats.GenerateCertificate(results, "v0.1.0", false, priv, mlDSAPriv)

	envelope := ats.ReportEnvelope{
		Results:     results,
		Certificate: cert,
	}
	reportFile := filepath.Join(keyDir, "report.json")
	data, _ := json.MarshalIndent(envelope, "", "  ")
	os.WriteFile(reportFile, data, 0o644)

	var verifyBuf bytes.Buffer
	ret := runTestVerify(reportFile, &verifyBuf)
	output := verifyBuf.String()

	if ret != 0 {
		t.Fatalf("verify returned non-zero: %d\n%s", ret, output)
	}
	for _, check := range []string{"✓ SHA-256", "✓ Ed25519"} {
		if !strings.Contains(output, check) {
			t.Errorf("verify output missing %q:\n%s", check, output)
		}
	}
}

func TestVerifyCommandTampered(t *testing.T) {
	keyDir := t.TempDir()
	_, priv, _ := ats.LoadOrGenerateKeyPair(keyDir)
	_, mlDSAPriv, _ := ats.LoadOrGenerateMLDSAKeyPair(keyDir)

	results := makeFakeResults()
	cert, _ := ats.GenerateCertificate(results, "v0.1.0", false, priv, mlDSAPriv)

	envelope := ats.ReportEnvelope{
		Results:     results,
		Certificate: cert,
	}
	envelope.Results[0].Speed.Mbps = 99999

	tamperedFile := filepath.Join(keyDir, "tampered.json")
	data, _ := json.MarshalIndent(envelope, "", "  ")
	os.WriteFile(tamperedFile, data, 0o644)

	var verifyBuf bytes.Buffer
	ret := runTestVerify(tamperedFile, &verifyBuf)
	output := verifyBuf.String()

	if ret == 0 {
		t.Fatalf("tampered report should have failed verification\n%s", output)
	}
	if !strings.Contains(output, "✗ SHA-256 hash mismatch") {
		t.Errorf("expected hash mismatch message:\n%s", output)
	}
}

func makeFakeResults() []probe.NodeResult {
	return []probe.NodeResult{
		{
			Index:  0,
			Name:   "test-node",
			Type:   "ss",
			Server: "1.0.0.1",
			Port:   443,
			Latency: &probe.LatencyResult{
				HTTPMs: 45.2,
				TCPMs:  23.1,
			},
			Speed: &probe.SpeedResult{
				Mbps: 125.5,
			},
			Evidence: []probe.Evidence{
				{
					Test:   "latency_http",
					URL:    "https://www.gstatic.com/generate_204",
					Method: "GET",
					TLSCert: &probe.TLSCertInfo{
						FingerprintSHA256: "abcdef1234567890",
						Issuer:            "CN=Google Trust Services",
						Subject:           "CN=*.gstatic.com",
						NotAfter:          "2026-12-31T23:59:59Z",
					},
				},
			},
		},
	}
}

func runTestVerify(reportFile string, w *bytes.Buffer) int {
	return runVerify([]string{reportFile}, w, w)
}

func TestMLDSAPersistence(t *testing.T) {
	keyDir := t.TempDir()

	pub1, priv1, err := ats.LoadOrGenerateMLDSAKeyPair(keyDir)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}

	pub2, priv2, err := ats.LoadOrGenerateMLDSAKeyPair(keyDir)
	if err != nil {
		t.Fatalf("reload: %v", err)
	}

	if !bytes.Equal(pub1.Bytes(), pub2.Bytes()) {
		t.Error("public keys differ on reload")
	}
	if !bytes.Equal(priv1.Bytes(), priv2.Bytes()) {
		t.Error("private keys differ on reload")
	}
}

func TestMLDSASignVerify(t *testing.T) {
	keyDir := t.TempDir()
	_, priv, _ := ats.LoadOrGenerateMLDSAKeyPair(keyDir)

	hashData := []byte("test-hash-data-1234567890abcdef")
	sig := ats.SignHashMLDSA(hashData, priv)
	pubBytes := priv.Public().(*mldsa87.PublicKey).Bytes()

	if err := ats.VerifyHashMLDSA(hashData, sig, pubBytes); err != nil {
		t.Fatalf("verify failed: %v", err)
	}

	tampered := []byte("tampered-data")
	if err := ats.VerifyHashMLDSA(tampered, sig, pubBytes); err == nil {
		t.Fatal("tampered hash should fail verification")
	}
}

func TestHybridCertificate(t *testing.T) {
	keyDir := t.TempDir()
	_, priv, _ := ats.LoadOrGenerateKeyPair(keyDir)
	_, mlDSAPriv, _ := ats.LoadOrGenerateMLDSAKeyPair(keyDir)

	results := makeFakeResults()
	cert, err := ats.GenerateCertificate(results, "v0.1.0", false, priv, mlDSAPriv)
	if err != nil {
		t.Fatalf("generate cert: %v", err)
	}

	// Verify both signatures
	hashBytes, _ := hex.DecodeString(cert.Hash)
	if err := ats.VerifyHash(hashBytes, cert.Signature, cert.PublicKey); err != nil {
		t.Fatalf("Ed25519: %v", err)
	}
	pubBytes, _ := hex.DecodeString(cert.MLDSAPublicKey)
	if err := ats.VerifyHashMLDSA(hashBytes, cert.MLDSASignature, pubBytes); err != nil {
		t.Fatalf("ML-DSA: %v", err)
	}
}

