package ats

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"time"

	"github.com/anixops/speedtest/internal/probe"
)

type ATSCertificate struct {
	Version      string    `json:"version"`
	ToolVersion  string    `json:"tool_version"`
	Timestamp    time.Time `json:"timestamp"`
	Hash         string    `json:"hash"`
	AntiTamperID string    `json:"anti_tamper_id"`
	OTSProof     string    `json:"ots_proof,omitempty"`
	OTSStatus    string    `json:"ots_status"`
	// Ed25519 signature (classical)
	PublicKey string `json:"public_key,omitempty"`
	Signature string `json:"signature,omitempty"`
	// ML-DSA-87 signature (post-quantum)
	MLDSAPublicKey string `json:"ml_dsa_public_key,omitempty"`
	MLDSASignature string `json:"ml_dsa_signature,omitempty"`
	// Key anchoring — public key itself anchored on-chain
	PublicKeyHash  string `json:"public_key_hash,omitempty"`
	PublicKeyOTS   string `json:"public_key_ots,omitempty"`
	PublicKeyOTSS  string `json:"public_key_ots_status,omitempty"`
}

type ReportEnvelope struct {
	Results     []probe.NodeResult `json:"results"`
	Certificate *ATSCertificate    `json:"certificate,omitempty"`
}

// ComputeCanonicalHash computes a SHA-256 hash of the results as compact JSON.
// HTML escaping is disabled so browsers can reproduce the same hash via JSON.stringify.
func ComputeCanonicalHash(results []probe.NodeResult) (string, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(results); err != nil {
		return "", err
	}
	// Remove trailing newline added by Encoder
	data := bytes.TrimSuffix(buf.Bytes(), []byte("\n"))
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:]), nil
}

func AntiTamperID(hash string) string {
	if len(hash) < 12 {
		return hash
	}
	return hash[:12]
}

// KeyFingerprint computes a SHA-256 fingerprint of the Ed25519 public key.
// This is the trust anchor for verify.html — the verifier pins this fingerprint.
func KeyFingerprint(pub ed25519.PublicKey) string {
	sum := sha256.Sum256(pub)
	return hex.EncodeToString(sum[:])
}

func WriteJSON(w io.Writer, envelope ReportEnvelope) {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.Encode(envelope)
}
