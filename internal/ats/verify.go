package ats

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
)

// Status is the outcome of a single verification check.
type Status int

const (
	StatusPass Status = iota
	StatusFail
	StatusSkip // check not applicable (e.g. signature absent)
)

// Check is one line of a verification report.
type Check struct {
	Name   string
	Status Status
	Detail string
}

// VerifyOptions carries the caller's trust anchors.
type VerifyOptions struct {
	// TrustedKeyFingerprint pins the Ed25519 signer (SHA-256 of the raw public key, hex).
	TrustedKeyFingerprint string
	// TrustedMLDSAFingerprint pins the ML-DSA-87 signer (SHA-256 of the raw public key, hex).
	TrustedMLDSAFingerprint string
}

// Result aggregates the checks of one verification run.
type Result struct {
	ComputedHash string
	Checks       []Check
}

// OK reports whether nothing failed and the report is authentic: either at
// least one signature verified, or only the bare hash exists (see Signed).
func (r Result) OK() bool {
	for _, c := range r.Checks {
		if c.Status == StatusFail {
			return false
		}
	}
	return true
}

// Signed reports whether at least one signature check passed.
func (r Result) Signed() bool {
	for _, c := range r.Checks {
		if c.Status == StatusPass && (c.Name == "ed25519" || c.Name == "ml-dsa-87") {
			return true
		}
	}
	return false
}

// Verify checks a report envelope. A pinned key makes the matching signature
// mandatory: a report that omits the signature, or carries a different key,
// fails instead of being silently skipped. Fingerprints are always recomputed
// from the embedded public key, never read from the certificate's own claims.
func Verify(env ReportEnvelope, opts VerifyOptions) Result {
	var res Result
	add := func(name string, st Status, format string, a ...any) {
		res.Checks = append(res.Checks, Check{Name: name, Status: st, Detail: fmt.Sprintf(format, a...)})
	}

	hash, err := ComputeCanonicalHash(env.Results)
	if err != nil {
		add("hash", StatusFail, "cannot compute hash: %v", err)
		return res
	}
	res.ComputedHash = hash

	cert := env.Certificate
	if cert == nil {
		add("certificate", StatusFail, "no certificate found; data cannot be verified")
		return res
	}

	if hash == cert.Hash {
		add("hash", StatusPass, "SHA-256 matches; data integrity confirmed")
	} else {
		add("hash", StatusFail, "SHA-256 mismatch; data may have been tampered with")
	}
	hashBytes, err := hex.DecodeString(cert.Hash)
	if err != nil {
		add("hash", StatusFail, "certificate hash is not valid hex")
		return res
	}

	// Ed25519
	trustedEd := normFP(opts.TrustedKeyFingerprint)
	switch {
	case cert.PublicKey != "" && cert.Signature != "":
		if err := VerifyHash(hashBytes, cert.Signature, cert.PublicKey); err != nil {
			add("ed25519", StatusFail, "%v", err)
			break
		}
		fp := fingerprintHex(cert.PublicKey)
		switch {
		case trustedEd == "":
			add("ed25519", StatusPass, "signature valid (signer key %s, not pinned)", fp)
		case fp == trustedEd:
			add("ed25519", StatusPass, "signature valid and signer matches the pinned key")
		default:
			add("ed25519", StatusFail, "signed by an untrusted key: got %s, want %s", fp, trustedEd)
		}
		if cert.PublicKeyHash != "" && !strings.EqualFold(cert.PublicKeyHash, fp) {
			add("key-hash", StatusFail, "certificate public_key_hash does not match its public key")
		}
	case trustedEd != "":
		add("ed25519", StatusFail, "a key is pinned but the report carries no Ed25519 signature")
	default:
		add("ed25519", StatusSkip, "no Ed25519 signature")
	}

	// ML-DSA-87
	trustedPQ := normFP(opts.TrustedMLDSAFingerprint)
	switch {
	case cert.MLDSAPublicKey != "" && cert.MLDSASignature != "":
		pubBytes, err := hex.DecodeString(cert.MLDSAPublicKey)
		if err != nil {
			add("ml-dsa-87", StatusFail, "public key is not valid hex")
			break
		}
		if err := VerifyHashMLDSA(hashBytes, cert.MLDSASignature, pubBytes); err != nil {
			add("ml-dsa-87", StatusFail, "%v", err)
			break
		}
		sum := sha256.Sum256(pubBytes)
		fp := hex.EncodeToString(sum[:])
		switch {
		case trustedPQ == "":
			add("ml-dsa-87", StatusPass, "post-quantum signature valid (signer key %s, not pinned)", fp[:16])
		case fp == trustedPQ:
			add("ml-dsa-87", StatusPass, "post-quantum signature valid and signer matches the pinned key")
		default:
			add("ml-dsa-87", StatusFail, "signed by an untrusted ML-DSA key: got %s, want %s", fp, trustedPQ)
		}
	case trustedPQ != "":
		add("ml-dsa-87", StatusFail, "an ML-DSA key is pinned but the report carries no ML-DSA signature")
	default:
		add("ml-dsa-87", StatusSkip, "no ML-DSA-87 signature")
	}

	// Informational OTS state
	switch cert.OTSStatus {
	case "confirmed":
		add("ots", StatusPass, "report hash submitted to OpenTimestamps; verify at https://verify.opentimestamps.org/")
	case "pending":
		add("ots", StatusSkip, "OpenTimestamps submission pending")
	}
	return res
}

func normFP(s string) string { return strings.ToLower(strings.TrimSpace(s)) }

func fingerprintHex(pubHex string) string {
	b, err := hex.DecodeString(pubHex)
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}
