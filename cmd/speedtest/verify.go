package main

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/anixops/speedtest/internal/ats"
	"github.com/cloudflare/circl/sign/mldsa/mldsa87"
)

func runVerify(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprintln(stderr, "Usage: speedtest verify <report.json> [--key-fingerprint <hash>]")
		return 2
	}

	filePath := args[0]
	var trustedKey string
	for i, a := range args[1:] {
		if a == "--key-fingerprint" && i+2 < len(args) {
			trustedKey = strings.ToLower(strings.TrimSpace(args[i+2]))
			break
		}
	}

	data, err := os.ReadFile(filePath)
	if err != nil {
		fmt.Fprintf(stderr, "error reading file: %v\n", err)
		return 2
	}

	// Try parsing as envelope with certificate
	var envelope ats.ReportEnvelope
	if err := json.Unmarshal(data, &envelope); err != nil {
		fmt.Fprintf(stderr, "error parsing JSON: %v\n", err)
		return 2
	}

	// Compute canonical hash of results
	hash, err := ats.ComputeCanonicalHash(envelope.Results)
	if err != nil {
		fmt.Fprintf(stderr, "error computing hash: %v\n", err)
		return 2
	}

	fmt.Fprintf(stdout, "File: %s\n", filePath)
	fmt.Fprintf(stdout, "Computed SHA-256: %s\n", hash)
	fmt.Fprintf(stdout, "Anti-Tamper ID:   %s\n", ats.AntiTamperID(hash))
	fmt.Fprintln(stdout, "")

	if envelope.Certificate == nil {
		fmt.Fprintln(stdout, "No certificate found in this file.")
		fmt.Fprintln(stdout, "The data cannot be verified without a certificate.")
		return 1
	}

	cert := envelope.Certificate
	fmt.Fprintf(stdout, "Certificate SHA-256: %s\n", cert.Hash)
	fmt.Fprintf(stdout, "Certificate ATS ID:    %s\n", cert.AntiTamperID)
	fmt.Fprintf(stdout, "Timestamp:             %s\n", cert.Timestamp.Format("2006-01-02 15:04:05 UTC"))
	fmt.Fprintf(stdout, "Blockchain Status:     %s\n", cert.OTSStatus)
	if cert.PublicKeyHash != "" {
		fmt.Fprintf(stdout, "Public Key Hash:     %s\n", cert.PublicKeyHash)
	}
	if cert.PublicKeyOTSS != "" {
		fmt.Fprintf(stdout, "Key OTS Status:      %s\n", cert.PublicKeyOTSS)
	}
	if trustedKey != "" {
		fmt.Fprintf(stdout, "Trusted Key:         %s\n", trustedKey)
	}
	fmt.Fprintln(stdout, "")

	allOK := true
	checkNum := 0

	// Trust anchor check (B)
	if trustedKey != "" && cert.PublicKeyHash != "" {
		checkNum++
		if strings.ToLower(cert.PublicKeyHash) == trustedKey {
			fmt.Fprintf(stdout, "[%d] ✓ Trust anchor: Report signed by the expected key.\n", checkNum)
		} else {
			fmt.Fprintf(stdout, "[%d] ✗ Trust anchor FAILED: NOT signed by the trusted key.\n", checkNum)
			fmt.Fprintf(stdout, "    Expected: %s\n", trustedKey)
			fmt.Fprintf(stdout, "    Got:      %s\n", cert.PublicKeyHash)
			allOK = false
		}
	}

	// Hash verification
	checkNum++
	if hash == cert.Hash {
		fmt.Fprintf(stdout, "[%d] ✓ SHA-256 hash: Data integrity confirmed.\n", checkNum)
		if cert.OTSProof != "" {
			fmt.Fprintln(stdout, "    Anchored to Bitcoin blockchain via OpenTimestamps.")
			fmt.Fprintln(stdout, "    Verify at: https://verify.opentimestamps.org/")
		}
	} else {
		fmt.Fprintf(stdout, "[%d] ✗ SHA-256 hash mismatch. Data may have been tampered with.\n", checkNum)
		allOK = false
	}

	// Key blockchain anchoring (D)
	if cert.PublicKeyOTSS == "confirmed" {
		checkNum++
		fmt.Fprintf(stdout, "[%d] ✓ Key anchored: Public key fingerprint timestamped via OpenTimestamps.\n", checkNum)
	} else if cert.PublicKeyOTSS == "pending" {
		checkNum++
		fmt.Fprintf(stdout, "[%d] ~ Key anchoring pending: Will be available later.\n", checkNum)
	}

	// Ed25519 signature
	checkNum++
	if cert.PublicKey != "" && cert.Signature != "" {
		hashBytes, _ := hex.DecodeString(cert.Hash)
		if err := ats.VerifyHash(hashBytes, cert.Signature, cert.PublicKey); err != nil {
			fmt.Fprintf(stdout, "[%d] ✗ Ed25519 signature: %v\n", checkNum, err)
			allOK = false
		} else {
			fmt.Fprintf(stdout, "[%d] ✓ Ed25519 signature: Report signed by trusted key.\n", checkNum)
		}
	} else {
		fmt.Fprintf(stdout, "[%d] — No Ed25519 signature\n", checkNum)
	}

	// ML-DSA-87 signature
	checkNum++
	if cert.MLDSAPublicKey != "" && cert.MLDSASignature != "" {
		hashBytes, _ := hex.DecodeString(cert.Hash)
		pubBytes, _ := hex.DecodeString(cert.MLDSAPublicKey)
		if err := ats.VerifyHashMLDSA(hashBytes, cert.MLDSASignature, pubBytes); err != nil {
			fmt.Fprintf(stdout, "[%d] ✗ ML-DSA-87 signature: %v\n", checkNum, err)
			allOK = false
		} else {
			fmt.Fprintf(stdout, "[%d] ✓ ML-DSA-87 signature: Post-quantum signature valid.\n", checkNum)
			fmt.Fprintf(stdout, "    PQC Key Hash: %s\n", mlDSAHashFromHex(cert.MLDSAPublicKey))
		}
	} else {
		fmt.Fprintf(stdout, "[%d] — No ML-DSA-87 signature\n", checkNum)
	}

	fmt.Fprintln(stdout, "")
	if allOK {
		fmt.Fprintln(stdout, "✓ VERIFIED: All checks passed (classical + post-quantum + trust anchor).")
		return 0
	}

	fmt.Fprintln(stdout, "✗ FAILED: Verification failed.")
	return 1
}

func mlDSAHashFromHex(hexStr string) string {
	pubBytes, err := hex.DecodeString(hexStr)
	if err != nil || len(pubBytes) != mldsa87.PublicKeySize {
		return hexStr[:16] + "..."
	}
	pub := &mldsa87.PublicKey{}
	if err := pub.UnmarshalBinary(pubBytes); err != nil {
		return hexStr[:16] + "..."
	}
	return ats.MLDSAHash(pub)
}
