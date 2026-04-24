package ats

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/anixops/speedtest/internal/probe"
	"github.com/cloudflare/circl/sign/mldsa/mldsa87"
)

var otsServers = []string{
	"https://a.pool.opentimestamps.org/timestamp",
	"https://b.pool.opentimestamps.org/timestamp",
	"https://alice.btc.calendar.opentimestamps.org/timestamp",
	"http://calendar.opentimestamps.org:8080/timestamp",
	"http://finney.calendar.eternitywall.com:8080/timestamp",
}

func GenerateCertificate(results []probe.NodeResult, toolVersion string, enableOTS bool, privKey ed25519.PrivateKey, mlDSAPriv *mldsa87.PrivateKey) (*ATSCertificate, error) {
	hash, err := ComputeCanonicalHash(results)
	if err != nil {
		return nil, fmt.Errorf("compute hash: %w", err)
	}

	hashBytes, err := hex.DecodeString(hash)
	if err != nil {
		return nil, fmt.Errorf("decode hash: %w", err)
	}

	cert := &ATSCertificate{
		Version:      "v1",
		ToolVersion:  toolVersion,
		Timestamp:    time.Now().UTC(),
		Hash:         hash,
		AntiTamperID: AntiTamperID(hash),
		OTSStatus:    "disabled",
	}

	// Ed25519 signature (classical)
	if privKey != nil {
		pub := privKey.Public().(ed25519.PublicKey)
		cert.PublicKey = hex.EncodeToString(pub)
		cert.Signature = SignHash(hashBytes, privKey)
		// Key anchoring: SHA-256 of the public key itself
		cert.PublicKeyHash = KeyFingerprint(pub)
	}

	// ML-DSA-87 signature (post-quantum)
	if mlDSAPriv != nil {
		cert.MLDSAPublicKey = MLDSAPublicKeyHex(mlDSAPriv.Public().(*mldsa87.PublicKey))
		cert.MLDSASignature = SignHashMLDSA(hashBytes, mlDSAPriv)
	}

	if !enableOTS {
		return cert, nil
	}

	// Submit report hash to OTS (anchoring data integrity to blockchain)
	proof, err := submitToOTS(hashBytes)
	if err != nil {
		cert.OTSStatus = "pending"
	} else {
		cert.OTSProof = proof
		cert.OTSStatus = "confirmed"
	}

	// Submit public key hash to OTS independently (anchoring the key itself)
	// This is done separately so the key is anchored regardless of report OTS status
	if cert.PublicKeyHash != "" {
		keyHashBytes, _ := hex.DecodeString(cert.PublicKeyHash)
		keyProof, err := submitToOTS(keyHashBytes)
		if err != nil {
			cert.PublicKeyOTSS = "pending"
		} else {
			cert.PublicKeyOTS = keyProof
			cert.PublicKeyOTSS = "confirmed"
		}
	}

	return cert, nil
}

func submitToOTS(hashBytes []byte) (string, error) {
	for _, server := range otsServers {
		proof, err := tryOTS(server, hashBytes)
		if err == nil {
			return proof, nil
		}
	}
	return "", fmt.Errorf("all OTS servers failed")
}

func tryOTS(url string, hashBytes []byte) (string, error) {
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Post(url, "application/x-opentimestamps", bytes.NewReader(hashBytes))
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("OTS server returned %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	return base64.StdEncoding.EncodeToString(body), nil
}
