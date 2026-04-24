package ats

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"

	"github.com/cloudflare/circl/sign/mldsa/mldsa87"
)

// GenerateMLDSAKeyPair generates a new ML-DSA-87 (Dilithium) keypair.
func GenerateMLDSAKeyPair() (*mldsa87.PublicKey, *mldsa87.PrivateKey, error) {
	return mldsa87.GenerateKey(nil)
}

// LoadOrGenerateMLDSAKeyPair loads from disk or generates a new ML-DSA-87 keypair.
func LoadOrGenerateMLDSAKeyPair(keyDir string) (*mldsa87.PublicKey, *mldsa87.PrivateKey, error) {
	if err := os.MkdirAll(keyDir, 0o700); err != nil {
		return nil, nil, fmt.Errorf("create key dir: %w", err)
	}

	privPath := filepath.Join(keyDir, "ml-dsa-key.priv")
	pubPath := filepath.Join(keyDir, "ml-dsa-key.pub")

	if data, err := os.ReadFile(privPath); err == nil {
		priv := &mldsa87.PrivateKey{}
		if err := priv.UnmarshalBinary(data); err != nil {
			return nil, nil, fmt.Errorf("invalid ML-DSA private key: %w", err)
		}
		pub := priv.Public().(*mldsa87.PublicKey)
		os.WriteFile(pubPath, pub.Bytes(), 0o644)
		return pub, priv, nil
	}

	pub, priv, err := GenerateMLDSAKeyPair()
	if err != nil {
		return nil, nil, fmt.Errorf("generate ML-DSA keypair: %w", err)
	}

	if err := os.WriteFile(privPath, priv.Bytes(), 0o600); err != nil {
		return nil, nil, fmt.Errorf("save private key: %w", err)
	}
	if err := os.WriteFile(pubPath, pub.Bytes(), 0o644); err != nil {
		return nil, nil, fmt.Errorf("save public key: %w", err)
	}

	return pub, priv, nil
}

// SignHashMLDSA signs a SHA-256 hash with ML-DSA-87. Returns hex-encoded signature.
func SignHashMLDSA(hash []byte, priv *mldsa87.PrivateKey) string {
	sig, _ := priv.Sign(nil, hash, nil)
	return hex.EncodeToString(sig)
}

// VerifyHashMLDSA verifies an ML-DSA-87 signature.
func VerifyHashMLDSA(hash []byte, sigHex string, pubBytes []byte) error {
	sig, err := hex.DecodeString(sigHex)
	if err != nil {
		return fmt.Errorf("decode signature: %w", err)
	}
	pub := &mldsa87.PublicKey{}
	if err := pub.UnmarshalBinary(pubBytes); err != nil {
		return fmt.Errorf("invalid ML-DSA public key: %w", err)
	}
	if !mldsa87.Verify(pub, hash, nil, sig) {
		return fmt.Errorf("ML-DSA signature verification failed")
	}
	return nil
}

// MLDSAPublicKeyHex returns hex representation of ML-DSA public key bytes.
func MLDSAPublicKeyHex(pub *mldsa87.PublicKey) string {
	return hex.EncodeToString(pub.Bytes())
}

// MLDSAHash computes a SHA-256 hash of the public key for compact display.
func MLDSAHash(pub *mldsa87.PublicKey) string {
	sum := sha256.Sum256(pub.Bytes())
	return hex.EncodeToString(sum[:])[:16]
}
