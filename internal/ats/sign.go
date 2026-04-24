package ats

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
)

// GenerateKeyPair creates a new Ed25519 keypair.
func GenerateKeyPair() (ed25519.PublicKey, ed25519.PrivateKey, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("generate ed25519 keypair: %w", err)
	}
	return pub, priv, nil
}

// LoadOrGenerateKeyPair loads an Ed25519 private key from PEM file, or generates and saves one.
func LoadOrGenerateKeyPair(keyDir string) (ed25519.PublicKey, ed25519.PrivateKey, error) {
	if err := os.MkdirAll(keyDir, 0o700); err != nil {
		return nil, nil, fmt.Errorf("create key dir: %w", err)
	}

	privPath := filepath.Join(keyDir, "signing-key.pem")
	pubPath := filepath.Join(keyDir, "signing-key.pub")

	// Try to load existing private key
	if data, err := os.ReadFile(privPath); err == nil {
		block, _ := pem.Decode(data)
		if block == nil {
			return nil, nil, fmt.Errorf("invalid PEM in private key file")
		}
		key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, nil, fmt.Errorf("parse private key: %w", err)
		}
		priv := key.(ed25519.PrivateKey)
		pub := priv.Public().(ed25519.PublicKey)
		// Ensure public key file exists too
		os.WriteFile(pubPath, []byte(hex.EncodeToString(pub)), 0o644)
		return pub, priv, nil
	}

	// Generate new keypair
	pub, priv, err := GenerateKeyPair()
	if err != nil {
		return nil, nil, err
	}

	// Save private key
	privBytes, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return nil, nil, fmt.Errorf("marshal private key: %w", err)
	}
	privPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privBytes})
	if err := os.WriteFile(privPath, privPEM, 0o600); err != nil {
		return nil, nil, fmt.Errorf("save private key: %w", err)
	}

	// Save public key
	if err := os.WriteFile(pubPath, []byte(hex.EncodeToString(pub)), 0o644); err != nil {
		return nil, nil, fmt.Errorf("save public key: %w", err)
	}

	return pub, priv, nil
}

// SignHash signs a SHA-256 hash with the private key. Returns hex-encoded signature.
func SignHash(hash []byte, priv ed25519.PrivateKey) string {
	sig := ed25519.Sign(priv, hash)
	return hex.EncodeToString(sig)
}

// VerifyHash verifies an Ed25519 signature. hash is the original data, sig and pub are hex-encoded.
func VerifyHash(hash []byte, sigHex string, pubHex string) error {
	pub, err := hex.DecodeString(pubHex)
	if err != nil {
		return fmt.Errorf("decode public key: %w", err)
	}
	sig, err := hex.DecodeString(sigHex)
	if err != nil {
		return fmt.Errorf("decode signature: %w", err)
	}
	if !ed25519.Verify(pub, hash, sig) {
		return fmt.Errorf("signature verification failed")
	}
	return nil
}
