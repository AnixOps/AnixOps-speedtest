package ats

import (
	"testing"

	"github.com/anixops/speedtest/internal/probe"
)

func sampleResults() []probe.NodeResult {
	return []probe.NodeResult{{Name: "node-a"}, {Name: "node-b"}}
}

func signedEnvelope(t *testing.T) (ReportEnvelope, string, string) {
	t.Helper()
	pub, priv, err := GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	_, pq, err := GenerateMLDSAKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	res := sampleResults()
	cert, err := GenerateCertificate(res, "test", false, priv, pq)
	if err != nil {
		t.Fatal(err)
	}
	return ReportEnvelope{Results: res, Certificate: cert}, KeyFingerprint(pub), fingerprintHex(cert.MLDSAPublicKey)
}

func find(r Result, name string) Check {
	for _, c := range r.Checks {
		if c.Name == name {
			return c
		}
	}
	return Check{Status: -1}
}

func TestVerifyHappyPath(t *testing.T) {
	env, fp, pqfp := signedEnvelope(t)
	r := Verify(env, VerifyOptions{TrustedKeyFingerprint: fp, TrustedMLDSAFingerprint: pqfp})
	if !r.OK() || !r.Signed() {
		t.Fatalf("expected verified, got %+v", r.Checks)
	}
}

func TestVerifyDetectsTamper(t *testing.T) {
	env, _, _ := signedEnvelope(t)
	env.Results[0].Name = "evil"
	if r := Verify(env, VerifyOptions{}); r.OK() {
		t.Fatal("tampered results must fail")
	}
}

func TestVerifyRejectsForeignKeyWithForgedHashClaim(t *testing.T) {
	// Attacker re-signs with their own key and copies the victim's fingerprint
	// into public_key_hash; the pinned check must still fail.
	_, victimFP, _ := signedEnvelope(t)
	env, _, _ := signedEnvelope(t)
	env.Certificate.PublicKeyHash = victimFP
	r := Verify(env, VerifyOptions{TrustedKeyFingerprint: victimFP})
	if r.OK() || find(r, "ed25519").Status != StatusFail {
		t.Fatalf("foreign key must fail: %+v", r.Checks)
	}
}

func TestVerifyPinnedKeyRequiresSignature(t *testing.T) {
	env, fp, _ := signedEnvelope(t)
	env.Certificate.Signature, env.Certificate.PublicKey, env.Certificate.PublicKeyHash = "", "", ""
	if r := Verify(env, VerifyOptions{TrustedKeyFingerprint: fp}); r.OK() {
		t.Fatal("pinned key with stripped signature must fail")
	}
}

func TestVerifyUnsignedIsIntegrityOnly(t *testing.T) {
	res := sampleResults()
	cert, _ := GenerateCertificate(res, "test", false, nil, nil)
	r := Verify(ReportEnvelope{Results: res, Certificate: cert}, VerifyOptions{})
	if !r.OK() || r.Signed() {
		t.Fatalf("unsigned report: OK=%v Signed=%v", r.OK(), r.Signed())
	}
}

func TestVerifyNoCertificate(t *testing.T) {
	if Verify(ReportEnvelope{Results: sampleResults()}, VerifyOptions{}).OK() {
		t.Fatal("missing certificate must fail")
	}
}
