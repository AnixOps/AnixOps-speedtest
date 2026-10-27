package kernel

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func sum(b []byte) string { h := sha256.Sum256(b); return hex.EncodeToString(h[:]) }

func TestExpectedSHA256FromDigest(t *testing.T) {
	good := strings.Repeat("ab", 32)
	got, err := ExpectedSHA256(&Release{}, Asset{Name: "x", Digest: "sha256:" + strings.ToUpper(good)}, http.DefaultClient)
	if err != nil || got != good {
		t.Fatalf("got %q, %v", got, err)
	}
}

func TestExpectedSHA256FromDgst(t *testing.T) {
	want := strings.Repeat("cd", 32)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("MD5= " + strings.Repeat("11", 16) + "\nSHA1= " + strings.Repeat("22", 20) + "\nSHA2-256= " + want + "\n"))
	}))
	defer srv.Close()
	rel := &Release{Assets: []Asset{{Name: "a.zip.dgst", URL: srv.URL}}}
	got, err := ExpectedSHA256(rel, Asset{Name: "a.zip"}, srv.Client())
	if err != nil || got != want {
		t.Fatalf("got %q, %v", got, err)
	}
}

func TestExpectedSHA256Missing(t *testing.T) {
	if _, err := ExpectedSHA256(&Release{}, Asset{Name: "a.zip"}, http.DefaultClient); err == nil {
		t.Fatal("expected error")
	}
}

func TestDownloadVerifies(t *testing.T) {
	payload := []byte("kernel-bytes")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write(payload) }))
	defer srv.Close()
	dest := filepath.Join(t.TempDir(), "bin")

	p, err := Download(context.Background(), &Release{}, Asset{Name: "k", URL: srv.URL, Digest: "sha256:" + sum(payload)}, dest, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(p); !bytes.Equal(b, payload) {
		t.Fatal("payload mismatch")
	}

	_, err = Download(context.Background(), &Release{}, Asset{Name: "k", URL: srv.URL, Digest: "sha256:" + strings.Repeat("00", 32)}, dest, 5*time.Second)
	if err == nil || !strings.Contains(err.Error(), "checksum mismatch") {
		t.Fatalf("expected checksum mismatch, got %v", err)
	}
	if _, statErr := os.Stat(dest + ".download"); statErr == nil {
		t.Fatal("tampered download must be removed")
	}
}

func TestDownloadRequiresDigest(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("x")) }))
	defer srv.Close()
	dest := filepath.Join(t.TempDir(), "bin")
	t.Setenv(AllowUnverifiedEnv, "")
	if _, err := Download(context.Background(), &Release{}, Asset{Name: "k", URL: srv.URL}, dest, time.Second); err == nil {
		t.Fatal("expected refusal without digest")
	}
	t.Setenv(AllowUnverifiedEnv, "1")
	if _, err := Download(context.Background(), &Release{}, Asset{Name: "k", URL: srv.URL}, dest, time.Second); err != nil {
		t.Fatalf("override should allow: %v", err)
	}
}

func TestExtractZip(t *testing.T) {
	dir := t.TempDir()
	zp := filepath.Join(dir, "a.zip")
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	w, _ := zw.Create("sub/xray")
	w.Write([]byte("BIN"))
	zw.Close()
	os.WriteFile(zp, buf.Bytes(), 0o644)

	out := filepath.Join(dir, "out")
	if err := ExtractZip(zp, out, func(n string) bool { return n == "xray" }); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(out); string(b) != "BIN" {
		t.Fatalf("got %q", b)
	}
	if err := ExtractZip(zp, out, func(string) bool { return false }); err == nil {
		t.Fatal("expected not-found error")
	}
}
