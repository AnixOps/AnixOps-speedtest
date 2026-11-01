package sub

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

const cacheTestLink = "trojan://pw@t.example.com:443?sni=t.example.com#T1"

func TestFetchWithCacheWritesAndFallsBack(t *testing.T) {
	ok := true
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !ok {
			http.Error(w, "down", http.StatusBadGateway)
			return
		}
		_, _ = w.Write([]byte(b64(cacheTestLink)))
	}))
	defer srv.Close()
	cache := filepath.Join(t.TempDir(), "sub.cache")

	res, err := FetchWithCache(context.Background(), srv.URL, "", cache)
	if err != nil || res.FromCache || len(res.Nodes) != 1 {
		t.Fatalf("first fetch: res=%+v err=%v", res, err)
	}
	st, err := os.Stat(cache)
	if err != nil || st.Mode().Perm() != 0o600 {
		t.Fatalf("cache not written 0600: %v %v", st, err)
	}

	ok = false
	res, err = FetchWithCache(context.Background(), srv.URL, "", cache)
	if err != nil || !res.FromCache || res.FetchErr == nil || len(res.Nodes) != 1 || res.Nodes[0].Name != "T1" {
		t.Fatalf("fallback: res=%+v err=%v", res, err)
	}
}

func TestFetchWithCacheKeepsCacheOnUnparsableBody(t *testing.T) {
	body := b64(cacheTestLink)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(body))
	}))
	defer srv.Close()
	cache := filepath.Join(t.TempDir(), "sub.cache")
	if _, err := FetchWithCache(context.Background(), srv.URL, "", cache); err != nil {
		t.Fatal(err)
	}
	body = "<html>maintenance</html>"
	res, err := FetchWithCache(context.Background(), srv.URL, "", cache)
	if err != nil || !res.FromCache {
		t.Fatalf("res=%+v err=%v", res, err)
	}
	got, _ := os.ReadFile(cache)
	if string(got) != b64(cacheTestLink) {
		t.Fatalf("cache overwritten with %q", got)
	}
}

func TestFetchWithCacheNoCache(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "down", http.StatusBadGateway)
	}))
	defer srv.Close()
	cache := filepath.Join(t.TempDir(), "missing.cache")
	if _, err := FetchWithCache(context.Background(), srv.URL, "", cache); err == nil {
		t.Fatal("expected an error without a cache")
	}
}
