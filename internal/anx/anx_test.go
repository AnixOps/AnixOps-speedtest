package anx

import (
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestMain doubles as a fake anx-proxy: re-executed with FAKE_ANX_PROXY=1 it
// checks the link file and listens where told, like the real binary.
func TestMain(m *testing.M) {
	if os.Getenv("FAKE_ANX_PROXY") == "1" {
		os.Exit(fakeProxy(os.Args[1:]))
	}
	os.Exit(m.Run())
}

func fakeProxy(args []string) int {
	var link, listen string
	for i := 0; i+1 < len(args); i += 2 {
		switch args[i] {
		case "--link":
			link = args[i+1]
		case "--listen":
			listen = args[i+1]
		}
	}
	data, err := os.ReadFile(link)
	if err != nil || !strings.HasPrefix(string(data), "anx://") {
		fmt.Fprintln(os.Stderr, "anx-proxy: the link cannot run")
		return 1
	}
	if info, _ := os.Stat(link); info.Mode().Perm() != 0o600 {
		fmt.Fprintln(os.Stderr, "link file not 0600")
		return 1
	}
	ln, err := net.Listen("tcp", listen)
	if err != nil {
		return 1
	}
	fmt.Println("listening", ln.Addr(), "mixed")
	for {
		c, err := ln.Accept()
		if err != nil {
			return 0
		}
		c.Close()
	}
}

func fakeBinary(t *testing.T) string {
	t.Helper()
	t.Setenv("FAKE_ANX_PROXY", "1")
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	return exe
}

func TestStartServesLink(t *testing.T) {
	bin := fakeBinary(t)
	url, stop, err := Start(context.Background(), bin, "anx://k@h:443?pk=x#n", t.TempDir(), 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(url, "socks5://127.0.0.1:") {
		t.Fatalf("url %q", url)
	}
	if err := stop(); err != nil {
		t.Fatalf("stop: %v", err)
	}
}

func TestStartReportsKernelOutput(t *testing.T) {
	bin := fakeBinary(t)
	_, _, err := Start(context.Background(), bin, "vless://bad", t.TempDir(), 5*time.Second)
	if err == nil || !strings.Contains(err.Error(), "the link cannot run") {
		t.Fatalf("want kernel output in error, got %v", err)
	}
}

func TestStartNeedsLink(t *testing.T) {
	if _, _, err := Start(context.Background(), "anx-proxy", " ", "", time.Second); err == nil {
		t.Fatal("empty link accepted")
	}
}

func TestResolveBinary(t *testing.T) {
	dir := t.TempDir()
	t.Setenv(EnvBinary, "")
	if _, err := ResolveBinary(filepath.Join(dir, "missing"), dir); err == nil {
		t.Fatal("missing explicit path accepted")
	}
	inBinDir := filepath.Join(dir, binaryName())
	if err := os.WriteFile(inBinDir, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	if got, err := ResolveBinary("", dir); err != nil || got != inBinDir {
		t.Fatalf("bin dir: %q %v", got, err)
	}
	t.Setenv(EnvBinary, inBinDir)
	if got, err := ResolveBinary("", ""); err != nil || got != inBinDir {
		t.Fatalf("env: %q %v", got, err)
	}
}
