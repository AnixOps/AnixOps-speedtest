package kernel

import (
	"context"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

func TestExecPath(t *testing.T) {
	cases := map[string]string{"mihomo": "./mihomo", "/usr/bin/x": "/usr/bin/x", "bin/x": "bin/x", "  ": ""}
	for in, want := range cases {
		if got := ExecPath(in); got != want {
			t.Errorf("%q: got %q want %q", in, got, want)
		}
	}
}

func TestReserveAndWait(t *testing.T) {
	addr, err := ReservePort()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	if err := WaitForListener(ctx, addr); err == nil {
		t.Fatal("nothing listens yet; expected timeout")
	}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	ctx2, cancel2 := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel2()
	if err := WaitForListener(ctx2, addr); err != nil {
		t.Fatalf("listener is up: %v", err)
	}
}

func TestStopperKillsAndCleans(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "work")
	os.MkdirAll(dir, 0o755)
	cmd := exec.Command("sleep", "30")
	if err := cmd.Start(); err != nil {
		t.Skip("sleep unavailable")
	}
	stop := NewStopper(cmd, dir)
	if err := stop(); err != nil {
		t.Fatalf("stop: %v", err)
	}
	if err := stop(); err != nil {
		t.Fatalf("second stop must be a no-op: %v", err)
	}
	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Fatal("cleanup dir should be removed")
	}
}
