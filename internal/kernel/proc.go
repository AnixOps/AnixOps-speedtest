package kernel

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// ReservePort asks the OS for a free loopback TCP port and returns "127.0.0.1:<port>".
// The port is released before returning, so a caller must start listening promptly.
func ReservePort() (string, error) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return "", fmt.Errorf("reserve local port: %w", err)
	}
	addr := ln.Addr().String()
	ln.Close()
	return addr, nil
}

// WaitForListener polls addr until a TCP connection succeeds or ctx ends.
func WaitForListener(ctx context.Context, addr string) error {
	var dialer net.Dialer
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	for {
		conn, err := dialer.DialContext(ctx, "tcp", addr)
		if err == nil {
			conn.Close()
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}
	}
}

// ExecPath makes a bare binary name resolvable by exec ("./name") so Go does not
// search PATH, while leaving absolute or already-qualified paths alone.
func ExecPath(p string) string {
	p = strings.TrimSpace(p)
	if p == "" || filepath.IsAbs(p) || strings.ContainsAny(p, `/\`) {
		return p
	}
	return "." + string(filepath.Separator) + p
}

// NewStopper returns an idempotent function that kills cmd, reaps it and removes
// cleanupDir. The kill we issue ourselves is not reported as an error.
func NewStopper(cmd *exec.Cmd, cleanupDir string) func() error {
	var once sync.Once
	var result error
	return func() error {
		once.Do(func() {
			var errs []error
			killed := false
			if cmd.Process != nil {
				if err := cmd.Process.Kill(); err == nil {
					killed = true
				} else if !errors.Is(err, os.ErrProcessDone) {
					errs = append(errs, err)
				}
			}
			if err := cmd.Wait(); err != nil && !errors.Is(err, context.Canceled) {
				var exitErr *exec.ExitError
				if !(killed && errors.As(err, &exitErr)) {
					errs = append(errs, err)
				}
			}
			if err := os.RemoveAll(cleanupDir); err != nil {
				errs = append(errs, err)
			}
			result = errors.Join(errs...)
		})
		return result
	}
}

// TailBuffer is an io.Writer that keeps only the last Max bytes written, used to
// attach a kernel's final log lines to a startup error without unbounded memory.
type TailBuffer struct {
	Max int
	mu  sync.Mutex
	buf []byte
}

func (t *TailBuffer) Write(p []byte) (int, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.buf = append(t.buf, p...)
	if t.Max > 0 && len(t.buf) > t.Max {
		t.buf = t.buf[len(t.buf)-t.Max:]
	}
	return len(p), nil
}

// Suffix formats the captured output for appending to an error ("" when empty).
func (t *TailBuffer) Suffix() string {
	t.mu.Lock()
	defer t.mu.Unlock()
	s := strings.TrimSpace(string(t.buf))
	if s == "" {
		return ""
	}
	return "\n  kernel output: " + strings.ReplaceAll(s, "\n", "\n    ")
}
