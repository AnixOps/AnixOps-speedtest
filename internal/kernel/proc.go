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

// Proc supervises a started kernel process: it reaps the process in the
// background so startup can notice an early exit, and offers an idempotent Stop.
type Proc struct {
	cmd      *exec.Cmd
	cleanup  string
	exited   chan struct{}
	waitErr  error
	killed   bool
	killMu   sync.Mutex
	stopOnce sync.Once
	stopErr  error
}

// Supervise starts reaping cmd (which must already be started). cleanupDir is
// removed by Stop.
func Supervise(cmd *exec.Cmd, cleanupDir string) *Proc {
	p := &Proc{cmd: cmd, cleanup: cleanupDir, exited: make(chan struct{})}
	go func() {
		p.waitErr = cmd.Wait()
		close(p.exited)
	}()
	return p
}

// WaitReady blocks until addr accepts connections. It returns early with an error
// if the process exits first or ctx ends.
func (p *Proc) WaitReady(ctx context.Context, addr string) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	go func() {
		select {
		case <-p.exited:
			cancel()
		case <-ctx.Done():
		}
	}()
	err := WaitForListener(ctx, addr)
	if err != nil {
		select {
		case <-p.exited:
			return fmt.Errorf("kernel exited before listening: %v", p.waitErr)
		default:
		}
	}
	return err
}

// Stop kills the process, waits for it and removes the cleanup dir. Idempotent.
// A kill we issued ourselves is not reported as an error.
func (p *Proc) Stop() error {
	p.stopOnce.Do(func() {
		var errs []error
		if p.cmd.Process != nil {
			if err := p.cmd.Process.Kill(); err == nil {
				p.killMu.Lock()
				p.killed = true
				p.killMu.Unlock()
			} else if !errors.Is(err, os.ErrProcessDone) {
				errs = append(errs, err)
			}
		}
		<-p.exited
		p.killMu.Lock()
		killed := p.killed
		p.killMu.Unlock()
		if err := p.waitErr; err != nil && !errors.Is(err, context.Canceled) {
			var exitErr *exec.ExitError
			if !killed || !errors.As(err, &exitErr) {
				errs = append(errs, err)
			}
		}
		if err := os.RemoveAll(p.cleanup); err != nil {
			errs = append(errs, err)
		}
		p.stopErr = errors.Join(errs...)
	})
	return p.stopErr
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
