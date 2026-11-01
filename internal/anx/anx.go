// Package anx runs nodes through an external anx-proxy process: a local
// SOCKS5/HTTP proxy built on the AnixOps Net client engine, whose outbound is
// imported from a share link (anx://, vless://, trojan://, ...).
//
// anx-proxy is not distributed with this tool and is never downloaded: point
// -anx-bin (or SPEEDTEST_ANX_BIN) at a binary you built, or place anx-proxy in
// the bin directory, next to speedtest, or on PATH.
package anx

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/anixops/speedtest/internal/kernel"
)

// EnvBinary names the environment variable that points at anx-proxy.
const EnvBinary = "SPEEDTEST_ANX_BIN"

func binaryName() string {
	if runtime.GOOS == "windows" {
		return "anx-proxy.exe"
	}
	return "anx-proxy"
}

// ResolveBinary returns the anx-proxy to run: explicit (a flag), then
// $SPEEDTEST_ANX_BIN, then <binDir>/anx-proxy, the executable's directory, PATH.
func ResolveBinary(explicit, binDir string) (string, error) {
	for _, p := range []string{explicit, os.Getenv(EnvBinary)} {
		if p = strings.TrimSpace(p); p == "" {
			continue
		}
		if !isFile(p) {
			return "", fmt.Errorf("anx-proxy not found at %s", p)
		}
		return p, nil
	}
	var dirs []string
	if binDir != "" {
		dirs = append(dirs, binDir)
	}
	if exe, err := os.Executable(); err == nil {
		dirs = append(dirs, filepath.Dir(exe))
	}
	for _, dir := range dirs {
		if full := filepath.Join(dir, binaryName()); isFile(full) {
			return full, nil
		}
	}
	if path, err := exec.LookPath(binaryName()); err == nil {
		return path, nil
	}
	return "", errors.New("anx-proxy not found: pass -anx-bin or set " + EnvBinary)
}

func isFile(p string) bool {
	info, err := os.Stat(p)
	return err == nil && !info.IsDir()
}

// Start launches anx-proxy for one share link and returns its local SOCKS5 URL
// and a stop function. The link (it carries the node's key) is written to a
// 0600 file in a private temp dir, never put on the command line.
func Start(ctx context.Context, binaryPath, link, workDir string, startupTimeout time.Duration) (string, func() error, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	binaryPath = strings.TrimSpace(binaryPath)
	link = strings.TrimSpace(link)
	switch {
	case binaryPath == "":
		return "", nil, errors.New("anx-proxy binary path is required")
	case link == "":
		return "", nil, errors.New("anx kernel needs the node's share link (use a share-link subscription, not a Clash YAML)")
	case startupTimeout <= 0:
		return "", nil, fmt.Errorf("startup timeout must be > 0, got %s", startupTimeout)
	}

	addr, err := kernel.ReservePort()
	if err != nil {
		return "", nil, err
	}
	if workDir != "" {
		if err := os.MkdirAll(workDir, 0o755); err != nil {
			return "", nil, fmt.Errorf("failed to prepare workDir: %w", err)
		}
	}
	tmpDir, err := os.MkdirTemp(workDir, "speedtest-anx-")
	if err != nil {
		return "", nil, fmt.Errorf("failed to create temp dir: %w", err)
	}
	linkPath := filepath.Join(tmpDir, "link.txt")
	if err := os.WriteFile(linkPath, []byte(link+"\n"), 0o600); err != nil {
		os.RemoveAll(tmpDir)
		return "", nil, fmt.Errorf("failed to write link: %w", err)
	}

	cmd := exec.CommandContext(ctx, kernel.ExecPath(binaryPath), Args(linkPath, addr)...)
	tail := &kernel.TailBuffer{Max: 2048}
	cmd.Stdout, cmd.Stderr = tail, tail
	if err := cmd.Start(); err != nil {
		os.RemoveAll(tmpDir)
		return "", nil, fmt.Errorf("failed to start anx-proxy: %w", err)
	}
	proc := kernel.Supervise(cmd, tmpDir)
	waitCtx, cancel := context.WithTimeout(ctx, startupTimeout)
	defer cancel()
	if err := proc.WaitReady(waitCtx, addr); err != nil {
		_ = proc.Stop()
		return "", nil, fmt.Errorf("waiting for anx-proxy listener: %w%s", err, tail.Suffix())
	}
	return "socks5://" + addr, proc.Stop, nil
}

// Args is the anx-proxy command line for a link file and a listen address.
func Args(linkPath, listen string) []string {
	return []string{"--link", linkPath, "--listen", listen}
}
