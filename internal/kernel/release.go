// Package kernel holds the download, verification and extraction logic shared
// by the mihomo and xray kernel launchers.
package kernel

import (
	"archive/zip"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"time"
)

// AllowUnverifiedEnv disables checksum enforcement when set to "1".
// It exists as an escape hatch for mirrors that strip release digests.
const AllowUnverifiedEnv = "SPEEDTEST_ALLOW_UNVERIFIED_KERNEL"

// maxDownloadBytes bounds a kernel archive download (real archives are ~20 MB).
const maxDownloadBytes = 256 << 20

// Asset is one downloadable file of a GitHub release.
type Asset struct {
	Name   string `json:"name"`
	URL    string `json:"browser_download_url"`
	Digest string `json:"digest"` // "sha256:<hex>" as reported by the GitHub API
}

// Release is the subset of the GitHub release payload we use.
type Release struct {
	Tag    string  `json:"tag_name"`
	Assets []Asset `json:"assets"`
}

// FetchRelease queries the GitHub API for a release ("latest" or a tag).
func FetchRelease(repo, version string) (*Release, error) {
	url := fmt.Sprintf("https://api.github.com/repos/%s/releases/%s", repo, releasePath(version))
	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		return nil, fmt.Errorf("fetch github release info: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("fetch github release info: status %s", resp.Status)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return nil, err
	}
	var rel Release
	if err := json.Unmarshal(body, &rel); err != nil {
		return nil, fmt.Errorf("parse release info: %w", err)
	}
	return &rel, nil
}

func releasePath(version string) string {
	if version == "" || version == "latest" {
		return "latest"
	}
	return "tags/" + version
}

var hexSHA256 = regexp.MustCompile(`(?i)\b[0-9a-f]{64}\b`)

// ExpectedSHA256 returns the lowercase hex SHA-256 the asset must match.
// It prefers the digest from the GitHub API and falls back to a "<asset>.dgst"
// sidecar file (the format Xray-core publishes).
func ExpectedSHA256(rel *Release, asset Asset, client *http.Client) (string, error) {
	if h, ok := strings.CutPrefix(strings.ToLower(asset.Digest), "sha256:"); ok && len(h) == 64 {
		return h, nil
	}
	for _, a := range rel.Assets {
		if a.Name != asset.Name+".dgst" {
			continue
		}
		resp, err := client.Get(a.URL)
		if err != nil {
			return "", err
		}
		defer resp.Body.Close()
		body, err := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
		if err != nil {
			return "", err
		}
		// A .dgst file lists several hashes; the SHA-256 line is tagged "256".
		for _, line := range strings.Split(string(body), "\n") {
			if strings.Contains(line, "256") {
				if m := hexSHA256.FindString(line); m != "" {
					return strings.ToLower(m), nil
				}
			}
		}
	}
	return "", fmt.Errorf("no sha256 digest published for %s", asset.Name)
}

// Download fetches asset into destPath+".download", verifying its SHA-256.
// The returned path is the verified archive.
func Download(ctx context.Context, rel *Release, asset Asset, destPath string, timeout time.Duration) (string, error) {
	client := &http.Client{Timeout: timeout}

	want, err := ExpectedSHA256(rel, asset, client)
	if err != nil {
		if os.Getenv(AllowUnverifiedEnv) != "1" {
			return "", fmt.Errorf("%w (set %s=1 to skip verification)", err, AllowUnverifiedEnv)
		}
		fmt.Fprintf(os.Stderr, "warning: %v; continuing unverified\n", err)
		want = ""
	}

	fmt.Fprintf(os.Stderr, "Downloading %s...\n", asset.Name)
	reqCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, asset.URL, nil)
	if err != nil {
		return "", fmt.Errorf("create download request: %w", err)
	}
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("download failed: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("download failed: status %s", resp.Status)
	}

	tmpPath := destPath + ".download"
	if err := os.MkdirAll(filepath.Dir(tmpPath), 0o755); err != nil {
		return "", err
	}
	f, err := os.Create(tmpPath)
	if err != nil {
		return "", err
	}
	h := sha256.New()
	written, err := io.Copy(io.MultiWriter(f, h), io.LimitReader(resp.Body, maxDownloadBytes))
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		os.Remove(tmpPath)
		return "", fmt.Errorf("write download: %w", err)
	}
	if written == 0 {
		os.Remove(tmpPath)
		return "", errors.New("downloaded file is empty")
	}
	if want != "" {
		if got := hex.EncodeToString(h.Sum(nil)); got != want {
			os.Remove(tmpPath)
			return "", fmt.Errorf("checksum mismatch for %s: got %s, want %s", asset.Name, got, want)
		}
	}
	return tmpPath, nil
}

// ExtractZip writes the first zip entry whose base name satisfies match to destPath.
func ExtractZip(zipPath, destPath string, match func(name string) bool) error {
	r, err := zip.OpenReader(zipPath)
	if err != nil {
		return fmt.Errorf("open zip: %w", err)
	}
	defer r.Close()
	for _, f := range r.File {
		if !match(filepath.Base(f.Name)) {
			continue
		}
		src, err := f.Open()
		if err != nil {
			return err
		}
		defer src.Close()
		return writeExecutable(destPath, src)
	}
	return errors.New("no binary found in zip archive")
}

// ExtractGzip decompresses a single-file .gz archive to destPath.
func ExtractGzip(gzPath, destPath string) error {
	f, err := os.Open(gzPath)
	if err != nil {
		return err
	}
	defer f.Close()
	gr, err := gzip.NewReader(f)
	if err != nil {
		return err
	}
	defer gr.Close()
	return writeExecutable(destPath, gr)
}

func writeExecutable(destPath string, src io.Reader) error {
	dst, err := os.OpenFile(destPath, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o755)
	if err != nil {
		return err
	}
	if _, err := io.Copy(dst, src); err != nil {
		dst.Close()
		return err
	}
	return dst.Close()
}

// Activate moves the extracted binary into place and marks it executable.
func Activate(extractedPath, destPath string) error {
	if runtime.GOOS == "windows" {
		os.Remove(destPath)
	}
	if err := os.Rename(extractedPath, destPath); err != nil {
		return fmt.Errorf("activate binary: %w", err)
	}
	return os.Chmod(destPath, 0o755)
}
