package sub

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
)

// FetchResult says where the nodes of FetchWithCache came from.
type FetchResult struct {
	Nodes []Node
	// FromCache is true when the fetch failed and the nodes were read from
	// the cache; FetchErr then holds the fetch error.
	FromCache bool
	FetchErr  error
}

// FetchWithCache fetches and parses the subscription. A body that parses is
// written to cachePath (0600, replaced atomically). When the fetch or the
// parse fails, the last good body is read back from cachePath instead. An
// empty cachePath behaves like FetchAndParse.
func FetchWithCache(ctx context.Context, subscriptionURL, userAgent, cachePath string) (FetchResult, error) {
	body, err := Fetch(ctx, subscriptionURL, userAgent)
	var nodes []Node
	if err == nil {
		nodes, err = Parse(body)
	}
	if err == nil {
		if cachePath != "" {
			if werr := writeCache(cachePath, body); werr != nil {
				return FetchResult{Nodes: nodes}, fmt.Errorf("subscription cache: %w", werr)
			}
		}
		return FetchResult{Nodes: nodes}, nil
	}
	if cachePath == "" {
		return FetchResult{}, err
	}
	cached, rerr := os.ReadFile(cachePath)
	if rerr != nil {
		return FetchResult{FetchErr: err}, fmt.Errorf("%w (no usable cache: %v)", err, rerr)
	}
	nodes, perr := Parse(cached)
	if perr != nil {
		return FetchResult{FetchErr: err}, fmt.Errorf("%w (cache %s: %v)", err, cachePath, perr)
	}
	return FetchResult{Nodes: nodes, FromCache: true, FetchErr: err}, nil
}

func writeCache(path string, body []byte) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".sub-cache-*")
	if err != nil {
		return err
	}
	name := tmp.Name()
	defer os.Remove(name)
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(body); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(name, path)
}
