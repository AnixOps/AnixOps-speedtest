package main

import (
	"flag"
	"fmt"
	"os"
	"sort"

	"gopkg.in/yaml.v3"
)

const defaultConfigFile = "speedtest.yaml"

// applyConfigFile loads a YAML mapping whose keys are command-line flag names
// (e.g. "format", "c", "timeout", "skip-speed") and applies every entry that was
// not given explicitly on the command line. Unknown keys are an error so typos
// don't silently do nothing.
//
// An empty path falls back to ./speedtest.yaml when it exists.
func applyConfigFile(fs *flag.FlagSet, path string) error {
	explicit := path != ""
	if path == "" {
		path = defaultConfigFile
	}
	data, err := os.ReadFile(path)
	if err != nil {
		if !explicit && os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("read config %s: %w", path, err)
	}
	var values map[string]any
	if err := yaml.Unmarshal(data, &values); err != nil {
		return fmt.Errorf("parse config %s: %w", path, err)
	}

	setOnCLI := map[string]bool{}
	fs.Visit(func(f *flag.Flag) { setOnCLI[f.Name] = true })

	keys := make([]string, 0, len(values))
	for k := range values {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		if k == "config" {
			continue
		}
		if fs.Lookup(k) == nil {
			return fmt.Errorf("config %s: unknown option %q", path, k)
		}
		if setOnCLI[k] {
			continue
		}
		if err := fs.Set(k, fmt.Sprint(values[k])); err != nil {
			return fmt.Errorf("config %s: option %q: %w", path, k, err)
		}
	}
	return nil
}
