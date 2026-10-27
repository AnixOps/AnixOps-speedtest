package main

import (
	"flag"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func newFS() (*flag.FlagSet, *string, *int, *bool, *time.Duration) {
	fs := flag.NewFlagSet("t", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	format := fs.String("format", "table", "")
	c := fs.Int("c", 5, "")
	skip := fs.Bool("skip-speed", false, "")
	to := fs.Duration("timeout", 10*time.Second, "")
	return fs, format, c, skip, to
}

func writeCfg(t *testing.T, body string) string {
	p := filepath.Join(t.TempDir(), "c.yaml")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestConfigFileAppliedAndCLIWins(t *testing.T) {
	fs, format, c, skip, to := newFS()
	if err := fs.Parse([]string{"-c", "9"}); err != nil {
		t.Fatal(err)
	}
	p := writeCfg(t, "format: json\nc: 20\nskip-speed: true\ntimeout: 15s\n")
	if err := applyConfigFile(fs, p); err != nil {
		t.Fatal(err)
	}
	if *format != "json" || *c != 9 || !*skip || *to != 15*time.Second {
		t.Fatalf("got format=%s c=%d skip=%v timeout=%v", *format, *c, *skip, *to)
	}
}

func TestConfigFileUnknownKey(t *testing.T) {
	fs, _, _, _, _ := newFS()
	if err := applyConfigFile(fs, writeCfg(t, "frmat: json\n")); err == nil {
		t.Fatal("typo must be rejected")
	}
}

func TestConfigFileBadValueAndMissing(t *testing.T) {
	fs, _, _, _, _ := newFS()
	if err := applyConfigFile(fs, writeCfg(t, "c: many\n")); err == nil {
		t.Fatal("bad value must be rejected")
	}
	if err := applyConfigFile(fs, "/nonexistent/c.yaml"); err == nil {
		t.Fatal("explicit missing file must error")
	}
}

func TestConfigFileDefaultAbsentIsFine(t *testing.T) {
	dir := t.TempDir()
	wd, _ := os.Getwd()
	defer os.Chdir(wd)
	os.Chdir(dir)
	fs, _, _, _, _ := newFS()
	if err := applyConfigFile(fs, ""); err != nil {
		t.Fatalf("no default file should be fine: %v", err)
	}
}
