package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/anixops/speedtest/internal/ats"
)

func runVerify(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("verify", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var opts ats.VerifyOptions
	fs.StringVar(&opts.TrustedKeyFingerprint, "key-fingerprint", "", "pin the Ed25519 signer (SHA-256 of the public key, hex)")
	fs.StringVar(&opts.TrustedMLDSAFingerprint, "mldsa-fingerprint", "", "pin the ML-DSA-87 signer (SHA-256 of the public key, hex)")
	fs.Usage = func() {
		fmt.Fprintln(stderr, "Usage: speedtest verify [--key-fingerprint <hex>] [--mldsa-fingerprint <hex>] <report.json>")
		fs.PrintDefaults()
	}
	// Accept the file before or after the flags.
	var file string
	rest := args
	for len(rest) > 0 {
		if err := fs.Parse(rest); err != nil {
			return 2
		}
		if fs.NArg() == 0 {
			break
		}
		if file == "" {
			file = fs.Arg(0)
		}
		rest = fs.Args()[1:]
	}
	if file == "" {
		fs.Usage()
		return 2
	}

	data, err := os.ReadFile(file)
	if err != nil {
		fmt.Fprintf(stderr, "error reading file: %v\n", err)
		return 2
	}
	var env ats.ReportEnvelope
	if err := json.Unmarshal(data, &env); err != nil {
		fmt.Fprintf(stderr, "error parsing JSON: %v\n", err)
		return 2
	}

	res := ats.Verify(env, opts)
	fmt.Fprintf(stdout, "File:             %s\n", file)
	fmt.Fprintf(stdout, "Computed SHA-256: %s\n", res.ComputedHash)
	fmt.Fprintf(stdout, "Anti-Tamper ID:   %s\n", ats.AntiTamperID(res.ComputedHash))
	if c := env.Certificate; c != nil {
		fmt.Fprintf(stdout, "Timestamp:        %s\n", c.Timestamp.Format("2006-01-02 15:04:05 UTC"))
		fmt.Fprintf(stdout, "Blockchain:       %s\n", c.OTSStatus)
	}
	fmt.Fprintln(stdout)

	for i, c := range res.Checks {
		mark := map[ats.Status]string{ats.StatusPass: "✓", ats.StatusFail: "✗", ats.StatusSkip: "—"}[c.Status]
		fmt.Fprintf(stdout, "[%d] %s %s: %s\n", i+1, mark, c.Name, c.Detail)
	}
	fmt.Fprintln(stdout)

	switch {
	case !res.OK():
		fmt.Fprintln(stdout, "✗ FAILED: verification failed.")
		return 1
	case !res.Signed():
		fmt.Fprintln(stdout, "~ INTEGRITY ONLY: the hash matches but no signature was verified; this does not prove who produced the report.")
		return 0
	default:
		fmt.Fprintln(stdout, "✓ VERIFIED: all checks passed.")
		return 0
	}
}
