# Contributing

1. `go vet ./... && go test -race ./...` must pass; CI also checks `gofmt -l .` and golangci-lint.
2. Keep new behaviour covered by tests. Network-dependent code should be tested with `httptest`
   servers; end-to-end checks can use a local mihomo shadowsocks listener as the "node".
3. Streaming/service checks are data, not code: edit `internal/checker/rules.yaml`
   (schema documented at the top of that file) rather than adding Go functions.
4. Never commit subscription URLs, tokens, keys (`.keys/`) or generated reports (`output/`).
5. Security-sensitive areas (kernel download verification, `internal/ats`) need a test for the failure path.

Report vulnerabilities privately via GitHub Security Advisories rather than public issues.
