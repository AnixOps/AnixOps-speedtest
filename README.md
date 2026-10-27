# AnixOps Speedtest

CLI for batch-testing proxy node quality from a Mihomo/Clash config or a subscription URL. It starts a
local proxy kernel per node (or per batch), routes every probe through it, and reports latency, speed,
service unlocks and exit-IP reputation — with signed, tamper-evident reports.

Default kernel: [mihomo](https://github.com/MetaCubeX/mihomo). [xray-core](https://github.com/XTLS/Xray-core) is supported for VMess/VLESS/Trojan/Shadowsocks.

## Install

```bash
# Linux / macOS — downloads the latest release and verifies its SHA-256 against checksums.txt
curl -fsSL https://raw.githubusercontent.com/AnixOps/AnixOps-speedtest/master/scripts/install-speedtest.sh | bash
# pin a version / custom dir:  VERSION=v1.2.3 INSTALL_DIR=$HOME/.local/bin bash install-speedtest.sh
```

```bash
go build -o speedtest ./cmd/speedtest      # from source
docker run --rm -v "$PWD:/work" ghcr.io/anixops/anixops-speedtest -f config.yaml -format json
```

Release checksums are signed with keyless [cosign](https://github.com/sigstore/cosign) (`checksums.txt.sigstore.json`) and an SBOM is attached.

No manual kernel setup: on first run the kernel is downloaded from GitHub Releases into `bin/` and its
**SHA-256 is verified** (GitHub release digest, or the `.dgst` file for Xray). A download without a published
digest is refused unless you set `SPEEDTEST_ALLOW_UNVERIFIED_KERNEL=1`.

## Usage

```bash
speedtest -f config.yaml                         # table to stdout
speedtest -sub "https://example/sub?token=..."   # v2ray/Clash subscription
speedtest -f config.yaml -latency-only -repeat 5 # median / jitter / loss over 5 samples
speedtest -f config.yaml -format json -redact    # shareable report: IPs masked, raw evidence dropped
speedtest -f config.yaml -format chart           # HTML report -> output/report.html
speedtest -f config.yaml -jsonl -                # stream one JSON line per node as it finishes
speedtest -f big.yaml -mihomo-batch 20 -c 10     # 20 nodes per mihomo process
speedtest verify output/report.json --key-fingerprint <sha256-of-signer-pubkey>
```

Progress is logged to stderr as nodes finish (`-q` silences it). Dead nodes (no latency probe answers) are
reported immediately and skip the remaining checks.

### Options

| Flag | Default | Description |
|------|---------|-------------|
| `-f` / `-sub` | – | Clash YAML file, or subscription URL (one is required) |
| `-sub-ua` | `clash.meta` | User-Agent for the subscription fetch |
| `-config` | `./speedtest.yaml` if present | YAML of option defaults, keyed by flag name; CLI flags win |
| `-kernel` | `mihomo` | `mihomo` or `xray` |
| `-format` | `table` | `table`, `json`, `csv`, `chart`, `png` (non-table default to `output/`) |
| `-o`, `-output-dir`, `-bin-dir`, `-key-dir` | – / `output` / `bin` / `.keys` | Paths |
| `-c` | `5` | Concurrent workers |
| `-timeout` | `10s` | Per-probe timeout |
| `-speed-timeout`, `-unlock-timeout` | 3×`-timeout`, `-timeout` | Per-phase overrides |
| `-repeat` | `1` | Latency samples per node; >1 reports median, jitter, loss |
| `-filter` | – | Only test nodes whose name contains this |
| `-latency-only` | false | Latency only (implies all `-skip-*` except latency) |
| `-skip-latency/-speed/-unlock/-topo/-iprisk/-dns/-ssh` | false | Skip individual checks |
| `-download-size` | `10485760` | Bytes for the speed test |
| `-unlock-rules` | – | YAML that overrides/extends the built-in unlock rules |
| `-mihomo-batch` | `0` | Nodes per mihomo process (0 = one process per node); falls back per node if a batch fails to start |
| `-redact` | false | Mask server/entry/exit IPs, drop raw evidence (applied *before* signing) |
| `-jsonl` | – | Stream per-node results as JSON lines to a file (`-` = stdout) |
| `-no-ats`, `-no-sign` | false | Disable OpenTimestamps anchoring / signatures |
| `-pushgateway`, `-prom-job` | – / `speedtest` | Push latency metrics to a Prometheus Pushgateway (skips file output) |
| `-q`, `-version` | | Quiet; print version, commit and build date |

A `speedtest.yaml` example:

```yaml
kernel: mihomo
c: 10
timeout: 15s
format: json
repeat: 3
skip-ssh: true
```

`.env` next to the binary may set `CF_ACCESS_CLIENT_ID` / `CF_ACCESS_CLIENT_SECRET` (Pushgateway behind Cloudflare Access); real environment variables take precedence.

## What is measured

- **HTTP latency** — GET `generate_204` through the node. **TCP latency** — connect **plus one TLS handshake round trip**
  to 1.1.1.1:443 (a bare SOCKS5 connect is acknowledged locally and would "succeed" for dead nodes).
- **Speed** — download of `-download-size` bytes (Cloudflare, Hetzner fallback).
- **Unlocks** — Netflix, YouTube Premium, Disney+, Bilibili, OpenAI, Claude, Spotify, TikTok, Wikipedia. Each verdict carries a
  `confidence` (`high|medium|low`). Rules live in [`internal/checker/rules.yaml`](internal/checker/rules.yaml) — edit or extend
  them via `-unlock-rules` without recompiling.
- **IP risk** — exit IP via ipinfo.io, reputation via proxycheck.io (HTTPS), ipapi.is as backup. Results are cached per exit IP.
  The plain-HTTP ip-api.com provider is **off** unless `SPEEDTEST_ALLOW_HTTP_GEOIP=1` (its answers can be forged on the path).
  If no reputation provider answers, the level is a coarse `medium` guess.
- **DNS region**, **SSH port 22**, **topology** (entry vs exit IP).

## Protocols

| Kernel | Protocols |
|--------|-----------|
| mihomo | VMess, VLESS (incl. Reality), Trojan, Shadowsocks, **and everything mihomo supports natively** (Hysteria2, TUIC, … — options are forwarded verbatim from Clash YAML) |
| xray | VMess, VLESS (incl. Reality), Trojan, Shadowsocks |

Share links parsed from subscriptions: `vmess://`, `vless://`, `trojan://`, `ss://`, `hysteria2://`/`hy2://`, `tuic://`.
Note: nodes from subscriptions are tested with certificate verification **off**.

## Reports and anti-tamper

Every report carries a certificate: SHA-256 of the canonical results, an Ed25519 signature, an ML-DSA-87 (post-quantum)
signature, and optional OpenTimestamps (Bitcoin) anchoring of the hash.

`speedtest verify report.json` recomputes the hash and checks the signatures. **A signature only proves who signed if you
know the signer's key**, so pin it:

```bash
speedtest verify report.json --key-fingerprint <sha256 of Ed25519 public key> --mldsa-fingerprint <sha256 of ML-DSA public key>
```

The fingerprints are printed when a report is generated (`Trust Anchor (key fingerprint)`). Fingerprints are always recomputed
from the embedded public key; a pinned key makes the matching signature mandatory. Without pins the result is reported as
"integrity only"/"signer not pinned". The self-check embedded in HTML reports detects accidental corruption but cannot
authenticate the author — use `verify` with a pinned key for that.

`-redact` is applied before signing, so a redacted report verifies like any other.

## Prometheus

`-pushgateway URL` pushes `speedtest_node_up`, `speedtest_http_latency_ms`, `speedtest_tcp_latency_ms`, and (with `-repeat > 1`)
`speedtest_http_jitter_ms`, `speedtest_http_loss_pct`. `scripts/speedtest-cron.sh` wraps this for cron (set `SUB_URL` or pass a config).

## Layout

```
cmd/speedtest      CLI, config file, verify subcommand
internal/kernel    shared kernel download+SHA-256 verification, process supervision
internal/mihomo    mihomo launcher (single node or batch)     internal/xray   xray launcher
internal/probe     orchestration, latency/speed, redaction, table/CSV
internal/checker   unlock rules engine, IP reputation, DNS, SSH
internal/ats       certificate, signing (Ed25519 + ML-DSA), verification, OTS, QR
internal/chart     HTML / PNG reports        internal/sub, internal/clash   input parsing
internal/prom      Pushgateway               internal/topo                  entry/exit analysis
```

## Development

```bash
go vet ./... && go test -race ./...
```

See [CONTRIBUTING.md](CONTRIBUTING.md). MIT licensed.
