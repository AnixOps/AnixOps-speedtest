# AnixOps Speedtest

Open-source CLI tool for batch testing proxy node quality from Mihomo/Clash configuration files. Helps you filter high-quality nodes with comprehensive testing.

> **Note**: Clash has been deprecated. This tool primarily targets [MetaCubeX/mihomo](https://github.com/MetaCubeX/mihomo) as the default proxy kernel, with xray-core also supported as an alternative.

## Features

### Streaming Unlock Detection
- Netflix (with region detection)
- YouTube Premium
- Disney+
- Bilibili (CN region check)
- OpenAI (ChatGPT)
- Claude
- Spotify
- Tiktok
- Wikipedia

### Network Quality Tests
- **HTTP Latency** - True HTTP request-response timing
- **TCP Latency** - Raw TCP connection timing
- **Download Speed** - Throughput measurement (Mbps)
- **IP Risk/Fraud Score** - Detect datacenter/proxy IPs via ip-api
- **DNS Region Detection** - Identify exit IP geolocation
- **SSH Port 22 Check** - Detect port 22 blocking
- **Topology Analysis** - Entry/exit IP comparison (origin vs proxy)

### Output Formats
- **table** - Terminal table (default)
- **json** - Machine-readable JSON (with embedded certificate)
- **csv** - Spreadsheet-compatible CSV
- **chart** - Interactive HTML report with anti-tamper certificate
- **png** - Image report with QR code

### Anti-Tamper (防伪)
Every report automatically generates a **Certificate of Authenticity**:
- SHA-256 hash of canonical test results
- Anti-tamper ID (12-char short hash)
- Bitcoin blockchain anchoring via OpenTimestamps (free, no API key)
- QR code in HTML/PNG reports for quick verification
- Client-side auto-verification in HTML reports

## Install

### Quick Install (Linux / macOS)

```bash
curl -fsSL https://raw.githubusercontent.com/AnixOps/AnixOps-speedtest/master/scripts/install-speedtest.sh | bash
```

### Build from Source

```bash
go build -o speedtest ./cmd/speedtest
```

### Prerequisites

None. The program automatically downloads the required proxy kernel on first run from GitHub Releases:

- **[mihomo](https://github.com/MetaCubeX/mihomo/releases)** - Default and recommended kernel
- **[xray-core](https://github.com/XTLS/Xray-core/releases)** - Alternative kernel

The downloaded binary is placed in the `bin/` directory and reused on subsequent runs. No manual setup required.

## Project Structure

```
.
├── bin/          # Downloaded proxy kernel binaries (auto-created)
├── output/       # Generated reports (auto-created)
│   └── verify.html  # Standalone web verification tool
├── cmd/
│   └── speedtest/
│       ├── main.go
│       └── verify.go   # CLI verification subcommand
├── internal/     # Internal packages
│   ├── ats/      # Anti-tamper: certificate, OTS, QR code
│   ├── chart/    # HTML/PNG report generation
│   ├── checker/  # Unlock & IP risk checkers
│   ├── clash/    # Clash YAML parser
│   ├── mihomo/   # Mihomo kernel launcher
│   ├── probe/    # Core testing engine
│   ├── proxy/    # SOCKS5/HTTP proxy dialer
│   ├── sub/      # Subscription URL parser
│   ├── topo/     # Topology analysis
│   └── xray/     # Xray kernel launcher
├── go.mod
└── README.md
```

## Usage

```bash
# Basic usage (defaults to mihomo kernel)
speedtest -f config.yaml

# Use xray kernel instead
speedtest -f config.yaml -kernel xray

# With HTML chart output (saved to output/report.html)
speedtest -f config.yaml -format chart

# Custom output file and directory
speedtest -f config.yaml -format chart -output-dir reports -o my-report.html

# Filter specific proxies by name
speedtest -f config.yaml -filter "HK"

# Skip certain tests for faster runs
speedtest -f config.yaml -skip-speed -skip-ssh

# JSON output
speedtest -f config.yaml -format json

# Adjust concurrency and timeout
speedtest -f config.yaml -c 10 -timeout 15s
```

## Command Line Options

| Flag | Default | Description |
|------|---------|-------------|
| `-f` | (required) | Path to Mihomo/Clash YAML config file |
| `-kernel` | `mihomo` | Proxy kernel: mihomo or xray |
| `-format` | `table` | Output format: table, json, csv, chart, png |
| `-o` | (auto) | Output file path (default: `outputDir/report.<format>`) |
| `-output-dir` | `output` | Directory for output files |
| `-bin-dir` | `bin` | Directory for downloaded kernel binaries |
| `-c` | `5` | Concurrent test workers |
| `-timeout` | `10s` | Per-probe timeout |
| `-filter` | (none) | Only test proxies whose name contains this |
| `-skip-latency` | false | Skip HTTP latency test |
| `-skip-speed` | false | Skip download speed test |
| `-skip-unlock` | false | Skip streaming unlock tests |
| `-skip-topo` | false | Skip topology analysis |
| `-skip-iprisk` | false | Skip IP risk check |
| `-skip-dns` | false | Skip DNS region detection |
| `-skip-ssh` | false | Skip SSH port 22 check |
| `-download-size` | `10485760` | Bytes to download for speed test |
| `-version` | false | Print version |
| `-no-ats` | false | Disable blockchain anchoring |

## Chart Output

The `chart` format generates a self-contained HTML report with:
- Summary statistics (nodes tested, avg latency, avg speed)
- Horizontal bar charts for latency, speed, and IP risk
- Streaming unlock coverage chart
- Detailed results table with colored badges

```bash
speedtest -f config.yaml -format chart
# Output: output/report.html — open in any browser
```

## Anti-Tamper Verification (防伪验证)

Every test run automatically generates a **Certificate of Authenticity** that prevents data tampering. The certificate includes a SHA-256 hash of all test results, anchored to the Bitcoin blockchain via [OpenTimestamps](https://opentimestamps.org).

### Verifying Reports

**CLI verification:**
```bash
speedtest verify output/report.json
# Outputs: hash match/mismatch, certificate details, blockchain status
```

**Web verification:**
Open `output/verify.html` in a browser, then drag and drop any `report.json` file. The page computes SHA-256 locally and compares against the embedded certificate.

**HTML report:**
HTML reports include an auto-verifying section at the bottom — it opens with a green "Verified" banner if the data is intact, or red "Tampered" if modified.

**PNG report:**
PNG reports include a QR code in the bottom-right corner that links to the OpenTimestamps verification page.

### Certificate Fields

| Field | Description |
|-------|-------------|
| `anti_tamper_id` | 12-char short hash (first 12 of SHA-256) |
| `hash` | Full SHA-256 of canonical JSON results |
| `timestamp` | UTC time when test completed |
| `ots_status` | `confirmed` (anchored) / `pending` / `disabled` |
| `ots_proof` | Base64-encoded OpenTimestamps proof file |

### Disabling Anchoring

Add `-no-ats` to disable blockchain anchoring. The certificate will still be generated with `ots_status: "disabled"`.

```bash
speedtest -f config.yaml -no-ats
```

## How It Works

1. Parses your Mihomo/Clash YAML config to extract proxy definitions
2. For each proxy node, launches a local proxy kernel instance with SOCKS5 inbound
3. Routes all test traffic through the proxy tunnel
4. Collects metrics from streaming services, IP APIs, and download endpoints
5. Outputs results in your chosen format

## Supported Proxy Types

- VMess
- VLESS
- Trojan
- Shadowsocks

## Kernel Comparison

| Feature | mihomo | xray |
|---------|--------|------|
| Clash config support | Native | Converted |
| Transport support | Full (all Clash protocols) | VMess/VLESS/Trojan/SS |
| DNS resolution | Native DNS engine | System DNS |
| Config format | YAML | JSON (auto-generated) |
| Default | Yes | No |

## License

MIT License
