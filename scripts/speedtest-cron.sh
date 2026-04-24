#!/bin/bash
# speedtest-cron.sh — Run latency-only test and push to Prometheus
# Usage: ./speedtest-cron.sh [config.yaml]
#
# Config:
#   SPEEDTEST_BIN  — path to speedtest binary (default: ./speedtest)
#   SUB_URL        — v2ray subscription URL (used if no config file)
#   CONFIG_FILE    — Clash YAML config path
#   PUSHGATEWAY    — Prometheus Pushgateway URL (default: http://127.0.0.1:9091)
#   PROM_JOB       — Prometheus job name (default: speedtest)
#   KERNEL         — proxy kernel (default: mihomo)
#   CONCURRENCY    — concurrent workers (default: 5)
#   TIMEOUT        — per-probe timeout (default: 10s)
#
# Crontab example (every 5 minutes):
#   */5 * * * * /path/to/speedtest-cron.sh /path/to/config.yaml >/dev/null 2>&1
set -euo pipefail

# === Configuration ===
SPEEDTEST_BIN="${SPEEDTEST_BIN:-/root/AnixOps/speedtest/speedtest-linux-amd64}"
PUSHGATEWAY="${PUSHGATEWAY:-http://10.100.0.122:9091}"
PROM_JOB="${PROM_JOB:-speedtest-cn}"
KERNEL="${KERNEL:-xray}"
CONCURRENCY="${CONCURRENCY:-5}"
TIMEOUT="${TIMEOUT:-10s}"

# First arg is config file, or use subscription URL
CONFIG_FILE="${1:-}"
SUB_URL="${SUB_URL:-https://x.kalijerry.uk/api/v1/client/subscribe?token=00debf0dc792365eab40cf969a10d48b}"

if [ -n "$CONFIG_FILE" ]; then
  MODE="-f ${CONFIG_FILE}"
else
  MODE="-sub ${SUB_URL}"
fi

if [ -z "$CONFIG_FILE" ] && [ -z "${SUB_URL:-}" ]; then
  echo "Error: provide a config file argument or set SUB_URL" >&2
  exit 1
fi

exec "${SPEEDTEST_BIN}" ${MODE} \
  -kernel "${KERNEL}" \
  -latency-only \
  -c "${CONCURRENCY}" \
  -timeout "${TIMEOUT}" \
  -pushgateway "${PUSHGATEWAY}" \
  -prom-job "${PROM_JOB}"
