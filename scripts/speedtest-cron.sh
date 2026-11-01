#!/bin/bash
# speedtest-cron.sh — Run latency-only test and push to Prometheus
# Usage: ./speedtest-cron.sh [config.yaml]
#
# Config:
#   SPEEDTEST_BIN  — path to speedtest binary (default: ./speedtest)
#   SUB_URL        — subscription URL (used if no config file)
#   SUB_UA         — User-Agent for the subscription fetch (default: speedtest's, per kernel)
#   CONFIG_FILE    — Clash YAML config path
#   PUSHGATEWAY    — Prometheus Pushgateway URL (default: http://127.0.0.1:9091)
#   PROM_JOB       — Prometheus job name (default: speedtest)
#   KERNEL         — proxy kernel: mihomo, xray or anx (default: mihomo)
#   ANX_BIN        — anx-proxy binary for KERNEL=anx (default: speedtest's search)
#   CONCURRENCY    — concurrent workers (default: 5)
#   TIMEOUT        — per-probe timeout (default: 10s)
#   REPEAT         — latency samples per node (default: 1; >1 adds jitter and loss)
#
# Crontab example (every 5 minutes):
#   */5 * * * * /path/to/speedtest-cron.sh /path/to/config.yaml >/dev/null 2>&1
set -euo pipefail

SPEEDTEST_BIN="${SPEEDTEST_BIN:-./speedtest}"
PUSHGATEWAY="${PUSHGATEWAY:-http://127.0.0.1:9091}"
PROM_JOB="${PROM_JOB:-speedtest}"
KERNEL="${KERNEL:-mihomo}"
CONCURRENCY="${CONCURRENCY:-5}"
TIMEOUT="${TIMEOUT:-10s}"
REPEAT="${REPEAT:-1}"

CONFIG_FILE="${1:-${CONFIG_FILE:-}}"
SUB_URL="${SUB_URL:-}"

if [ -n "$CONFIG_FILE" ]; then
  args=(-f "$CONFIG_FILE")
elif [ -n "$SUB_URL" ]; then
  args=(-sub "$SUB_URL")
else
  echo "Error: provide a config file argument or set SUB_URL" >&2
  exit 1
fi
[ -n "${SUB_UA:-}" ] && args+=(-sub-ua "$SUB_UA")
[ -n "${ANX_BIN:-}" ] && args+=(-anx-bin "$ANX_BIN")

exec "${SPEEDTEST_BIN}" "${args[@]}" \
  -kernel "${KERNEL}" \
  -latency-only \
  -repeat "${REPEAT}" \
  -c "${CONCURRENCY}" \
  -timeout "${TIMEOUT}" \
  -pushgateway "${PUSHGATEWAY}" \
  -prom-job "${PROM_JOB}"
