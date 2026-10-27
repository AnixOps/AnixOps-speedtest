#!/bin/bash
# install-speedtest.sh — Download, verify and install speedtest from GitHub Releases
# Usage: curl -fsSL https://raw.githubusercontent.com/AnixOps/AnixOps-speedtest/master/scripts/install-speedtest.sh | bash
#
# Environment:
#   VERSION      release tag to install (default: latest)
#   INSTALL_DIR  target directory (default: /usr/local/bin, falls back to ~/.local/bin)
set -euo pipefail

REPO="AnixOps/AnixOps-speedtest"
VERSION="${VERSION:-latest}"

OS="$(uname -s | tr '[:upper:]' '[:lower:]')"
case "$(uname -m)" in
  x86_64|amd64)  ARCH="amd64" ;;
  aarch64|arm64) ARCH="arm64" ;;
  armv7l)        ARCH="armv7" ;;
  *) echo "Unsupported architecture: $(uname -m)" >&2; exit 1 ;;
esac
case "$OS" in
  linux|darwin) ;;
  *) echo "Unsupported OS: $OS" >&2; exit 1 ;;
esac
if [ "$OS" = "darwin" ] && [ "$ARCH" = "armv7" ]; then
  echo "Unsupported platform: darwin/armv7" >&2; exit 1
fi

if [ "$VERSION" = "latest" ]; then
  BASE="https://github.com/${REPO}/releases/latest/download"
else
  BASE="https://github.com/${REPO}/releases/download/${VERSION}"
fi

BIN="speedtest-${OS}-${ARCH}"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

echo "=> Downloading ${BIN} (${VERSION})..."
curl -fSL --retry 3 -o "${TMP}/${BIN}" "${BASE}/${BIN}"
curl -fSL --retry 3 -o "${TMP}/checksums.txt" "${BASE}/checksums.txt"

echo "=> Verifying SHA-256..."
EXPECTED="$(awk -v f="$BIN" '$2 == f || $2 == "*"f {print $1}' "${TMP}/checksums.txt")"
[ -n "$EXPECTED" ] || { echo "No checksum listed for ${BIN}" >&2; exit 1; }
if command -v sha256sum >/dev/null 2>&1; then
  ACTUAL="$(sha256sum "${TMP}/${BIN}" | awk '{print $1}')"
else
  ACTUAL="$(shasum -a 256 "${TMP}/${BIN}" | awk '{print $1}')"
fi
if [ "$EXPECTED" != "$ACTUAL" ]; then
  echo "Checksum mismatch: expected ${EXPECTED}, got ${ACTUAL}" >&2
  exit 1
fi
chmod +x "${TMP}/${BIN}"

INSTALL_DIR="${INSTALL_DIR:-/usr/local/bin}"
SUDO=""
if [ ! -w "$INSTALL_DIR" ]; then
  if [ "$(id -u)" -ne 0 ] && command -v sudo >/dev/null 2>&1 && [ "$INSTALL_DIR" = "/usr/local/bin" ]; then
    SUDO="sudo"
  elif [ "$INSTALL_DIR" = "/usr/local/bin" ]; then
    INSTALL_DIR="${HOME}/.local/bin"
    mkdir -p "$INSTALL_DIR"
  fi
fi
$SUDO install -m 0755 "${TMP}/${BIN}" "${INSTALL_DIR}/speedtest"

echo "=> Installed to ${INSTALL_DIR}/speedtest"
case ":$PATH:" in *":${INSTALL_DIR}:"*) ;; *) echo "Note: ${INSTALL_DIR} is not in your PATH" ;; esac
"${INSTALL_DIR}/speedtest" -version
