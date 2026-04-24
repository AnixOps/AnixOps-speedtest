#!/bin/bash
# install-speedtest.sh — Download and install speedtest from GitHub Releases
# Usage: curl -fsSL https://raw.githubusercontent.com/AnixOps/AnixOps-speedtest/master/scripts/install-speedtest.sh | bash
set -e

VERSION="26.1.1"
INSTALL_DIR="/usr/local/bin"

# Detect OS and arch
OS="$(uname -s | tr '[:upper:]' '[:lower:]')"
ARCH="$(uname -m)"

case "$ARCH" in
  x86_64)  ARCH="amd64" ;;
  aarch64) ARCH="arm64" ;;
  armv7l)  ARCH="arm64" ;;
  arm64)   ARCH="arm64" ;;
  *) echo "Unsupported architecture: $ARCH"; exit 1 ;;
esac

case "$OS" in
  linux|darwin) ;;
  *) echo "Unsupported OS: $OS"; exit 1 ;;
esac

BIN="speedtest-${OS}-${ARCH}"
URL="https://github.com/AnixOps/AnixOps-speedtest/releases/download/v${VERSION}/${BIN}"

echo "=> Downloading speedtest v${VERSION} for ${OS}/${ARCH}..."
curl -fSL --retry 3 -o "${INSTALL_DIR}/speedtest" "${URL}"
chmod +x "${INSTALL_DIR}/speedtest"

echo "=> Installed to ${INSTALL_DIR}/speedtest"
speedtest --version
