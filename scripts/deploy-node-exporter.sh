#!/bin/bash
# deploy-node-exporter.sh — Download, install, and enable Node Exporter on Linux
set -e

VERSION="1.8.2"
ARCH="amd64"
INSTALL_DIR="/usr/local/bin"
SERVICE_FILE="/etc/systemd/system/node_exporter.service"

echo "=> Downloading Node Exporter v${VERSION}..."
cd /tmp
wget -q "https://github.com/prometheus/node_exporter/releases/download/v${VERSION}/node_exporter-${VERSION}.linux-${ARCH}.tar.gz"

echo "=> Extracting..."
tar xzf "node_exporter-${VERSION}.linux-${ARCH}.tar.gz"
cp "node_exporter-${VERSION}.linux-${ARCH}/node_exporter" "${INSTALL_DIR}/node_exporter"
chmod +x "${INSTALL_DIR}/node_exporter"
rm -rf "node_exporter-${VERSION}.linux-${ARCH}" "node_exporter-${VERSION}.linux-${ARCH}.tar.gz"

echo "=> Installing systemd service..."
cat > "${SERVICE_FILE}" << 'EOF'
[Unit]
Description=Node Exporter
After=network.target

[Service]
Type=simple
User=nobody
Group=nogroup
ExecStart=/usr/local/bin/node_exporter --web.listen-address=":9100"
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable --now node_exporter

echo "=> Verifying..."
sleep 2
curl -s http://localhost:9100/metrics -o /dev/null -w "HTTP %{http_code}\n"
echo "=> Node Exporter deployed on port 9100"
