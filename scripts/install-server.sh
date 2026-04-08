#!/bin/bash
# DocVault Server Installation Script (Linux)
# Usage: sudo bash install-server.sh

set -e

echo "=== DocVault Server Installation ==="

# Check root
if [ "$EUID" -ne 0 ]; then
  echo "Please run as root (sudo)"
  exit 1
fi

# Create user and directories
useradd -r -s /bin/false docvault 2>/dev/null || true
mkdir -p /opt/docvault /var/lib/docvault/vault /var/log/docvault

# Download latest release (or copy binary manually)
if [ -f "./docvault-linux-amd64" ]; then
  cp docvault-linux-amd64 /opt/docvault/docvault
else
  echo "Place docvault-linux-amd64 binary in current directory and re-run"
  exit 1
fi
chmod +x /opt/docvault/docvault

# Create config
if [ ! -f /opt/docvault/.env ]; then
  MASTER_KEY=$(openssl rand -hex 32)
  JWT_SECRET=$(openssl rand -hex 32)
  cat > /opt/docvault/.env << ENVEOF
DOCVAULT_DB_URL=postgres://docvault_app:CHANGE_ME@localhost:5432/docvault?sslmode=disable
DOCVAULT_MASTER_KEY=${MASTER_KEY}
DOCVAULT_JWT_SECRET=${JWT_SECRET}
DOCVAULT_VAULT_PATH=/var/lib/docvault/vault
DOCVAULT_LISTEN_ADDR=:8080
DOCVAULT_OSQUERY_PSK=$(openssl rand -hex 16)
DOCVAULT_SLACK_WEBHOOK=
ENVEOF
  chmod 600 /opt/docvault/.env
  echo "Config created at /opt/docvault/.env — EDIT DATABASE PASSWORD!"
fi

# Install systemd service
cat > /etc/systemd/system/docvault.service << 'SVCEOF'
[Unit]
Description=DocVault Document Security Server
After=postgresql.service network.target
Requires=postgresql.service

[Service]
Type=simple
User=docvault
WorkingDirectory=/opt/docvault
EnvironmentFile=/opt/docvault/.env
ExecStart=/opt/docvault/docvault serve
Restart=always
RestartSec=5
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
SVCEOF

# Set permissions
chown -R docvault:docvault /opt/docvault /var/lib/docvault /var/log/docvault

# Enable and start
systemctl daemon-reload
systemctl enable docvault

echo ""
echo "=== Installation Complete ==="
echo ""
echo "Next steps:"
echo "  1. Edit /opt/docvault/.env (set database password)"
echo "  2. Create database: sudo -u postgres createdb docvault"
echo "  3. Create user:     sudo -u postgres psql -c \"CREATE USER docvault_app WITH PASSWORD 'yourpass';\""
echo "  4. Run migrations:  /opt/docvault/docvault migrate"
echo "  5. Seed admin user: /opt/docvault/docvault seed"
echo "  6. Start server:    sudo systemctl start docvault"
echo "  7. Open browser:    http://YOUR_IP:8080"
echo ""
