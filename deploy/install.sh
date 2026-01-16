#!/bin/bash
# Stria DNS Server Installation Script
#
# Usage:
#   sudo ./install.sh
#
# This script:
#   1. Creates stria user and group
#   2. Installs binaries to /usr/local/bin
#   3. Creates configuration directories
#   4. Installs systemd service
#   5. Enables and starts the service

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check if running as root
if [[ $EUID -ne 0 ]]; then
    log_error "This script must be run as root"
    exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

# Check for binaries
STRIA_BIN="${PROJECT_ROOT}/target/release/stria"
STRIA_CTL_BIN="${PROJECT_ROOT}/target/release/stria-ctl"

if [[ ! -f "$STRIA_BIN" ]] || [[ ! -f "$STRIA_CTL_BIN" ]]; then
    log_error "Release binaries not found. Build with: cargo build --release"
    exit 1
fi

log_info "Installing Stria DNS Server..."

# Create stria user and group
if ! id -u stria &>/dev/null; then
    log_info "Creating stria user..."
    useradd -r -s /bin/false -d /var/lib/stria stria
else
    log_info "User stria already exists"
fi

# Install binaries
log_info "Installing binaries..."
install -m 755 "$STRIA_BIN" /usr/local/bin/stria
install -m 755 "$STRIA_CTL_BIN" /usr/local/bin/stria-ctl

# Create directories
log_info "Creating directories..."
mkdir -p /etc/stria
mkdir -p /var/lib/stria
mkdir -p /var/run/stria

# Set permissions
chown -R stria:stria /var/lib/stria
chown -R stria:stria /var/run/stria
chown -R root:stria /etc/stria
chmod 750 /etc/stria

# Install default configuration if not exists
if [[ ! -f /etc/stria/config.yaml ]]; then
    log_info "Installing default configuration..."
    install -m 640 -o root -g stria "${PROJECT_ROOT}/examples/minimal.yaml" /etc/stria/config.yaml
else
    log_warn "Configuration already exists at /etc/stria/config.yaml"
fi

# Install systemd service
log_info "Installing systemd service..."
install -m 644 "${SCRIPT_DIR}/stria.service" /etc/systemd/system/stria.service
systemctl daemon-reload

# Enable service
log_info "Enabling stria service..."
systemctl enable stria

log_info "Installation complete!"
echo ""
echo "Next steps:"
echo "  1. Edit configuration: sudo nano /etc/stria/config.yaml"
echo "  2. Start the service:  sudo systemctl start stria"
echo "  3. Check status:       sudo systemctl status stria"
echo "  4. View logs:          sudo journalctl -u stria -f"
echo ""
echo "Control commands:"
echo "  stria-ctl stats       - Show server statistics"
echo "  stria-ctl cache stats - Show cache statistics"
echo "  stria-ctl block add   - Add block rule"
echo "  stria-ctl allow add   - Add allow rule"
