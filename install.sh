#!/bin/bash
# Amnezia Web Panel — One-Command Installer
# Usage: bash <(curl -s https://raw.githubusercontent.com/ScannerVpn/Amnezia-Web-Panel/main/install.sh)

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
CYAN='\033[0;36m'
YELLOW='\033[1;33m'
NC='\033[0m'

info()    { echo -e "${CYAN}[INFO]${NC} $1"; }
success() { echo -e "${GREEN}[OK]${NC} $1"; }
warn()    { echo -e "${YELLOW}[WARN]${NC} $1"; }
error()   { echo -e "${RED}[ERROR]${NC} $1"; exit 1; }

echo ""
echo -e "${CYAN}╔══════════════════════════════════════╗${NC}"
echo -e "${CYAN}║       Amnezia Web Panel Installer    ║${NC}"
echo -e "${CYAN}╚══════════════════════════════════════╝${NC}"
echo ""

# Check root
if [ "$EUID" -ne 0 ]; then
  error "Please run as root: sudo bash install.sh"
fi

INSTALL_DIR="/opt/amnezia-panel"
PANEL_PORT="${PANEL_PORT:-54325}"
REPO="https://github.com/ScannerVpn/Amnezia-Web-Panel"

# Install base dependencies
info "Installing dependencies..."
apt-get update -qq
apt-get install -y -qq curl git ca-certificates openssl

# Install Docker
if ! command -v docker &>/dev/null; then
  info "Installing Docker..."
  curl -fsSL https://get.docker.com | bash
  systemctl enable docker
  systemctl start docker
  success "Docker installed"
else
  success "Docker already installed"
fi

# Install Docker Compose (plugin or standalone fallback)
install_compose() {
  if apt-get install -y -qq docker-compose-plugin 2>/dev/null; then
    success "Docker Compose plugin installed"
    return 0
  fi
  info "Downloading Docker Compose standalone binary..."
  COMPOSE_VERSION=$(curl -fsSL https://api.github.com/repos/docker/compose/releases/latest \
    | grep '"tag_name"' | sed 's/.*"v\([^"]*\)".*/\1/')
  ARCH=$(uname -m)
  curl -fsSL "https://github.com/docker/compose/releases/download/v${COMPOSE_VERSION}/docker-compose-linux-${ARCH}" \
    -o /usr/local/bin/docker-compose
  chmod +x /usr/local/bin/docker-compose
  mkdir -p /usr/local/lib/docker/cli-plugins
  ln -sf /usr/local/bin/docker-compose /usr/local/lib/docker/cli-plugins/docker-compose
  success "Docker Compose ${COMPOSE_VERSION} installed"
}

if ! docker compose version &>/dev/null 2>&1; then
  info "Installing Docker Compose..."
  install_compose
else
  success "Docker Compose already available"
fi

# Clone or update repo
if [ -d "$INSTALL_DIR/.git" ]; then
  info "Updating panel from GitHub..."
  git -C "$INSTALL_DIR" pull --quiet
else
  info "Cloning panel from GitHub..."
  git clone --quiet "$REPO" "$INSTALL_DIR"
fi

cd "$INSTALL_DIR"

# Create .env if not exists
if [ ! -f ".env" ]; then
  info "Generating configuration..."
  ADMIN_PASS=$(openssl rand -base64 12 | tr -d '/+=' | head -c 16)
  SECRET_KEY=$(openssl rand -hex 32)

  cat > .env <<EOF
ADMIN_USERNAME=admin
ADMIN_PASSWORD=${ADMIN_PASS}
SECRET_KEY=${SECRET_KEY}
PANEL_PORT=${PANEL_PORT}
DATA_DIR=/app/data
# Set to 1 to run git pull automatically on each container start
UPDATE_ON_START=0
EOF
  chmod 600 .env
  success ".env file created (mode 600)"
else
  ADMIN_PASS=$(grep ADMIN_PASSWORD .env | cut -d= -f2)
  warn ".env already exists — using existing credentials"
fi

# Create data directory
mkdir -p data
chmod 700 data

# ── Open firewall port ────────────────────────────────────────────────────────
open_port() {
  local port=$1
  info "Opening port ${port}/tcp in firewall..."
  # ufw
  if command -v ufw &>/dev/null; then
    ufw allow "${port}/tcp" 2>/dev/null && success "ufw: port ${port}/tcp allowed" || true
  fi
  # firewalld
  if command -v firewall-cmd &>/dev/null && systemctl is-active --quiet firewalld 2>/dev/null; then
    firewall-cmd --permanent --add-port="${port}/tcp" 2>/dev/null && \
    firewall-cmd --reload 2>/dev/null && \
    success "firewalld: port ${port}/tcp allowed" || true
  fi
  # iptables fallback
  if command -v iptables &>/dev/null; then
    iptables -C INPUT -p tcp --dport "${port}" -j ACCEPT 2>/dev/null || \
      iptables -I INPUT -p tcp --dport "${port}" -j ACCEPT 2>/dev/null || true
    # Persist iptables rules
    if command -v iptables-save &>/dev/null; then
      mkdir -p /etc/iptables
      iptables-save > /etc/iptables/rules.v4 2>/dev/null || true
      success "iptables: port ${port}/tcp allowed (persisted)"
    fi
  fi
}

open_port "${PANEL_PORT}"

# Stop existing container
docker compose down 2>/dev/null || true

# Build and start
info "Building and starting the panel..."
docker compose up -d --build

# Wait for panel to be ready
info "Waiting for panel to start..."
READY=0
for i in $(seq 1 30); do
  if curl -sf "http://localhost:${PANEL_PORT}/login" &>/dev/null; then
    READY=1
    break
  fi
  sleep 2
done

if [ "$READY" -eq 0 ]; then
  warn "Panel did not respond on port ${PANEL_PORT} within 60s."
  warn "Check logs with: docker compose -f ${INSTALL_DIR}/docker-compose.yml logs"
fi

# Get server IPv4 address (force -4 to avoid IPv6)
SERVER_IP=$(curl -4 -s --max-time 5 ifconfig.me 2>/dev/null || \
            curl -4 -s --max-time 5 icanhazip.com 2>/dev/null || \
            hostname -I | tr ' ' '\n' | grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$' | grep -v '^127\.' | head -1)

# Save credentials to a file (mode 600) instead of just printing to terminal
CREDS_FILE="$INSTALL_DIR/.panel-credentials"
cat > "$CREDS_FILE" <<EOF
Amnezia Web Panel — Initial Credentials
========================================
Panel URL:   http://${SERVER_IP}:${PANEL_PORT}
Username:    admin
Password:    ${ADMIN_PASS}

Generated: $(date -u +"%Y-%m-%dT%H:%M:%SZ")
========================================
EOF
chmod 600 "$CREDS_FILE"

# ── Create update helper script ───────────────────────────────────────────────
cat > /usr/local/bin/amnezia-update <<'UPDATESCRIPT'
#!/bin/bash
# Amnezia Web Panel — update helper
# Usage: amnezia-update
set -e
INSTALL_DIR="/opt/amnezia-panel"
cd "$INSTALL_DIR"
echo "[update] Pulling latest code from GitHub..."
git pull
echo "[update] Rebuilding and restarting container..."
docker compose up -d --build
echo "[update] Done. Panel is running."
UPDATESCRIPT
chmod +x /usr/local/bin/amnezia-update
success "Update helper installed: run 'amnezia-update' anytime to update"

echo ""
echo -e "${GREEN}╔══════════════════════════════════════╗${NC}"
echo -e "${GREEN}║    Panel installed successfully! ✅   ║${NC}"
echo -e "${GREEN}╚══════════════════════════════════════╝${NC}"
echo ""
echo -e "  ${CYAN}Panel URL:${NC}   http://${SERVER_IP}:${PANEL_PORT}"
echo -e "  ${CYAN}Username:${NC}    admin"
echo -e "  ${CYAN}Password:${NC}    (saved to ${CREDS_FILE})"
echo ""
echo -e "  ${YELLOW}⚠  Credentials saved to:${NC} ${CREDS_FILE}"
echo -e "  ${YELLOW}   View with: sudo cat ${CREDS_FILE}${NC}"
echo -e "  ${YELLOW}   Delete after recording: sudo rm ${CREDS_FILE}${NC}"
echo ""
echo -e "  ${CYAN}To update the panel:${NC} amnezia-update"
echo -e "  ${CYAN}To view logs:${NC}        docker compose -f ${INSTALL_DIR}/docker-compose.yml logs -f"
echo ""
