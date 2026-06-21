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
apt-get install -y -qq curl git ca-certificates

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
  # Try plugin via apt first (Ubuntu 22.04+ with Docker repo)
  if apt-get install -y -qq docker-compose-plugin 2>/dev/null; then
    success "Docker Compose plugin installed"
    return 0
  fi

  # Fallback: download standalone binary from GitHub
  info "Downloading Docker Compose standalone binary..."
  COMPOSE_VERSION=$(curl -fsSL https://api.github.com/repos/docker/compose/releases/latest \
    | grep '"tag_name"' | sed 's/.*"v\([^"]*\)".*/\1/')
  ARCH=$(uname -m)
  curl -fsSL "https://github.com/docker/compose/releases/download/v${COMPOSE_VERSION}/docker-compose-linux-${ARCH}" \
    -o /usr/local/bin/docker-compose
  chmod +x /usr/local/bin/docker-compose

  # Create shim so "docker compose" (space) works too
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
  ADMIN_PASS=$(cat /dev/urandom | tr -dc 'a-zA-Z0-9' | head -c 16)
  SECRET_KEY=$(cat /dev/urandom | tr -dc 'a-zA-Z0-9' | head -c 64)

  cat > .env <<EOF
ADMIN_USERNAME=admin
ADMIN_PASSWORD=${ADMIN_PASS}
SECRET_KEY=${SECRET_KEY}
PANEL_PORT=${PANEL_PORT}
DATA_DIR=/app/data
EOF
  success ".env file created"
else
  ADMIN_PASS=$(grep ADMIN_PASSWORD .env | cut -d= -f2)
  warn ".env already exists — using existing credentials"
fi

# Create data directory
mkdir -p data

# Stop existing container
docker compose down 2>/dev/null || true

# Build and start
info "Building and starting the panel..."
docker compose up -d --build

# Wait for panel to be ready
info "Waiting for panel to start..."
for i in $(seq 1 30); do
  if curl -sf "http://localhost:${PANEL_PORT}/login" &>/dev/null; then
    break
  fi
  sleep 2
done

# Get server IPv4 address (force -4 to avoid IPv6)
SERVER_IP=$(curl -4 -s --max-time 5 ifconfig.me 2>/dev/null || \
            curl -4 -s --max-time 5 icanhazip.com 2>/dev/null || \
            hostname -I | tr ' ' '\n' | grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$' | grep -v '^127\.' | head -1)

echo ""
echo -e "${GREEN}╔══════════════════════════════════════╗${NC}"
echo -e "${GREEN}║    Panel installed successfully! ✅   ║${NC}"
echo -e "${GREEN}╚══════════════════════════════════════╝${NC}"
echo ""
echo -e "  ${CYAN}Panel URL:${NC}   http://${SERVER_IP}:${PANEL_PORT}"
echo -e "  ${CYAN}Username:${NC}    admin"
echo -e "  ${CYAN}Password:${NC}    ${ADMIN_PASS}"
echo ""
echo -e "  ${YELLOW}WARNING: Save your password in a safe place!${NC}"
echo ""
echo -e "  To update: cd ${INSTALL_DIR} && git pull && docker compose up -d --build"
echo ""
