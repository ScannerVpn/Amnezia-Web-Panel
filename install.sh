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
  error "لطفاً با root اجرا کنید: sudo bash install.sh"
fi

INSTALL_DIR="/opt/amnezia-panel"
PANEL_PORT="${PANEL_PORT:-54325}"
REPO="https://github.com/ScannerVpn/Amnezia-Web-Panel"

# Install dependencies
info "نصب وابستگی‌ها..."
apt-get update -qq
apt-get install -y -qq curl git ca-certificates

# Install Docker
if ! command -v docker &>/dev/null; then
  info "نصب Docker..."
  curl -fsSL https://get.docker.com | bash
  systemctl enable docker
  systemctl start docker
  success "Docker نصب شد"
else
  success "Docker از قبل نصب است"
fi

# Install Docker Compose plugin
if ! docker compose version &>/dev/null; then
  info "نصب Docker Compose..."
  apt-get install -y -qq docker-compose-plugin
fi

# Clone or update repo
if [ -d "$INSTALL_DIR/.git" ]; then
  info "به‌روزرسانی پنل..."
  git -C "$INSTALL_DIR" pull --quiet
else
  info "دانلود پنل از GitHub..."
  git clone --quiet "$REPO" "$INSTALL_DIR"
fi

cd "$INSTALL_DIR"

# Create .env if not exists
if [ ! -f ".env" ]; then
  info "ایجاد فایل تنظیمات..."
  ADMIN_PASS=$(cat /dev/urandom | tr -dc 'a-zA-Z0-9' | head -c 16)
  SECRET_KEY=$(cat /dev/urandom | tr -dc 'a-zA-Z0-9' | head -c 64)

  cat > .env <<EOF
ADMIN_USERNAME=admin
ADMIN_PASSWORD=${ADMIN_PASS}
SECRET_KEY=${SECRET_KEY}
PANEL_PORT=${PANEL_PORT}
DATA_DIR=/app/data
EOF
  success "فایل .env ایجاد شد"
else
  ADMIN_PASS=$(grep ADMIN_PASSWORD .env | cut -d= -f2)
  warn "فایل .env از قبل وجود دارد — استفاده از تنظیمات موجود"
fi

# Create data directory
mkdir -p data

# Stop existing container
docker compose down 2>/dev/null || true

# Build and start
info "ساخت و راه‌اندازی پنل..."
docker compose up -d --build

# Wait for container to be healthy
info "منتظر راه‌اندازی پنل..."
for i in $(seq 1 30); do
  if curl -sf "http://localhost:${PANEL_PORT}/login" &>/dev/null; then
    break
  fi
  sleep 2
done

# Get server IP
SERVER_IP=$(curl -s ifconfig.me 2>/dev/null || hostname -I | awk '{print $1}')

echo ""
echo -e "${GREEN}╔══════════════════════════════════════╗${NC}"
echo -e "${GREEN}║       پنل با موفقیت نصب شد! ✅       ║${NC}"
echo -e "${GREEN}╚══════════════════════════════════════╝${NC}"
echo ""
echo -e "  ${CYAN}آدرس پنل:${NC}     http://${SERVER_IP}:${PANEL_PORT}"
echo -e "  ${CYAN}نام کاربری:${NC}   admin"
echo -e "  ${CYAN}رمز عبور:${NC}    ${ADMIN_PASS}"
echo ""
echo -e "  ${YELLOW}⚠️  رمز عبور را در مکان امنی ذخیره کنید${NC}"
echo ""
echo -e "  برای به‌روزرسانی: cd ${INSTALL_DIR} && git pull && docker compose up -d --build"
echo ""
