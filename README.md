# 🛡️ Amnezia Web Panel

**Web-based management panel for AmneziaVPN** — install and manage VPN protocols on your own servers via SSH from a beautiful, multi-language dashboard.

[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

**Languages:** [🇮🇷 فارسی](README.fa.md) | [🇷🇺 Русский](README.ru.md) | [🇨🇳 中文](README.zh.md) | 🇬🇧 English

---

## ✨ Features

| Protocol | Description |
|---|---|
| 🔒 **AmneziaWG** | WireGuard with DPI-bypass obfuscation — best for Iran/China |
| 🔑 **WireGuard** | Fast modern VPN |
| ⚡ **Xray VLESS Reality** | Mimics HTTPS — hardest to detect, no domain needed |
| 🌊 **VLESS WebSocket** | CDN-friendly WS+TLS |
| 📶 **VLESS gRPC** | CDN-friendly, multiplexed gRPC+TLS |
| 📡 **VMess WebSocket** | Legacy VMess, wide client support |
| 🐴 **Trojan** | Trojan over TLS |
| 🌑 **Shadowsocks 2022** | Lightweight modern obfuscation |
| 🌐 **OpenVPN** | Classic VPN with Docker |

### Panel Features
- 🌍 **4 Languages** — English, فارسی, Русский, 中文
- 📊 **Traffic monitoring** — per-user rx/tx with visual progress bars
- 📅 **Expiry dates** — auto-disable clients on expiry
- 👥 **Bulk user creation** — create 100 users in one click
- 📤 **CSV export** — export client list with usage data
- 🔍 **Amnezia App detection** — finds configs created by Amnezia desktop/mobile app
- ✏️ **Edit users** — name, email, notes, expiry, traffic limit
- 📱 **QR codes** — for easy mobile setup
- 🔄 **Self-update** — update panel from GitHub in one click
- 🔥 **Auto firewall** — opens ports automatically during install
- 📈 **Progress log** — real-time installation progress

---

## 🚀 One-Command Install

Run on a fresh Ubuntu/Debian server:

```bash
bash <(curl -s https://raw.githubusercontent.com/ScannerVpn/Amnezia-Web-Panel/main/install.sh)
```

After installation, credentials are displayed:

```
╔══════════════════════════════════════╗
║    Panel installed successfully! ✅   ║
╚══════════════════════════════════════╝

  Panel URL:   http://YOUR-IP:54325
  Username:    admin
  Password:    xxxxxxxxxxxx
```

---

## 📋 Requirements

**Panel server:**
- Ubuntu 20.04+ or Debian 11+
- 512MB RAM minimum
- Internet access

**VPN servers:**
- Ubuntu 20.04+ or Debian 11+
- Root or sudo SSH access
- Internet access

---

## 🛠️ Manual Install

```bash
git clone https://github.com/ScannerVpn/Amnezia-Web-Panel.git
cd Amnezia-Web-Panel
cp .env.example .env
nano .env          # Set admin password and secret key
docker compose up -d --build
```

---

## 🔄 Update

From the panel Settings page → **Update from GitHub** button.

Or manually:
```bash
cd /opt/amnezia-panel && git pull && docker compose up -d --build
```

---

## 🏪 Reseller Features

This panel is designed for selling VPN access:

- **Traffic limits** — set per-user GB limits with visual progress bars
- **Expiry dates** — auto-disable on date or after N days
- **Bulk create** — generate 5-100 users instantly with prefix + sequential numbers
- **Export CSV** — export all users with usage data for billing
- **Notes & Email** — attach customer info to each user
- **Edit users** — change any field after creation
- **Search** — live search across user table

---

## 📁 Project Structure

```
├── app.py              # FastAPI backend
├── managers/
│   ├── ssh_manager.py
│   ├── awg_manager.py
│   ├── wireguard_manager.py
│   ├── xray_manager.py
│   └── openvpn_manager.py
├── translations/       # en, fa, ru, zh
├── templates/          # Jinja2 HTML
├── static/             # CSS + JS
├── Dockerfile
├── docker-compose.yml
└── install.sh
```

---

## 📄 License

MIT License
