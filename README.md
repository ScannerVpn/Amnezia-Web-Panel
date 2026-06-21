# 🛡️ Amnezia Web Panel

پنل مدیریت تحت وب برای AmneziaVPN — نصب و مدیریت کامل پروتکل‌های VPN روی سرور شخصی

[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

## ✨ امکانات

- 🔒 **AmneziaWG** — WireGuard با obfuscation ضد فیلتر (مناسب ایران)
- 🔑 **WireGuard** — پروتکل سریع و مدرن
- ⚡ **Xray XTLS-Reality** — تقلید ترافیک HTTPS، دشوارترین تشخیص
- 🌐 **OpenVPN** — پشتیبانی گسترده
- 📊 نمایش مصرف ترافیک هر کاربر به صورت real-time
- 📱 تولید QR Code برای موبایل
- 🔍 شناسایی کانفیگ‌های ساخته‌شده توسط برنامه Amnezia
- 👥 مدیریت کاربران با محدودیت ترافیک
- 🖥️ مدیریت چند سرور از یک پنل

## 🚀 نصب سریع

روی سرور Ubuntu/Debian اجرا کنید:

```bash
bash <(curl -s https://raw.githubusercontent.com/ScannerVpn/Amnezia-Web-Panel/main/install.sh)
```

بعد از نصب، اطلاعات ورود نمایش داده می‌شود:

```
╔══════════════════════════════════════╗
║       پنل با موفقیت نصب شد! ✅       ║
╚══════════════════════════════════════╝

  آدرس پنل:     http://YOUR-IP:54325
  نام کاربری:   admin
  رمز عبور:    xxxxxxxxxxxx
```

## 📋 پیش‌نیازها

سرور پنل:
- Ubuntu 20.04+ یا Debian 11+
- 512MB RAM حداقل
- اتصال به اینترنت

سرورهای VPN:
- Ubuntu 20.04+ یا Debian 11+
- دسترسی SSH با root یا sudo
- اتصال به اینترنت

## 🛠️ نصب دستی

```bash
git clone https://github.com/ScannerVpn/Amnezia-Web-Panel.git
cd Amnezia-Web-Panel

# کپی و ویرایش تنظیمات
cp .env.example .env
nano .env

# اجرا با Docker
docker compose up -d --build
```

## 🔄 به‌روزرسانی

```bash
cd /opt/amnezia-panel
git pull
docker compose up -d --build
```

## 📁 ساختار پروژه

```
├── app.py              # FastAPI — منطق اصلی
├── managers/
│   ├── ssh_manager.py      # اتصال SSH
│   ├── awg_manager.py      # AmneziaWG (Docker)
│   ├── wireguard_manager.py # WireGuard
│   ├── xray_manager.py     # Xray Reality
│   └── openvpn_manager.py  # OpenVPN
├── templates/          # قالب‌های HTML
├── static/             # CSS و JS
├── Dockerfile
├── docker-compose.yml
└── install.sh          # نصاب خودکار
```

## 🔒 امنیت

- رمزهای SSH با base64 در دیتابیس ذخیره می‌شوند (برای production از رمزنگاری قوی‌تر استفاده کنید)
- Session-based auth با bcrypt
- پنل را پشت Nginx قرار دهید و HTTPS فعال کنید

## 📄 لایسنس

MIT License
