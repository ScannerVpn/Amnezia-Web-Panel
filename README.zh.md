# 🛡️ Amnezia Web Panel

**AmneziaVPN 网页管理面板** — 通过SSH在您自己的服务器上安装和管理VPN协议。

**语言：** [🇮🇷 فارسی](README.fa.md) | [🇷🇺 Русский](README.ru.md) | 🇨🇳 中文 | [🇬🇧 English](README.md)

---

## ✨ 功能特性

| 协议 | 说明 |
|---|---|
| 🔒 **AmneziaWG** | 带DPI绕过混淆的WireGuard — 最适合中国/伊朗 |
| 🔑 **WireGuard** | 快速现代VPN |
| ⚡ **Xray VLESS Reality** | 伪装HTTPS流量，无需域名 |
| 🌊 **VLESS WebSocket** | CDN兼容，WS+TLS |
| 📶 **VLESS gRPC** | CDN兼容，gRPC多路复用 |
| 📡 **VMess WebSocket** | 广泛客户端支持 |
| 🐴 **Trojan** | TLS上的Trojan协议 |
| 🌑 **Shadowsocks 2022** | 轻量级现代混淆 |
| 🌐 **OpenVPN** | 经典VPN协议 |

### 面板功能
- 🌍 **4种语言** — English、فارسی、Русский、中文
- 📊 **流量监控** — 每用户的上传/下载统计
- 📅 **到期日期** — 到期自动禁用
- 👥 **批量创建** — 一键创建100个用户
- 📤 **导出CSV** — 用于计费和报告
- 🔍 **检测Amnezia配置** — 发现Amnezia App创建的配置
- ✏️ **编辑用户** — 名称、邮箱、备注、到期、流量限制
- 📱 **二维码** — 方便移动端导入
- 🔄 **自动更新** — 一键从GitHub更新
- 🔥 **自动开放端口** — 安装协议时自动配置防火墙

---

## 🚀 一键安装

在Ubuntu/Debian服务器上运行：

```bash
bash <(curl -s https://raw.githubusercontent.com/ScannerVpn/Amnezia-Web-Panel/main/install.sh)
```

安装完成后显示登录信息：

```
╔══════════════════════════════════════╗
║    Panel installed successfully! ✅   ║
╚══════════════════════════════════════╝

  Panel URL:   http://YOUR-IP:54325
  Username:    admin
  Password:    xxxxxxxxxxxx
```

---

## 📋 系统要求

**面板服务器：** Ubuntu 20.04+ 或 Debian 11+，512MB内存，网络连接。

**VPN服务器：** Ubuntu 20.04+ 或 Debian 11+，SSH root/sudo权限，网络连接。

---

## 🏪 经销商功能

- **流量限制** — 每用户GB限额，带可视化进度条
- **到期日期** — 指定日期自动禁用
- **批量创建** — 5-100个用户，带前缀和序号
- **导出CSV** — 所有用户及使用数据
- **备注和邮箱** — 每个用户的客户信息
- **搜索** — 用户表实时搜索

---

## 🔄 更新

面板设置页面 → **Update from GitHub** 按钮。

或手动更新：
```bash
cd /opt/amnezia-panel && git pull && docker compose up -d --build
```
