# 🚀 edgetunnel 2.1
![Dashboard](./img.png)

[![Stars](https://img.shields.io/github/stars/cmliu/edgetunnel?style=flat-square&logo=github)](https://github.com/cmliu/edgetunnel/stargazers)
[![Forks](https://img.shields.io/github/forks/cmliu/edgetunnel?style=flat-square&logo=github)](https://github.com/cmliu/edgetunnel/network/members)
[![License](https://img.shields.io/github/license/cmliu/edgetunnel?style=flat-square)](https://github.com/cmliu/edgetunnel/blob/main/LICENSE)
[![Telegram](https://img.shields.io/badge/Telegram-Group-blue?style=flat-square&logo=telegram)](https://t.me/CMLiussss)
[![YouTube](https://img.shields.io/badge/YouTube-Channel-red?style=flat-square&logo=youtube)](https://www.youtube.com/watch?v=LeT4jQUh8ok)
[![zread](https://img.shields.io/badge/Ask_Zread-_.svg?style=flat-square&color=00b0aa&labelColor=000000&logo=data%3Aimage%2Fsvg%2Bxml%3Bbase64%2CPHN2ZyB3aWR0aD0iMTYiIGhlaWdodD0iMTYiIHZpZXdCb3g9IjAgMCAxNiAxNiIgZmlsbD0ibm9uZSIgeG1sbnM9Imh0dHA6Ly93d3cudzMub3JnLzIwMDAvc3ZnIj4KPHBhdGggZD0iTTQuOTYxNTYgMS42MDAxSDIuMjQxNTZDMS44ODgxIDEuNjAwMSAxLjYwMTU2IDEuODg2NjQgMS42MDE1NiAyLjI0MDFWNC45NjAxQzEuNjAxNTYgNS4zMTM1NiAxLjg4ODEgNS42MDAxIDIuMjQxNTYgNS42MDAxSDQuOTYxNTZDNS4zMTUwMiA1LjYwMDEgNS42MDE1NiA1LjMxMzU2IDUuNjAxNTYgNC45NjAxVjIuMjQwMUM1LjYwMTU2IDEuODg2NjQgNS4zMTUwMiAxLjYwMDEgNC45NjE1NiAxLjYwMDFaIiBmaWxsPSIjZmZmIi8%2BCjxwYXRoIGQ9Ik00Ljk2MTU2IDEwLjM5OTlIMi4yNDE1NkMxLjg4ODEgMTAuMzk5OSAxLjYwMTU2IDEwLjY4NjQgMS42MDE1NiAxMS4wMzk5VjEzLjc1OTlDMS42MDE1NiAxNC4xMTM0IDEuODg4MSAxNC4zOTk5IDIuMjQxNTYgMTQuMzk5OUg0Ljk2MTU2QzUuMzE1MDIgMTQuMzk5OSA1LjYwMTU2IDE0LjExMzQgNS42MDE1NiAxMy43NTk5VjExLjAzOTlDNS42MDE1NiAxMC42ODY0IDUuMzE1MDIgMTAuMzk5OSA0Ljk2MTU2IDEwLjM5OTlaIiBmaWxsPSIjZmZmIi8%2BCjxwYXRoIGQ9Ik0xMy43NTg0IDEuNjAwMUgxMS4wMzg0QzEwLjY4NSAxLjYwMDEgMTAuMzk4NCAxLjg4NjY0IDEwLjM5ODQgMi4yNDAxVjQuOTYwMUMxMC4zOTg0IDUuMzEzNTYgMTAuNjg1IDUuNjAwMSAxMS4wMzg0IDUuNjAwMUgxMy43NTg0QzE0LjExMTkgNS42MDAxIDE0LjM5ODQgNS4zMTM1NiAxNC4zOTg0IDQuOTYwMVYyLjI0MDFDMTQuMzk4NCAxLjg4NjY0IDE0LjExMTkgMS42MDAxIDEzLjc1ODQgMS42MDAxWiIgZmlsbD0iI2ZmZiIvPgo8cGF0aCBkPSJNNCAxMkwxMiA0TDQgMTJaIiBmaWxsPSIjZmZmIi8%2BCjxwYXRoIGQ9Ik00IDEyTDEyIDQiIHN0cm9rZT0iI2ZmZiIgc3Ryb2tlLXdpZHRoPSIxLjUiIHN0cm9rZS1saW5lY2FwPSJyb3VuZCIvPgo8L3N2Zz4K&logoColor=ffffff)](https://zread.ai/cmliu/edgetunnel)
[![Ask DeepWiki](https://deepwiki.com/badge.svg)](https://deepwiki.com/cmliu/edgetunnel)

---

## 📖 Introduction

**edgetunnel** is an edge computing tunnel and proxy decryption solution built on the Cloudflare Workers / Pages platform. It efficiently handles network traffic, offering a robust management dashboard and flexible node configuration capabilities.

- 🖥️ **Live Demo**: [https://EDT-Pages.github.io/admin](https://EDT-Pages.github.io/admin)

### ✨ Core Features

- 🛡️ **Multi-Protocol Support**: Deep integration with VLESS, Trojan, and Shadowsocks protocols, with support for advanced TLS encryption and padding.
- 📊 **Management Dashboard**: Visual web admin panel supporting real-time configuration tuning, live audit logging, and traffic usage metrics.
- 🛠️ **Flexible Deployment**: Native support for Cloudflare Workers as well as Cloudflare Pages (Direct Asset Upload & GitHub CI/CD).
- 🔄 **Subscription Engine**: Automated multi-client subscription generation and subconverter integration (Clash, Sing-box, Surge, Loon, Quantumult X).
- ⚡ **Performance Acceleration**: Supports custom ProxyIP, SOCKS5/HTTP/HTTPS/TURN/SSTP chained proxying, and best IP APIs to minimize latency.
- 🌐 **Cross-Platform Compatibility**: Fully compatible with Windows, Android, iOS, macOS, Linux, and OpenWrt router environments.

---

## 💡 Quick Deployment
>[!TIP]
> 📖 **Illustrated Deployment Guide**: [edgetunnel Setup Tutorial](https://cmliussss.com/p/edt2/)

>[!WARNING]
> ⚠️ **Error 1101 Troubleshooting**: [Video Walkthrough](https://www.youtube.com/watch?v=r4uVTEJptdE)

### ⚙️ Cloudflare Workers Deployment

<details>
<summary><code><strong>「 Step-by-Step Workers Deployment Guide 」</strong></code></summary>

1. **Deploy CF Worker**:
   - Create a new Worker in the Cloudflare Dashboard.
   - Paste the contents of [_worker.js](https://github.com/cmliu/edgetunnel/blob/main/_worker.js) into the Worker script editor.
   - In the left sidebar, navigate to `Settings` > `Variables and Secrets` > `Add`.
   - Set the variable name to **ADMIN**, and set its value to your administrator password, then click `Save and Deploy`.

2. **Bind KV Namespace**:
   - In the `Settings` > `Bindings` tab, click `Add` > `KV Namespace`.
   - Set the variable name to **KV**, then choose an existing namespace or create a new one to bind, then click `Save`.

3. **Bind Custom Domain**:
   - In the Worker console under the `Triggers` tab, scroll down and click `Add Custom Domain`.
   - Enter your subdomain managed on Cloudflare DNS (e.g. `vless.example.com`), click `Add Custom Domain`, and wait for the SSL certificate to provision.

4. **Access Admin Panel**:
   - Navigate to `https://vless.example.com/admin` and enter your `ADMIN` password to log in.

</details>

### 🛠 Cloudflare Pages Direct Upload (Recommended) [Tutorial](https://cmliussss.com/p/edt2/)

<details>
<summary><code><strong>「 Step-by-Step Pages Direct Upload Guide 」</strong></code></summary>

1. **Deploy CF Pages**:
   - Download the repository [main.zip](https://github.com/cmliu/edgetunnel/archive/refs/heads/main.zip) archive (and please leave a Star!).
   - In Cloudflare Pages dashboard, select `Upload assets`, choose a project name, and click `Create project`. Upload `main.zip` and click `Deploy site`.
   - Once deployed, click `Continue to project`, then navigate to `Settings` > `Environment variables` > **Production** > `Add variable`.
   - Set the variable name to **ADMIN**, set the value to your administrator password, then click `Save`.
   - Return to the `Deployments` tab, click `Create new deployment` at the bottom right, re-upload `main.zip`, and click `Save and Deploy`.

2. **Bind KV Namespace**:
   - Under `Settings` > `Bindings`, click `+ Add` > `KV Namespace`, select or create a namespace.
   - Set the variable name to **KV**, click `Save`, and redeploy.

3. **Bind Custom CNAME Domain**: [Video Tutorial](https://www.youtube.com/watch?v=LeT4jQUh8ok&t=851s)
   - In the Pages dashboard under `Custom domains`, click `Set up a custom domain`.
   - Enter your subdomain (e.g., `lizi.example.com`). Do not use your root domain.
   - In your DNS provider, add a CNAME record pointing `lizi` to `your-project.pages.dev`, then click `Activate domain`.

4. **Access Admin Panel**:
   - Visit `https://lizi.example.com/admin` and enter your `ADMIN` password to log in.

</details>

### 🛠 Cloudflare Pages + GitHub Deployment

<details>
<summary><code><strong>「 Step-by-Step Pages + GitHub Guide 」</strong></code></summary>

1. **Deploy CF Pages**:
   - Fork this repository on GitHub (and leave a Star!).
   - In Cloudflare Pages dashboard, click `Connect to Git`, select the `edgetunnel` repository, and click `Begin setup`.
   - On the `Set up builds and deployments` page, expand `Environment variables (advanced)` and click `Add variable`.
   - Set variable name to **ADMIN** with your password, then click `Save and Deploy`.

2. **Bind KV Namespace**:
   - Navigate to `Settings` > `Bindings` > `+ Add` > `KV Namespace`.
   - Set variable name to **KV**, select a namespace, and save.

3. **Bind Custom Domain**: [Video Tutorial](https://www.youtube.com/watch?v=LeT4jQUh8ok&t=851s)
   - In the `Custom domains` tab, click `Set up a custom domain`.
   - Add your subdomain (e.g. `lizi.example.com`), configure the CNAME record to point to `your-project.pages.dev`, and activate.

4. **Access Admin Panel**:
   - Visit `https://lizi.example.com/admin` and log in with your `ADMIN` password.

</details>

---

## 🔑 Environment Variables Reference

| Variable Name | Required | Example | Description |
| :--- | :---: | :--- | :--- |
| **ADMIN** | ✅ | `123456` | Dashboard login password |
| **KEY** | ❌ | `CMLiussss` | Quick subscription secret path key. Accessing `/{KEY}` immediately fetches nodes |
| **UUID** | ❌ | `90cd4a77-141a-43c9-991b-08263cfe9c10` | Static UUID override (must be standard **UUIDv4** format) |
| **PROXYIP** | ❌ | `proxyip.cmliussss.net:443` | Custom global reverse proxy IP / SNI target |
| **URL** | ❌ | `https://cloudflare-error-page-3th.pages.dev` | Default homepage camouflage URL (or set to `1101` for native error page) |
| **GO2SOCKS5** | ❌ | `blog.cmliussss.com`,`*.ip111.cn`,`*google.com` | Whitelist domains forced through SOCKS5 (`*` for global, comma-separated) |
| **DEBUG** | ❌ | `1` or `true` | **Developer Mode**: enables verbose console debug logging (disabled by default) |
| **OFF_LOG** | ❌ | `1` or `true` | Disables audit logging to KV storage (logging enabled by default) |
| **BEST_SUB** | ❌ | `1` or `true` | Enables acting as a **preferred subscription generator** backend (disabled by default) |
| **PRELOAD_RACE_DIAL** | ❌ | `1` or `true` | Enables **DNS preload racing dials** for direct connections (disabled by default) |
| **TCP_CONCURRENT_DIAL** | ❌ | `2` | **Concurrent TCP dial count** (default: `2`). Disables automatic fallback on CMCC networks |
| **PROXY_CONCURRENT_DIAL** | ❌ | `1` | **Concurrent proxy dial count** (default: `1`). Higher values accelerate dials but change exit IPs |

---

## 🔧 Advanced Routing & URL Parameters

If you need to customize the **Subscription Token** and **Client Node UUID**:
1. Changing the `ADMIN` or `KEY` variable value will deterministically derive a new subscription `token` and node `UUID`.
2. Setting the `UUID` variable explicitly locks the user identification UUID (must follow standard **UUIDv4** format).

Dynamic underlying proxy switching via **URL Path / Query**:

- **Custom ProxyIP**:
   ```url
   /proxyip=proxyip.cmliussss.net
   /?proxyip=proxyip.cmliussss.net
   ```

- **Custom SOCKS5 Proxy**:
   ```url
   /socks5=user:password@127.0.0.1:1080
   /?socks5=user:password@127.0.0.1:1080
   /socks://dXNlcjpwYXNzd29yZA==@127.0.0.1:1080 (activates global SOCKS5)
   /socks5://user:password@127.0.0.1:1080 (activates global SOCKS5)
   ```

- **Custom HTTP Proxy**:
   ```url
   /http=user:password@127.0.0.1:1080
   /http://user:password@127.0.0.1:8080 (activates global HTTP proxy)
   ```

- **Trojan Fallback**: (For self-hosted backends with Trojan inbound; fallback server must use the same password without WebSocket or TLS. UDP is passed transparently to the fallback service for optimal performance)
   ```url
   /trojan=1.1.1.1:1234
   ```

---

## 💻 Recommended Client Apps

| Platform | Recommended Clients |
| :--- | :--- |
| **Windows** | [v2rayN](https://github.com/2dust/v2rayN/releases), [Hiddify](https://github.com/hiddify/hiddify-app/releases), [FlClash](https://github.com/chen08209/FlClash/releases), [mihomo-party](https://github.com/mihomo-party-org/clash-party/releases), [Clash Verge Rev](https://github.com/clash-verge-rev/clash-verge-rev/releases), [Clashmi](https://github.com/KaringX/clashmi/releases), [FlyClash](https://github.com/GtxFury/FlyClash/releases), [Karing](https://github.com/KaringX/karing/releases), [Bettbox](https://github.com/appshubcc/Bettbox/releases) |
| **Android** | [v2rayNG](https://github.com/2dust/v2rayNG/releases), [ClashMetaForAndroid](https://github.com/MetaCubeX/ClashMetaForAndroid/releases/), [FlClash](https://github.com/chen08209/FlClash/releases), [Clashmi](https://github.com/KaringX/clashmi/releases), [Hiddify](https://github.com/hiddify/hiddify-app/releases), [NekoBox](https://github.com/MatsuriDayo/NekoBoxForAndroid/releases), [FlyClash](https://github.com/GtxFury/FlyClash/releases), [Karing](https://github.com/KaringX/karing/releases), [Bettbox](https://github.com/appshubcc/Bettbox/releases) |
| **iOS** | Surge, Shadowrocket, Stash, [Hiddify](https://github.com/hiddify/hiddify-app/releases), Loon, Egern, [Clashmi](https://clashmi.app/download), [Karing](https://karing.app/), Quantumult X |
| **macOS** | [FlClash](https://github.com/chen08209/FlClash/releases), [mihomo-party](https://github.com/mihomo-party-org/clash-party/releases), [Clash Verge Rev](https://github.com/clash-verge-rev/clash-verge-rev/releases), Surge, [Clashmi](https://clashmi.app/download), [Karing](https://karing.app/), [FlyClash](https://github.com/GtxFury/FlyClash/releases) |
| **HarmonyOS** | [ClashBox](https://github.com/xiaobaigroup/ClashBox/releases) |

---

## ⭐ Project Stargazers

![Stargazers over time](https://github.com/cmliu/cmliu/blob/main/star/edgetunnel.svg)

---

## 🙏 Special Thanks & Credits
### 💖 Infrastructure Sponsorship - Cloud servers for maintaining [Subscription Converter Services](https://sub.cmliussss.net/)
- [Yuusei Network](https://yuusei.io/)
- [VMRack](https://www.vmrack.net?ref_code=5Zk7eNhbgL7)

### 🛠 Open Source References & Upstream Projects
- [zizifn/edgetunnel](https://github.com/zizifn/edgetunnel)
- [3Kmfi6HP/EDtunnel](https://github.com/6Kmfi6HP/EDtunnel)
- [SHIJS1999/cloudflare-worker-vless-ip](https://github.com/SHIJS1999/cloudflare-worker-vless-ip)
- [Stanley-baby](https://github.com/Stanley-baby)
- [ACL4SSR](https://github.com/ACL4SSR/ACL4SSR/tree/master/Clash/config)
- [股神](https://t.me/CF_NAT/38889)
- [Workers/Pages Metrics](https://t.me/zhetengsha/3382)
- [白嫖哥](https://t.me/bestcfipas)
- [Mingyu](https://github.com/ymyuuu/workers-vless)
- [ToiCF/CF-Workers-HTTPS](https://github.com/ToiCF/CF-Workers-HTTPS)
- [ToiCF/CF-Workers-TURN](https://github.com/ToiCF/CF-Workers-TURN)
- [ToiCF/CF-Workers-SoftEther](https://github.com/ToiCF/CF-Workers-SoftEther)
- [eooce](https://github.com/eooce/Cloudflare-proxy)
- [Sukka](https://ip.skk.moe/)
- [zhangtaile](https://github.com/cmliu/edgetunnel/pull/999)
- [1345695](https://github.com/1345695/edcloudwasm)
- [ToiCF/GrainTCP](https://github.com/ToiCF/GrainTCP)
- [xream](https://github.com/cmliu/edgetunnel/pull/1359)

---

## ⚠️ Disclaimer

1. This project ("edgetunnel") is provided exclusively for **educational, scientific research, and authorized personal security testing** purposes.
2. Users downloading or utilizing this codebase must strictly adhere to the laws and regulations of their jurisdiction.
3. The authors and contributors assume no responsibility or liability for any actions, consequences, or damages resulting from the misuse of this software.
4. Testing deployments should be dismantled within 24 hours of concluding evaluation.

---

**If you find this project helpful, please consider leaving a Star 🌟 — it is greatly appreciated!**
