# ⚔️ KaliAI — Pentesting Intelligence Platform

> An AI-powered pentesting assistant that connects GPT-4o to your Kali Linux machine via a local MCP server, with a live streaming terminal, auto-install, and self-healing agent capabilities. Built for teaching students offensive security.

---

## 📸 What It Does

- 💬 **Chat with GPT-4o** to run any Kali Linux tool using natural language
- 🖥️ **Live terminal panel** streams real command output as it runs
- 📦 **Auto-installs missing tools** via `apt` or `pip` on the fly
- 🔧 **Self-healing agent** — if a tool fails, it fetches docs and retries with corrected flags
- ⏹️ **Stop button** kills both the AI stream and the running process on Kali instantly
- 🔀 **Switch AI models** — GPT-4o, GPT-4o Mini, GPT-4 Turbo, o1, and more
- 🧰 **46 tools** across Recon, Web App, Network, and Utils categories

---

## 🏗️ Architecture

```
[ Browser — index.html ]
        ↕  HTTP / SSE
[ MCP Server — server.js ]   ← runs on your Kali Linux VM/Docker
        ↕  exec / spawn
[ Kali Tools: nmap, nikto, gobuster, sqlmap, hydra... ]

[ Browser ] ←→ [ OpenAI GPT-4o API ]  (direct from browser)
```

The web app is served **by** the MCP server itself at `http://<kali-ip>:3001` — this avoids all CORS and mixed-content issues.

---

## 🚀 Setup

### 1. On Your Kali Linux Machine

```bash
# Create project folder
mkdir -p ~/Desktop/Agent && cd ~/Desktop/Agent

# Install Node.js dependencies
npm init -y
npm install express cors

# Copy server.js and index.html into this folder
# Then start the server
node server.js
```

You should see:
```
🔥  KaliAI MCP Server v3.0  →  http://0.0.0.0:3001
📡  Streaming: SSE enabled on all tool endpoints
🔧  Auto-install: 40+ tools covered
📖  Self-heal docs: GET /docs/<toolname>
```

### 2. Open the Web App

Open your browser and go to:
```
http://localhost:3001
```

Or from another machine on the same network:
```
http://192.168.88.129:3001   ← replace with your Kali IP
```

> ⚠️ **Do NOT open `index.html` directly as a `file://` URL** — the browser will block all API calls due to CORS policy. Always access via `http://`.

### 3. Configure

Click **⚙ Configure** in the top right and enter:

| Field | Value |
|---|---|
| **OpenAI API Key** | Your `sk-proj-...` key from platform.openai.com |
| **Kali MCP Server URL** | `http://localhost:3001` (or your Kali IP) |
| **Default AI Model** | GPT-4o (recommended) |
| **Default Target** | e.g. `172.18.0.4` or `crapi.apisec.ai` |

Click **Save & Connect**. The **MCP Online** and **AI Ready** indicators in the header should both turn green.

---

## 🧰 Available Tools

### 🔭 Recon (15)
| Tool | Description |
|---|---|
| `ping_host` | Check if host is alive |
| `nmap_scan` | Port & service detection |
| `masscan` | Ultra-fast port scanner |
| `arp_scan` | LAN host discovery |
| `netdiscover` | Passive ARP discovery |
| `dns_lookup` | A / MX / NS / TXT records |
| `dnsrecon` | Deep DNS recon & zone transfer |
| `fierce` | DNS subdomain brute-force |
| `sublist3r` | Subdomain OSINT enumeration |
| `theHarvester` | Email & host OSINT |
| `whois_lookup` | Domain registration info |
| `whatweb` | Web tech stack detection |
| `wafw00f` | WAF detection |
| `sslyze` | SSL/TLS configuration analyser |
| `testssl` | Comprehensive TLS checker |

### 🕸️ Web App (15)
| Tool | Description |
|---|---|
| `nikto_scan` | Web vulnerability scanner |
| `gobuster_dir` | Directory brute-force |
| `gobuster_vhost` | Virtual host brute-force |
| `feroxbuster` | Recursive content discovery |
| `ffuf` | Fast web fuzzer |
| `wfuzz` | Parameter & header fuzzer |
| `dirb_scan` | Classic directory brute-force |
| `sqlmap_scan` | SQL injection tester |
| `xsstrike` | Advanced XSS scanner |
| `dalfox` | XSS parameter analyser |
| `commix` | Command injection scanner |
| `nuclei` | Template-based vulnerability scanner |
| `wpscan` | WordPress enumeration |
| `curl_request` | Custom HTTP request |
| `jwt_tool` | JWT token analyser & attacker |

### 🔗 Network (14)
| Tool | Description |
|---|---|
| `enum4linux` | SMB / NetBIOS enumeration |
| `smbmap` | SMB share enumeration |
| `smbclient` | SMB client & share access |
| `nbtscan` | NetBIOS name scanner |
| `crackmapexec` | SMB / LDAP / SSH network sweep |
| `snmpwalk` | SNMP enumeration |
| `onesixtyone` | SNMP community string scanner |
| `smtp_user_enum` | SMTP user enumeration |
| `hydra` | Online password brute-force |
| `medusa` | Modular parallel brute-forcer |
| `ncrack` | Network authentication cracker |
| `responder` | LLMNR / NBT-NS poisoner (analyse mode) |
| `tcpdump` | Packet capture |
| `curl_headers` | Fetch HTTP response headers |

### 🛠️ Utils (2)
| Tool | Description |
|---|---|
| `searchsploit` | Search Exploit-DB |
| `run_command` | Run any custom shell command |

---

## ✨ Features In Detail

### Live Terminal Streaming
Every tool streams its output character-by-character to the terminal panel on the right. Color coding:
- 🟢 Green — stdout (normal output)
- 🔴 Red/Orange — stderr (errors)
- 🟡 Yellow — auto-install in progress
- 🔵 Blue — info / self-healing messages

### Auto-Install
If a tool isn't installed when the AI calls it, the server automatically installs it:
```
📦 'gobuster' not found. Installing...
$ apt-get install -y gobuster
...
✅ gobuster installed successfully.
```
The tool then runs immediately after install — no manual steps needed.

### Self-Healing Agent
If a tool fails due to bad flags or wrong syntax:
1. The agent detects the error pattern (e.g. `unrecognized arguments`)
2. It fetches documentation from `GET /docs/<toolname>`
3. The docs are injected into the GPT conversation
4. GPT re-issues the tool call with corrected parameters
5. The corrected command runs automatically

### Stop Button
Pressing **⏹ Stop** simultaneously:
- Aborts the OpenAI API stream
- Sends `POST /kill` to the MCP server
- Kills the running process **and its entire process group** on Kali with `SIGKILL`
- Works even for long-running tools like `ffuf`, `hydra`, or `nuclei`

---

## 💬 Example Prompts

```
Scan 172.18.0.4 for open ports and explain all findings
Run nikto on http://172.18.0.4 and explain the vulnerabilities
Do a full recon on crapi.apisec.ai — DNS, WHOIS, subdomains, WAF
Run gobuster on http://172.18.0.4 and find hidden directories
Enumerate SMB shares on 172.18.0.4 using enum4linux and smbmap
Test http://crapi.apisec.ai/login for SQL injection
Explain the OWASP API Top 10 with real examples
Search for exploits for vsftpd 2.3.4 and explain how to use them
Run a full nuclei scan on http://172.18.0.4
```

---

## 🔌 API Endpoints

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/` | Serves the web app (index.html) |
| `GET` | `/health` | Server health & tool list |
| `GET` | `/docs/:tool` | Tool usage documentation |
| `POST` | `/tools/:name` | Run a tool (streaming with `?stream=1`) |
| `POST` | `/run` | Run arbitrary command with streaming |
| `POST` | `/kill` | Kill running process by sessionId or all |

All tool endpoints support **SSE streaming** when called with `?stream=1` or `Accept: text/event-stream`.

---

## ⚠️ Security Notes

- The MCP server exposes a `run_command` endpoint — **keep it on your local/lab network only**
- Never expose port `3001` to the internet
- Only scan systems you have **explicit permission** to test
- This tool is designed for **educational use** in a controlled lab environment
- The `responder` tool runs in **analyse mode (`-A`) only** by default — it listens but does not poison

---

## 📁 File Structure

```
~/Desktop/Agent/
├── server.js       ← MCP server (runs on Kali)
├── index.html      ← Web app (served by server.js)
├── package.json
└── node_modules/
```

---

## 🛠️ Troubleshooting

| Problem | Fix |
|---|---|
| MCP shows Offline | Make sure `node server.js` is running and the URL in Config is correct |
| Terminal stays idle | You opened `index.html` as `file://` — access via `http://localhost:3001` instead |
| Tool not found error | The agent auto-installs it — or run `apt-get install -y <tool>` manually |
| OpenAI API error | Check your API key in ⚙ Configure — must start with `sk-` |
| Stop doesn't kill terminal | Make sure you're on the latest `server.js` with the `/kill` endpoint |
| `tool role` OpenAI error | Update to the latest `index.html` — self-healing logic has been fixed |
| SSE stream drops during install | Update to latest `server.js` — heartbeat keepalive now runs during long installs |

---

## 📦 Dependencies

```json
{
  "dependencies": {
    "express": "^4.18.2",
    "cors": "^2.8.5"
  }
}
```

Node.js v18+ recommended.
