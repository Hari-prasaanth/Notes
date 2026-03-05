```
git add . ; git commit -m "Update scripts" ; git push
```

# PentestMCP — Educational Web Pentest Server

A Kali Linux-based MCP server exposing common web penetration testing tools 
to Claude Desktop. For authorized, educational use only.

---

## ⚠️ Legal Disclaimer

This tool is for **authorized security testing and education only**.  
Only use against systems you own or have explicit written permission to test.  
Unauthorized scanning is illegal in most jurisdictions.

---

## Tools Included

| Tool              | Command       | Purpose                          |
|-------------------|---------------|----------------------------------|
| nmap_scan         | nmap          | Port/service/version detection   |
| nmap_port_scan    | nmap          | Targeted port range scanning     |
| nmap_vuln_scan    | nmap --script | Known CVE detection via scripts  |
| nikto_scan        | nikto         | Web server vulnerability scan    |
| sqlmap_scan       | sqlmap        | SQL injection testing            |
| wpscan_scan       | wpscan        | WordPress vulnerability scanner  |
| dirb_scan         | dirb          | Web directory brute-force        |
| searchsploit_query| searchsploit  | ExploitDB keyword search         |
| searchsploit_cve  | searchsploit  | ExploitDB CVE lookup             |
| dns_lookup        | dig           | DNS A/MX/NS/TXT record lookup    |
| whois_lookup      | whois         | WHOIS domain/IP info             |
| ping_host         | ping          | Host reachability check          |

---

## Prerequisites

- Docker Desktop installed and running
- Claude Desktop installed
- ~4GB disk space for Kali image + tools

---

## Setup

### 1. Build the Docker Image

```bash
# From the directory containing Dockerfile and server.py
docker build -t pentest-mcp:latest .
```

This takes 5–15 minutes on first build (downloads Kali + tools).

### 2. Configure Claude Desktop

Open your Claude Desktop config file:

- **macOS**: `~/Library/Application Support/Claude/claude_desktop_config.json`
- **Windows**: `%APPDATA%\Claude\claude_desktop_config.json`
- **Linux**: `~/.config/Claude/claude_desktop_config.json`

Merge in the contents of `claude_desktop_config.json` from this repo:

```json
{
  "mcpServers": {
    "pentest": {
      "command": "docker",
      "args": [
        "run", "--rm", "-i",
        "--cap-add", "NET_RAW",
        "--cap-add", "NET_ADMIN",
        "--security-opt", "no-new-privileges:true",
        "pentest-mcp:latest"
      ]
    }
  }
}
```

### 3. Restart Claude Desktop

Fully quit and relaunch Claude Desktop. You should see "pentest" in the MCP tools menu.

---

## Usage Examples in Claude

```
Run an nmap scan on 192.168.1.10
```

```
Check for SQL injection vulnerabilities on http://192.168.1.10/login.php
```

```
Run a nikto scan on http://192.168.1.10
```

```
Search for exploits related to "Apache 2.4.49"
```

```
Enumerate WordPress users and plugins at http://192.168.1.10
```

---

## Scanning Your Local Network

By default, Docker runs in bridge network mode — the container can reach IPs on your LAN 
but not hosts that require raw ARP (host discovery on subnets may be limited).

For full LAN scanning (e.g., scanning 192.168.1.0/24), update `docker-compose.yml` to:

```yaml
network_mode: host
```

Or add `--network host` to the args in `claude_desktop_config.json`.

---

## Saving Scan Results

A `./scan-results` volume is mounted into the container at `/home/pentester/results`.
You can redirect output there from inside a tool call, or use the tool output directly 
in Claude's chat.

---

## Rebuilding After Changes

```bash
docker build --no-cache -t pentest-mcp:latest .
```

---

## Security Notes

- Server runs as non-root user `pentester` inside the container
- `no-new-privileges` security option is set
- All inputs are sanitized to block shell injection
- `NET_RAW` and `NET_ADMIN` capabilities are granted only to nmap as needed