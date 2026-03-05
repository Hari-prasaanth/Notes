#!/usr/bin/env python3
"""Pentest MCP Server - Educational security testing tools wrapped with FastMCP."""

import subprocess
import logging
import sys
import re
import os
import shlex

logging.basicConfig(stream=sys.stderr, level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger("pentest-mcp")

from fastmcp import FastMCP

mcp = FastMCP("PentestMCP")

MAX_TIMEOUT = int(os.environ.get("MAX_SCAN_TIMEOUT", "300"))

DANGEROUS_PATTERNS = [";", "&&", "||", "|", "`", "$(",  "$(", ">", "<", "\\n", "\n", "\\r"]

def sanitize_target(target: str) -> str:
    """Sanitize a target hostname/IP to prevent shell injection."""
    target = target.strip()
    for pat in DANGEROUS_PATTERNS:
        if pat in target:
            raise ValueError(f"Dangerous character in target: {pat}")
    if not re.match(r'^[a-zA-Z0-9.\-_:/]+$', target):
        raise ValueError(f"Invalid characters in target: {target}")
    return target

def sanitize_flag(value: str) -> str:
    """Sanitize a simple flag/argument value."""
    value = value.strip()
    for pat in DANGEROUS_PATTERNS:
        if pat in value:
            raise ValueError(f"Dangerous character in argument: {pat}")
    return value

def run_tool(cmd: list, timeout: int = MAX_TIMEOUT) -> str:
    """Run a subprocess command and return combined stdout/stderr."""
    log.info(f"Running: {' '.join(cmd)}")
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout
        )
        output = result.stdout + ("\n[STDERR]\n" + result.stderr if result.stderr.strip() else "")
        return output.strip() if output.strip() else "[No output returned]"
    except subprocess.TimeoutExpired:
        return f"[TIMEOUT] Command exceeded {timeout}s limit: {' '.join(cmd)}"
    except FileNotFoundError:
        return f"[ERROR] Tool not found: {cmd[0]} — is it installed in the container?"
    except Exception as e:
        return f"[ERROR] Unexpected error: {str(e)}"


@mcp.tool()
def nmap_scan(target: str = "", flags: str = "-sV -sC") -> str:
    """Run an nmap scan against a target. Flags default to -sV -sC for version/script detection."""
    if not target:
        return "[ERROR] target is required."
    try:
        target = sanitize_target(target)
        flag_list = shlex.split(sanitize_flag(flags))
    except ValueError as e:
        return f"[ERROR] Input validation failed: {e}"

    cmd = ["nmap"] + flag_list + [target]
    return run_tool(cmd)


@mcp.tool()
def nmap_port_scan(target: str = "", ports: str = "1-1000") -> str:
    """Scan specific ports on a target with nmap. Ports can be a range like 1-65535 or comma-list like 22,80,443."""
    if not target:
        return "[ERROR] target is required."
    try:
        target = sanitize_target(target)
        ports = sanitize_flag(ports)
        if not re.match(r'^[\d,\-]+$', ports):
            return "[ERROR] Invalid port specification. Use format: 22,80,443 or 1-1000"
    except ValueError as e:
        return f"[ERROR] Input validation failed: {e}"

    cmd = ["nmap", "-p", ports, "-sV", target]
    return run_tool(cmd)


@mcp.tool()
def nmap_vuln_scan(target: str = "") -> str:
    """Run nmap vuln scripts against a target to identify known vulnerabilities."""
    if not target:
        return "[ERROR] target is required."
    try:
        target = sanitize_target(target)
    except ValueError as e:
        return f"[ERROR] Input validation failed: {e}"

    cmd = ["nmap", "--script", "vuln", target]
    return run_tool(cmd, timeout=MAX_TIMEOUT)


@mcp.tool()
def nikto_scan(target: str = "", extra_flags: str = "") -> str:
    """Run a nikto web server vulnerability scan against a target URL or host."""
    if not target:
        return "[ERROR] target is required."
    try:
        target = sanitize_target(target)
        extra = shlex.split(sanitize_flag(extra_flags)) if extra_flags else []
    except ValueError as e:
        return f"[ERROR] Input validation failed: {e}"

    cmd = ["nikto", "-h", target] + extra
    return run_tool(cmd)


@mcp.tool()
def sqlmap_scan(url: str = "", data: str = "", extra_flags: str = "") -> str:
    """Run sqlmap to test a URL for SQL injection. Provide POST data with data= param if needed."""
    if not url:
        return "[ERROR] url is required."
    try:
        url = sanitize_target(url)
        extra = shlex.split(sanitize_flag(extra_flags)) if extra_flags else []
    except ValueError as e:
        return f"[ERROR] Input validation failed: {e}"

    cmd = ["sqlmap", "-u", url, "--batch", "--level=2", "--risk=1"]
    if data:
        try:
            data = sanitize_flag(data)
        except ValueError as e:
            return f"[ERROR] Invalid data parameter: {e}"
        cmd += ["--data", data]
    cmd += extra
    return run_tool(cmd)


@mcp.tool()
def wpscan_scan(url: str = "", enumerate: str = "u,vp,vt") -> str:
    """Run WPScan against a WordPress site. enumerate options: u=users, vp=vulnerable plugins, vt=vulnerable themes."""
    if not url:
        return "[ERROR] url is required."
    try:
        url = sanitize_target(url)
        enumerate = sanitize_flag(enumerate)
        if not re.match(r'^[a-z,]+$', enumerate):
            return "[ERROR] Invalid enumerate value. Use: u,vp,vt,ap,at,cb,dbe"
    except ValueError as e:
        return f"[ERROR] Input validation failed: {e}"

    cmd = ["wpscan", "--url", url, "--enumerate", enumerate, "--no-update"]
    return run_tool(cmd)


@mcp.tool()
def dirb_scan(url: str = "", wordlist: str = "/usr/share/dirb/wordlists/common.txt") -> str:
    """Run dirb directory brute-force against a web target. Wordlist path must be on the container."""
    if not url:
        return "[ERROR] url is required."
    try:
        url = sanitize_target(url)
        wordlist = sanitize_flag(wordlist)
        if not re.match(r'^[a-zA-Z0-9/._\-]+$', wordlist):
            return "[ERROR] Invalid wordlist path."
        if not os.path.exists(wordlist):
            return f"[ERROR] Wordlist not found: {wordlist}"
    except ValueError as e:
        return f"[ERROR] Input validation failed: {e}"

    cmd = ["dirb", url, wordlist, "-r"]
    return run_tool(cmd)


@mcp.tool()
def searchsploit_query(query: str = "") -> str:
    """Search ExploitDB via searchsploit for known exploits matching a product or CVE."""
    if not query:
        return "[ERROR] query is required."
    try:
        query = sanitize_flag(query)
    except ValueError as e:
        return f"[ERROR] Input validation failed: {e}"

    cmd = ["searchsploit", query]
    return run_tool(cmd)


@mcp.tool()
def searchsploit_cve(cve: str = "") -> str:
    """Search ExploitDB for a specific CVE identifier like CVE-2021-44228."""
    if not cve:
        return "[ERROR] cve is required."
    try:
        cve = sanitize_flag(cve)
        if not re.match(r'^CVE-\d{4}-\d+$', cve, re.IGNORECASE):
            return "[ERROR] Invalid CVE format. Use: CVE-YYYY-NNNNN"
    except ValueError as e:
        return f"[ERROR] Input validation failed: {e}"

    cmd = ["searchsploit", cve]
    return run_tool(cmd)


@mcp.tool()
def dns_lookup(target: str = "") -> str:
    """Perform DNS lookups (A, MX, NS, TXT records) on a domain using dig and host."""
    if not target:
        return "[ERROR] target is required."
    try:
        target = sanitize_target(target)
    except ValueError as e:
        return f"[ERROR] Input validation failed: {e}"

    results = []
    for rtype in ["A", "MX", "NS", "TXT"]:
        out = run_tool(["dig", "+short", target, rtype], timeout=15)
        results.append(f"[{rtype}]\n{out}")
    return "\n\n".join(results)


@mcp.tool()
def whois_lookup(target: str = "") -> str:
    """Run a whois lookup on a domain or IP address."""
    if not target:
        return "[ERROR] target is required."
    try:
        target = sanitize_target(target)
    except ValueError as e:
        return f"[ERROR] Input validation failed: {e}"

    return run_tool(["whois", target], timeout=30)


@mcp.tool()
def ping_host(target: str = "", count: str = "4") -> str:
    """Ping a host to check reachability. count defaults to 4 packets."""
    if not target:
        return "[ERROR] target is required."
    try:
        target = sanitize_target(target)
        count = sanitize_flag(count)
        if not count.isdigit() or int(count) > 20:
            return "[ERROR] count must be a number between 1 and 20."
    except ValueError as e:
        return f"[ERROR] Input validation failed: {e}"

    return run_tool(["ping", "-c", count, target], timeout=30)


@mcp.tool()
def list_tools() -> str:
    """List all available pentest tools and their descriptions."""
    tools = [
        ("nmap_scan", "Full nmap scan with version/script detection (-sV -sC)"),
        ("nmap_port_scan", "Scan specific ports on a target"),
        ("nmap_vuln_scan", "Run nmap vuln scripts for known CVEs"),
        ("nikto_scan", "Web server vulnerability scanner"),
        ("sqlmap_scan", "SQL injection testing tool"),
        ("wpscan_scan", "WordPress vulnerability scanner"),
        ("dirb_scan", "Web directory brute-force scanner"),
        ("searchsploit_query", "Search ExploitDB for exploits by keyword"),
        ("searchsploit_cve", "Search ExploitDB by CVE ID"),
        ("dns_lookup", "DNS record lookup (A, MX, NS, TXT)"),
        ("whois_lookup", "WHOIS lookup for domain/IP"),
        ("ping_host", "Ping a host for reachability"),
    ]
    lines = ["=== PentestMCP Tools ===\n"]
    for name, desc in tools:
        lines.append(f"  {name:<25} {desc}")
    lines.append("\n[!] For educational/authorized testing only.")
    return "\n".join(lines)


if __name__ == "__main__":
    log.info("Starting PentestMCP server...")
    mcp.run(transport="stdio")