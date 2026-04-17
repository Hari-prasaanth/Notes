/**
 * KaliAI MCP Server v3.1 — FIXED
 *
 * Fixes applied:
 *  1. CORS headers added to every SSE response (was missing → NetworkError)
 *  2. SSE responses flush immediately (res.flushHeaders)
 *  3. spawn uses {detached:true, stdio:['ignore','pipe','pipe']} for reliable kill
 *  4. Kill broadcasts SSE event to all active streams so terminal reacts
 *  5. Terminal prompt ($) injected as "prompt" event after every command
 *  6. Sudo password check improved — won't shell-inject on special chars
 *  7. /tools/masscan + nmap_scan flag "needs_root" so UI can prompt creds
 *  8. process.kill(-pid) guarded with fallback to proc.kill()
 *
 * Run: npm install && node server.js
 */

const express = require("express");
const cors    = require("cors");
const { exec, spawn } = require("child_process");
const path    = require("path");
const fs      = require("fs");

const app  = express();
const PORT = process.env.PORT || 3001;

// ─── CORS — must be BEFORE all routes ─────────────────────────────────────
app.use(cors({
  origin: "*",
  methods: ["GET", "POST", "OPTIONS"],
  allowedHeaders: ["Content-Type", "Accept", "Cache-Control"],
}));
app.options("*", cors()); // pre-flight for all routes

app.use(express.json());

// ─── Sanitise ──────────────────────────────────────────────────────────────
// Strip shell metacharacters — keeps alphanumeric, dots, slashes, dashes,
// colons, spaces, @, =, commas, brackets, underscores, quotes (handled separately)
function s(v) {
  return String(v || "").replace(/[`$;&|><\n\r\0]/g, "");
}

// Safe quote: wraps in single quotes after escaping internal single quotes
function sq(v) {
  return "'" + String(v || "").replace(/'/g, "'\\''") + "'";
}

// ─── Tool install map ──────────────────────────────────────────────────────
const INSTALL = {
  nmap:             "apt-get install -y nmap",
  masscan:          "apt-get install -y masscan",
  "arp-scan":       "apt-get install -y arp-scan",
  netdiscover:      "apt-get install -y netdiscover",
  dnsrecon:         "pip3 install dnsrecon --break-system-packages",
  fierce:           "pip3 install fierce --break-system-packages",
  sublist3r:        "apt-get install -y sublist3r",
  theharvester:     "apt-get install -y theharvester",
  whatweb:          "apt-get install -y whatweb",
  wafw00f:          "pip3 install wafw00f --break-system-packages",
  sslyze:           "pip3 install sslyze --break-system-packages",
  "testssl.sh":     "apt-get install -y testssl.sh",
  nikto:            "apt-get install -y nikto",
  gobuster:         "apt-get install -y gobuster",
  feroxbuster:      "apt-get install -y feroxbuster",
  ffuf:             "apt-get install -y ffuf",
  wfuzz:            "apt-get install -y wfuzz",
  dirb:             "apt-get install -y dirb",
  sqlmap:           "apt-get install -y sqlmap",
  xsstrike:         "apt-get install -y xsstrike 2>/dev/null; which xsstrike || (git clone https://github.com/s0md3v/XSStrike /opt/XSStrike --depth 1 2>/dev/null; pip3 install -r /opt/XSStrike/requirements.txt --break-system-packages 2>/dev/null); true",
  dalfox:           "apt-get install -y dalfox",
  commix:           "apt-get install -y commix",
  nuclei:           "apt-get install -y nuclei",
  wpscan:           "apt-get install -y wpscan",
  enum4linux:       "apt-get install -y enum4linux",
  smbmap:           "apt-get install -y smbmap",
  smbclient:        "apt-get install -y smbclient",
  nbtscan:          "apt-get install -y nbtscan",
  crackmapexec:     "apt-get install -y crackmapexec",
  snmpwalk:         "apt-get install -y snmp",
  onesixtyone:      "apt-get install -y onesixtyone",
  "smtp-user-enum": "apt-get install -y smtp-user-enum",
  hydra:            "apt-get install -y hydra",
  medusa:           "apt-get install -y medusa",
  ncrack:           "apt-get install -y ncrack",
  responder:        "apt-get install -y responder",
  tcpdump:          "apt-get install -y tcpdump",
  searchsploit:     "apt-get install -y exploitdb",
  metasploit:       "apt-get install -y metasploit-framework",
  ftp:              "apt-get install -y ftp",
  "ftp-ssl":        "apt-get install -y ftp-ssl",
  telnet:           "apt-get install -y telnet",
  openssl:          "apt-get install -y openssl",
  mysql:            "apt-get install -y default-mysql-client",
  redis:            "apt-get install -y redis-tools",
  mongo:            "apt-get install -y mongodb-clients 2>/dev/null; apt-get install -y mongosh 2>/dev/null; true",
  rpcclient:        "apt-get install -y samba-common-bin",
  ldapsearch:       "apt-get install -y ldap-utils",
  impacket:         "pip3 install impacket --break-system-packages",
};

// ─── Tools that need root ──────────────────────────────────────────────────
// On Kali Linux the server typically runs as root already.
// We only block if we're NOT root AND no sudo password is set.
const NEEDS_ROOT = new Set(["masscan","arp-scan","netdiscover","tcpdump","responder","ncrack"]);
// Note: nmap removed from NEEDS_ROOT — nmap works without root for TCP connect scans (-sT)

async function isRunningAsRoot() {
  return new Promise(resolve => {
    exec("id -u", (err, stdout) => resolve(!err && stdout.trim() === "0"));
  });
}

// ─── Tool docs (for self-healing) ─────────────────────────────────────────
const TOOL_DOCS = {
  nmap:         "nmap [flags] <target>. Common: -sT (TCP connect), -sV (version), -sC (scripts), -p- (all ports), -T4 (fast), -A (aggressive). Ex: nmap -sV -sC -p 1-1000 192.168.1.1",
  nikto:        "nikto -h <host> [-p port] [-ssl] [-id user:pass]. Ex: nikto -h http://192.168.1.1 -p 80",
  gobuster:     "gobuster dir -u <url> -w <wordlist> [-t threads] [-x extensions]. Ex: gobuster dir -u http://site.com -w /usr/share/wordlists/dirb/common.txt -t 50",
  ffuf:         "ffuf -u <url/FUZZ> -w <wordlist> [-mc status] [-t threads]. FUZZ keyword required in URL. Ex: ffuf -u http://site.com/FUZZ -w /usr/share/wordlists/dirb/common.txt",
  sqlmap:       "sqlmap -u <url?param=val> [--dbs] [--tables] [--dump] [--batch] [--level=1-5] [--risk=1-3]. Ex: sqlmap -u 'http://site.com/page?id=1' --batch --dbs",
  hydra:        "hydra [-l user|-L list] [-p pass|-P list] <target> <service> [-t threads] [-V verbose]. Ex: hydra -l admin -P /usr/share/wordlists/rockyou.txt 192.168.1.1 ssh",
  enum4linux:   "enum4linux [-a all] [-u user] [-p pass] <target>. Ex: enum4linux -a 192.168.1.1",
  wpscan:       "wpscan --url <url> [--enumerate u,p,vp,vt] [--api-token token]. Ex: wpscan --url http://site.com --enumerate u,vp",
  nuclei:       "nuclei -u <url> [-t templates/] [-severity low,medium,high,critical] [-stats]. Ex: nuclei -u http://site.com -severity high,critical",
  crackmapexec: "crackmapexec <smb|ssh|ldap> <target> [-u user] [-p pass] [--shares] [--users]. Ex: crackmapexec smb 192.168.1.0/24",
  feroxbuster:  "feroxbuster -u <url> -w <wordlist> [-t threads] [-x ext] [--depth n]. Ex: feroxbuster -u http://site.com -w /usr/share/wordlists/dirb/common.txt -t 50",
  masscan:      "masscan <target> -p<ports> --rate=<rate>. Needs root. Ex: masscan 192.168.1.0/24 -p1-65535 --rate=1000",
  dirb:         "dirb <url> [wordlist] [-r no recurse] [-S silent] [-z ms delay]. Ex: dirb http://site.com /usr/share/dirb/wordlists/common.txt",
  sublist3r:    "sublist3r -d <domain> [-t threads] [-o output]. Ex: sublist3r -d example.com",
  theharvester: "theHarvester -d <domain> -b <sources>. Sources: google,bing,crtsh,certspotter. Ex: theHarvester -d example.com -b google,crtsh",
  metasploit:   "msfconsole -q -x '<commands>' — chain with semicolons. Ex: use auxiliary/scanner/ftp/anonymous; set RHOSTS 1.2.3.4; run",
  ftp_anon:     "ftp anonymous login test using curl: curl -v --user anonymous:anon ftp://<host>/",
  port_vuln:    "Chained: nmap version detect → searchsploit → metasploit auto-exploit. POST /tools/port_vuln_scan {target, port, service?}",
};

// ─── Helpers ───────────────────────────────────────────────────────────────
function run(cmd, timeout = 120000) {
  return new Promise((resolve) => {
    exec(cmd, { timeout, maxBuffer: 1024 * 1024 * 10 }, (err, stdout, stderr) => {
      resolve({
        success: !err,
        stdout:  stdout  || "",
        stderr:  stderr  || "",
        error:   err?.message || null,
      });
    });
  });
}

function checkTool(bin) {
  return new Promise((resolve) => {
    exec(`which ${s(bin)} 2>/dev/null`, (err, stdout) =>
      resolve(!err && stdout.trim().length > 0)
    );
  });
}

// ─── Sudo password store (in-memory only, never logged) ───────────────────
let sudoPassword = null;

// Write a sudo SSE helper — sets CORS headers on the response too
function setSseHeaders(res) {
  res.setHeader("Content-Type",  "text/event-stream; charset=utf-8");
  res.setHeader("Cache-Control", "no-cache, no-transform");
  res.setHeader("Connection",    "keep-alive");
  res.setHeader("X-Accel-Buffering", "no");
  // CORS on SSE responses specifically (cors() middleware may not fire for streamed responses)
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type, Accept, Cache-Control");
  res.flushHeaders(); // send headers immediately so browser opens stream
}

function sendSSE(res, type, data) {
  try {
    res.write(`data: ${JSON.stringify({ type, data })}\n\n`);
  } catch (_) {}
}

// ─── Active process registry ───────────────────────────────────────────────
// Maps sessionId -> { proc, res }  so kill can also send SSE to the terminal
const activeProcs = new Map();
let sessionCounter = 0;

// ─── Kill endpoint ─────────────────────────────────────────────────────────
app.post("/kill", (req, res) => {
  const { sessionId } = req.body;

  function killProc(id) {
    const entry = activeProcs.get(id);
    if (!entry) return false;
    const { proc, sseRes } = entry;
    // Tell the terminal it was killed
    if (sseRes) {
      sendSSE(sseRes, "killed", `\n⛔  Process killed by user (session ${id})`);
      sendSSE(sseRes, "prompt", "$ ");
      try { sseRes.end(); } catch (_) {}
    }
    try { process.kill(-proc.pid, "SIGKILL"); } catch (_) {
      try { proc.kill("SIGKILL"); } catch (_) {}
    }
    activeProcs.delete(id);
    return true;
  }

  if (sessionId) {
    const killed = killProc(Number(sessionId));
    return res.json({ killed, sessionId });
  }

  // Kill ALL
  let count = 0;
  for (const id of activeProcs.keys()) { if (killProc(id)) count++; }
  res.json({ killed: count, all: true });
});

// ─── Sudo routes ───────────────────────────────────────────────────────────
app.post("/sudo", (req, res) => {
  const { password } = req.body;
  if (!password) return res.status(400).json({ error: "password required" });

  // Verify sudo works — use spawn to avoid injection via exec string
  const proc = spawn("sudo", ["-S", "whoami"], { stdio: ["pipe", "pipe", "pipe"] });
  proc.stdin.write(password + "\n");
  proc.stdin.end();

  let out = "";
  proc.stdout.on("data", d => { out += d.toString(); });
  proc.on("close", () => {
    if (out.trim() === "root") {
      sudoPassword = password;
      res.json({ valid: true });
    } else {
      sudoPassword = null;
      res.json({ valid: false, error: "Incorrect password or sudo not configured" });
    }
  });
  proc.on("error", err => res.json({ valid: false, error: err.message }));
});

app.get("/sudo/status", (req, res) => {
  res.json({ hasPassword: !!sudoPassword });
});

app.post("/sudo/clear", (req, res) => {
  sudoPassword = null;
  res.json({ cleared: true });
});

// ─── Which tools need root (so UI can prompt) ──────────────────────────────
app.get("/tools/needs_root", (req, res) => {
  res.json({ tools: [...NEEDS_ROOT] });
});

// ─── SSE streaming runner ──────────────────────────────────────────────────
// NOTE: headers must already be set by the caller before invoking this
function runStreaming(cmd, res, timeout = 180000) {
  const sessionId = ++sessionCounter;
  sendSSE(res, "session", sessionId);
  sendSSE(res, "cmd",     `$ ${cmd}`);

  const proc = spawn("bash", ["-c", cmd], {
    detached: true,
    stdio:    ["ignore", "pipe", "pipe"],
  });

  activeProcs.set(sessionId, { proc, sseRes: res });

  let fullOutput = "";

  proc.stdout.on("data", chunk => {
    const t = chunk.toString();
    fullOutput += t;
    sendSSE(res, "stdout", t);
  });

  proc.stderr.on("data", chunk => {
    const t = chunk.toString();
    fullOutput += t;
    sendSSE(res, "stderr", t);
  });

  const timer = setTimeout(() => {
    try { process.kill(-proc.pid, "SIGKILL"); } catch (_) {
      try { proc.kill("SIGKILL"); } catch (_) {}
    }
    activeProcs.delete(sessionId);
    sendSSE(res, "error",  "⏱  Command timed out");
    sendSSE(res, "prompt", "$ ");
    try { res.end(); } catch (_) {}
  }, timeout);

  proc.on("close", code => {
    clearTimeout(timer);
    activeProcs.delete(sessionId);
    sendSSE(res, "done",   { code, output: fullOutput });
    // ── KEY FIX: emit prompt so terminal shows $ after every command ──
    sendSSE(res, "prompt", `\n$ `);
    try { res.end(); } catch (_) {}
  });

  proc.on("error", err => {
    clearTimeout(timer);
    activeProcs.delete(sessionId);
    sendSSE(res, "error",  `Process error: ${err.message}`);
    sendSSE(res, "prompt", "\n$ ");
    try { res.end(); } catch (_) {}
  });

  // If browser disconnects, kill the process
  res.on("close", () => {
    clearTimeout(timer);
    if (activeProcs.has(sessionId)) {
      try { process.kill(-proc.pid, "SIGKILL"); } catch (_) {
        try { proc.kill("SIGKILL"); } catch (_) {}
      }
      activeProcs.delete(sessionId);
    }
  });
}

// ─── Auto-install helper ───────────────────────────────────────────────────
async function ensureTool(binName, res) {
  const present = await checkTool(binName);
  if (present) return true;

  const installCmd = INSTALL[binName];
  if (!installCmd) {
    sendSSE(res, "warn", `⚠  No install recipe for '${binName}'. Trying apt...`);
    await run(`DEBIAN_FRONTEND=noninteractive apt-get install -y ${s(binName)} 2>&1`);
    return checkTool(binName);
  }

  sendSSE(res, "install", `📦 '${binName}' not found — installing...\n$ ${installCmd}`);

  // Heartbeat every 5 s during long installs
  const hb = setInterval(() => {
    try { res.write(`: heartbeat\n\n`); } catch (_) { clearInterval(hb); }
  }, 5000);

  const result = await run(`DEBIAN_FRONTEND=noninteractive ${installCmd} 2>&1`, 180000);
  clearInterval(hb);

  sendSSE(res, result.success ? "stdout" : "stderr", result.stdout + result.stderr);

  const ok = await checkTool(binName);
  sendSSE(res, ok ? "install_ok" : "install_fail",
    ok ? `✅ ${binName} installed.` : `❌ Failed to install ${binName}.`
  );
  return ok;
}

// ─── Inject sudo into command ──────────────────────────────────────────────
function injectSudo(cmd) {
  if (!sudoPassword) return cmd;
  const escaped = sudoPassword.replace(/'/g, "'\\''");
  return cmd.replace(/\bsudo\b/g, `echo '${escaped}' | sudo -S `);
}

// ─── Per-tool timeout map (ms) ─────────────────────────────────────────────
const TOOL_TIMEOUTS = {
  nikto_scan:     600000,
  nuclei:         600000,
  gobuster_dir:   600000,
  gobuster_vhost: 600000,
  feroxbuster:    600000,
  ffuf:           600000,
  wfuzz:          600000,
  sqlmap_scan:    600000,
  hydra:          600000,
  medusa:         600000,
  wpscan:         300000,
  masscan:        300000,
  dirb_scan:      300000,
  enum4linux:     300000,
  dnsrecon:       300000,
  sublist3r:      300000,
  theharvester:   300000,
  tcpdump:        120000,
  responder:       60000,
  port_vuln_scan: 600000,
  full_host_audit:900000,
  msf_exploit:    300000,
  msf_run:        300000,
  ftp_anon:       120000,
  smb_full:       300000,
  http_full:      300000,
  mysql_check:    300000,
  smtp_check:     180000,
  redis_check:     60000,
  ssh_brute:      600000,
  ftp_brute:      600000,
  default:        120000,
};

function getTimeout(toolName) {
  return TOOL_TIMEOUTS[toolName] || TOOL_TIMEOUTS.default;
}

// ─── Generic tool route handler ────────────────────────────────────────────
// Signature: toolRoute(req, res, bin, buildCmd, toolName?)
// bin      = binary to check/install e.g. "nmap"
// buildCmd = arrow fn: body => "shell command string"
// toolName = optional key for timeout lookup (defaults to bin)
async function toolRoute(req, res, bin, buildCmd, toolName) {
  // Guard: buildCmd must be a function — catch miscalled routes early
  if (typeof buildCmd !== "function") {
    console.error(`toolRoute miscall: buildCmd is ${typeof buildCmd} for bin=${bin}`);
    if (!res.headersSent) {
      setSseHeaders(res);
      sendSSE(res, "fatal", `Server config error: buildCmd is not a function for '${bin}'`);
      sendSSE(res, "prompt", "\n$ ");
    }
    return res.end();
  }

  const cmd     = buildCmd(req.body);
  const timeout = getTimeout(toolName || bin || "default");
  const stream  = req.query.stream === "1" ||
                  req.headers["accept"] === "text/event-stream";

  if (stream) {
    // Set SSE headers ONCE right here — nothing else should call setSseHeaders
    setSseHeaders(res);

    // ── Check if this tool needs root and we have no sudo password ──────
    if (NEEDS_ROOT.has(bin) && !sudoPassword) {
      sendSSE(res, "needs_root", {
        needs_root: true,
        tool:       bin,
        message:    `'${bin}' requires root. Please provide your sudo password via Configure → Sudo Password.`,
      });
      sendSSE(res, "prompt", "\n$ ");
      return res.end();
    }

    if (bin) {
      const ok = await ensureTool(s(bin), res);
      if (!ok) {
        sendSSE(res, "fatal", `Cannot proceed: ${bin} could not be installed.`);
        sendSSE(res, "prompt", "\n$ ");
        return res.end();
      }
    }
    runStreaming(injectSudo(cmd), res, timeout);

  } else {
    // ── Non-streaming JSON path ──────────────────────────────────────────
    if (NEEDS_ROOT.has(bin) && !sudoPassword) {
      return res.status(403).json({
        needs_root: true,
        tool:       bin,
        message:    `'${bin}' requires root privileges. POST /sudo first.`,
      });
    }
    if (bin) {
      const present = await checkTool(bin);
      if (!present) {
        return res.json({ success: false, stdout: "", stderr: `Tool '${bin}' not installed.` });
      }
    }
    res.json(await run(injectSudo(cmd), timeout));
  }
}

// ─── Static file serving ───────────────────────────────────────────────────
app.get("/", (req, res) => {
  const htmlPath = path.join(__dirname, "index.html");
  if (fs.existsSync(htmlPath)) {
    res.sendFile(htmlPath);
  } else {
    res.json({
      name:      "KaliAI MCP Server",
      version:   "3.1",
      status:    "online",
      streaming: true,
      note:      "Place index.html next to server.js to serve the web app here.",
    });
  }
});
app.use(express.static(__dirname));

// ─── Health & docs ─────────────────────────────────────────────────────────
app.get("/health", (req, res) =>
  res.json({
    status:    "online",
    version:   "3.2",
    tools:     Object.keys(INSTALL),
    chains:    ["port_vuln_scan","full_host_audit","ftp_anon","smb_full","http_full","mysql_check","smtp_check","redis_check"],
    streaming: true,
  })
);

app.get("/docs/:tool", (req, res) => {
  const doc = TOOL_DOCS[req.params.tool];
  res.json({
    tool: req.params.tool,
    doc:  doc || `Run 'man ${s(req.params.tool)}' or '${s(req.params.tool)} --help' for usage.`,
  });
});

// ─── Generic /run endpoint ─────────────────────────────────────────────────
app.post("/run", async (req, res) => {
  const { cmd, bin } = req.body;
  if (!cmd) return res.status(400).json({ error: "cmd required" });

  // Set SSE headers once here
  setSseHeaders(res);

  if (bin) {
    const ok = await ensureTool(s(bin), res);
    if (!ok) {
      sendSSE(res, "fatal", `Cannot proceed: ${bin} could not be installed.`);
      sendSSE(res, "prompt", "\n$ ");
      return res.end();
    }
  }

  runStreaming(injectSudo(s(cmd)), res);
});

// ─── RECON routes ──────────────────────────────────────────────────────────
app.post("/tools/ping_host",     (q,r) => toolRoute(q,r,"ping",         b=>`ping -c 4 ${s(b.target)}`));
app.post("/tools/nmap_scan",     (q,r) => toolRoute(q,r,"nmap",         b=>`nmap ${s(b.flags||"-sT -sV -sC --top-ports 1000 -T4")} ${s(b.target)}`));
app.post("/tools/masscan",       (q,r) => toolRoute(q,r,"masscan",      b=>`masscan ${s(b.target)} -p${s(b.ports||"1-65535")} --rate=${s(b.rate||"1000")}`));
app.post("/tools/arp_scan",      (q,r) => toolRoute(q,r,"arp-scan",     b=>`arp-scan -I ${s(b.interface||"eth0")} ${b.range?s(b.range):"--localnet"}`));
app.post("/tools/netdiscover",   (q,r) => toolRoute(q,r,"netdiscover",  b=>`netdiscover -i ${s(b.interface||"eth0")} ${b.range?"-r "+s(b.range):""} -P -N`));
app.post("/tools/dns_lookup",    async (q,r) => {
  const t = s(q.body.target);
  const [a,mx,ns,txt] = await Promise.all([
    run(`dig +short A ${t}`),
    run(`dig +short MX ${t}`),
    run(`dig +short NS ${t}`),
    run(`dig +short TXT ${t}`),
  ]);
  r.json({ success:true, stdout:`[A]\n${a.stdout}\n[MX]\n${mx.stdout}\n[NS]\n${ns.stdout}\n[TXT]\n${txt.stdout}` });
});
app.post("/tools/dnsrecon",      (q,r) => toolRoute(q,r,"dnsrecon",     b=>`dnsrecon -d ${s(b.target)} ${s(b.flags||"-t std,brt")}`));
app.post("/tools/fierce",        (q,r) => toolRoute(q,r,"fierce",       b=>`fierce --domain ${s(b.domain)}`));
app.post("/tools/sublist3r",     (q,r) => toolRoute(q,r,"sublist3r",    b=>`sublist3r -d ${s(b.domain)}`));
app.post("/tools/theharvester",  (q,r) => toolRoute(q,r,"theHarvester", b=>`theHarvester -d ${s(b.domain)} -b ${s(b.source||"google,crtsh,certspotter")}`));
app.post("/tools/whois_lookup",  (q,r) => toolRoute(q,r,"whois",        b=>`whois ${s(b.target)}`));
app.post("/tools/whatweb",       (q,r) => toolRoute(q,r,"whatweb",      b=>`whatweb -a${s(b.aggression||"3")} ${s(b.url)}`));
app.post("/tools/wafw00f",       (q,r) => toolRoute(q,r,"wafw00f",      b=>`wafw00f ${s(b.url)}`));
app.post("/tools/sslyze",        (q,r) => toolRoute(q,r,"sslyze",       b=>`sslyze ${s(b.host)} ${s(b.flags||"--tlsv1_2 --tlsv1_3 --certinfo --heartbleed")}`));
app.post("/tools/testssl",       (q,r) => toolRoute(q,r,"testssl.sh",   b=>`testssl.sh --quiet ${s(b.host)}`));

// ─── WEB APP routes ────────────────────────────────────────────────────────
app.post("/tools/nikto_scan",    (q,r) => toolRoute(q,r,"nikto",        b=>`nikto -h ${s(b.target).startsWith("http")?s(b.target):"http://"+s(b.target)} ${s(b.flags||"")}`,          "nikto_scan"));
app.post("/tools/gobuster_dir",  (q,r) => toolRoute(q,r,"gobuster",     b=>`gobuster dir -u ${s(b.url)} -w ${s(b.wordlist||"/usr/share/wordlists/dirb/common.txt")} ${s(b.flags||"-t 50 -q")}`, "gobuster_dir"));
app.post("/tools/gobuster_vhost",(q,r) => toolRoute(q,r,"gobuster",     b=>`gobuster vhost -u ${s(b.url)} -w ${s(b.wordlist||"/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt")} -t 50 -q`, "gobuster_vhost"));
app.post("/tools/feroxbuster",   (q,r) => toolRoute(q,r,"feroxbuster",  b=>`feroxbuster -u ${s(b.url)} -w ${s(b.wordlist||"/usr/share/wordlists/dirb/common.txt")} ${s(b.flags||"-t 50 -q --no-state")}`, "feroxbuster"));
app.post("/tools/ffuf",          (q,r) => toolRoute(q,r,"ffuf",         b=>{ const u=s(b.url).includes("FUZZ")?s(b.url):s(b.url)+"/FUZZ"; return `ffuf -u ${u} -w ${s(b.wordlist||"/usr/share/wordlists/dirb/common.txt")} ${s(b.flags||"-t 50 -mc 200,301,302,403")}`; }, "ffuf"));
app.post("/tools/wfuzz",         (q,r) => toolRoute(q,r,"wfuzz",        b=>{ const u=s(b.url).includes("FUZZ")?s(b.url):s(b.url)+"/FUZZ"; return `wfuzz -w ${s(b.wordlist||"/usr/share/wordlists/dirb/common.txt")} ${s(b.flags||"--hc 404 -t 50")} ${u}`; }, "wfuzz"));
app.post("/tools/dirb_scan",     (q,r) => toolRoute(q,r,"dirb",         b=>`dirb ${s(b.url)} ${s(b.wordlist||"/usr/share/dirb/wordlists/common.txt")} -r -S`,                          "dirb_scan"));
app.post("/tools/sqlmap_scan",   (q,r) => toolRoute(q,r,"sqlmap",       b=>`sqlmap -u ${sq(b.url)} ${s(b.flags||"--batch --level=2 --risk=2")}`,                                       "sqlmap_scan"));
app.post("/tools/xsstrike",      (q,r) => toolRoute(q,r,"xsstrike",     b=>`xsstrike -u ${sq(b.url)} ${s(b.flags||"")} 2>/dev/null || python3 /opt/XSStrike/xsstrike.py -u ${sq(b.url)} ${s(b.flags||"")}`, "xsstrike"));
app.post("/tools/dalfox",        (q,r) => toolRoute(q,r,"dalfox",       b=>`dalfox url ${sq(b.url)} ${s(b.flags||"")}`,                                                               "dalfox"));
app.post("/tools/commix",        (q,r) => toolRoute(q,r,"commix",       b=>`commix --url=${sq(b.url)} ${s(b.flags||"--batch")}`,                                                      "commix"));
app.post("/tools/nuclei",        (q,r) => toolRoute(q,r,"nuclei",       b=>`nuclei -u ${s(b.target)} ${b.templates?"-t "+s(b.templates):""} ${s(b.flags||"-severity low,medium,high,critical")}`, "nuclei"));
app.post("/tools/wpscan",        (q,r) => toolRoute(q,r,"wpscan",       b=>`wpscan --url ${s(b.url)} ${s(b.flags||"--enumerate vp,vt,u --detection-mode aggressive")}`,               "wpscan"));
app.post("/tools/curl_request",  (q,r) => toolRoute(q,r,"curl",         b=>`curl -s -o - -w "\\n\\n[HTTP %{http_code}] [%.3fs]" -X ${s(b.method||"GET")} ${b.headers?`-H ${sq(b.headers)}`:""} ${b.data?`-d ${sq(b.data)}`:""} ${sq(b.url)}`, "curl_request"));
app.post("/tools/jwt_tool",      (q,r) => toolRoute(q,r,"python3",      b=>`python3 /opt/jwt_tool/jwt_tool.py ${s(b.token)} ${s(b.flags||"-t")}`,                                     "jwt_tool"));

// ─── NETWORK routes ────────────────────────────────────────────────────────
app.post("/tools/enum4linux",    (q,r) => toolRoute(q,r,"enum4linux",   b=>`enum4linux ${s(b.flags||"-a")} ${s(b.target)}`,                                                           "enum4linux"));
app.post("/tools/smbmap",        (q,r) => toolRoute(q,r,"smbmap",       b=>`smbmap -H ${s(b.target)} ${s(b.flags||"")}`,                                                              "smbmap"));
app.post("/tools/smbclient",     (q,r) => toolRoute(q,r,"smbclient",    b=>`smbclient ${s(b.flags||"-N -L")} ${s(b.target)}`,                                                         "smbclient"));
app.post("/tools/nbtscan",       (q,r) => toolRoute(q,r,"nbtscan",      b=>`nbtscan -r ${s(b.range)}`,                                                                                "nbtscan"));
app.post("/tools/crackmapexec",  (q,r) => toolRoute(q,r,"crackmapexec", b=>`crackmapexec ${s(b.protocol||"smb")} ${s(b.target)} ${s(b.flags||"")}`,                                   "crackmapexec"));
app.post("/tools/snmpwalk",      (q,r) => toolRoute(q,r,"snmpwalk",     b=>`snmpwalk -v${s(b.version||"2c")} -c ${s(b.community||"public")} ${s(b.target)}`,                          "snmpwalk"));
app.post("/tools/onesixtyone",   (q,r) => toolRoute(q,r,"onesixtyone",  b=>`onesixtyone -c ${s(b.wordlist||"/usr/share/seclists/Discovery/SNMP/common-snmp-community-strings.txt")} ${s(b.target)}`, "onesixtyone"));
app.post("/tools/smtp_user_enum",(q,r) => toolRoute(q,r,"smtp-user-enum",b=>`smtp-user-enum -M ${s(b.mode||"VRFY")} -U ${s(b.wordlist||"/usr/share/seclists/Usernames/top-usernames-shortlist.txt")} -t ${s(b.target)}`, "smtp_user_enum"));
app.post("/tools/hydra",         (q,r) => toolRoute(q,r,"hydra",        b=>`hydra ${b.user?"-l "+s(b.user):"-L /usr/share/seclists/Usernames/top-usernames-shortlist.txt"} -P ${s(b.wordlist||"/usr/share/wordlists/rockyou.txt")} ${s(b.flags||"-t 4 -V")} ${s(b.target)} ${s(b.service||"ssh")}`, "hydra"));
app.post("/tools/medusa",        (q,r) => toolRoute(q,r,"medusa",       b=>`medusa -h ${s(b.target)} ${b.user?"-u "+s(b.user):"-U /usr/share/seclists/Usernames/top-usernames-shortlist.txt"} -P ${s(b.wordlist||"/usr/share/wordlists/rockyou.txt")} -M ${s(b.service||"ssh")} ${s(b.flags||"-t 4")}`, "medusa"));
app.post("/tools/ncrack",        (q,r) => toolRoute(q,r,"ncrack",       b=>`ncrack ${s(b.flags||"-v")} ${s(b.target)} -p ${s(b.service||"ssh")}`,                                     "ncrack"));
app.post("/tools/responder",     (q,r) => toolRoute(q,r,"responder",    b=>`timeout 30 responder -I ${s(b.interface||"eth0")} ${s(b.flags||"-A")}`,                                   "responder"));
app.post("/tools/tcpdump",       (q,r) => toolRoute(q,r,"tcpdump",      b=>`tcpdump -i ${s(b.interface||"eth0")} -c ${s(b.count||"100")} ${s(b.filter||"")} -A`,                      "tcpdump"));
app.post("/tools/searchsploit",  (q,r) => toolRoute(q,r,"searchsploit", b=>`searchsploit ${sq(b.query)}`,                                                                             "searchsploit"));
app.post("/tools/curl_headers",  (q,r) => toolRoute(q,r,"curl",         b=>`curl -s -I ${sq(b.url)}`,                                                                                 "curl_headers"));
app.post("/tools/run_command",   (q,r) => toolRoute(q,r,null,           b=>s(b.command),                                                                                              "run_command"));

// ─── METASPLOIT ────────────────────────────────────────────────────────────
// Runs msfconsole in batch mode with a semicolon-separated command string
app.post("/tools/msf_run", async (req, res) => {
  setSseHeaders(res);
  const { commands, timeout: tout } = req.body;
  if (!commands) { sendSSE(res,"fatal","commands required"); sendSSE(res,"prompt","\n$ "); return res.end(); }
  // Build rc script so msfconsole exits cleanly after commands
  const cmds = s(commands);
  const cmd  = `msfconsole -q -x "${cmds}; exit"`;
  runStreaming(cmd, res, tout || 300000);
});

// Metasploit: search for a module and auto-run it
app.post("/tools/msf_exploit", async (req, res) => {
  setSseHeaders(res);
  const { target, port, module: mod, options } = req.body;
  if (!target || !mod) { sendSSE(res,"fatal","target and module required"); sendSSE(res,"prompt","\n$ "); return res.end(); }
  const t = s(target); const p = s(port||""); const m = s(mod);
  const opts = options ? s(options) : "";
  const cmd = `msfconsole -q -x "use ${m}; set RHOSTS ${t}; ${p?"set RPORT "+p+"; ":""}${opts}; run; exit"`;
  runStreaming(cmd, res, 300000);
});

// Metasploit: search exploits for a keyword
app.post("/tools/msf_search", (q,r) => toolRoute(q,r,"msfconsole",
  b=>`msfconsole -q -x "search ${s(b.query)}; exit"`, "msf_search"));

// ─── FTP ───────────────────────────────────────────────────────────────────
// Anonymous login test
app.post("/tools/ftp_anon", async (req, res) => {
  setSseHeaders(res);
  const { target, port } = req.body;
  if (!target) { sendSSE(res,"fatal","target required"); sendSSE(res,"prompt","\n$ "); return res.end(); }
  const t = s(target); const p = s(port||"21");
  // Three methods: curl anonymous, nmap ftp-anon script, hydra
  const cmd = [
    `echo "=== [1/3] curl anonymous FTP login test ==="`,
    `curl -v --connect-timeout 10 --user anonymous:anonymous ftp://${t}:${p}/ 2>&1 | head -40`,
    `echo ""`,
    `echo "=== [2/3] nmap ftp-anon + ftp-bounce scripts ==="`,
    `nmap -p ${p} --script ftp-anon,ftp-bounce,ftp-syst,ftp-vsftpd-backdoor --script-timeout 30s -T4 ${t}`,
    `echo ""`,
    `echo "=== [3/3] hydra FTP anonymous brute ==="`,
    `hydra -l anonymous -p anonymous ftp://${t}:${p} -t 4 -V 2>&1 | tail -20`,
  ].join(" && ");
  runStreaming(cmd, res, 120000);
});

// FTP bruteforce
app.post("/tools/ftp_brute", (q,r) => toolRoute(q,r,"hydra",
  b=>`hydra -L ${s(b.userlist||"/usr/share/seclists/Usernames/top-usernames-shortlist.txt")} -P ${s(b.passlist||"/usr/share/wordlists/rockyou.txt")} ftp://${s(b.target)}:${s(b.port||"21")} -t 10 -V`,
  "ftp_brute"));

// ─── SSH ───────────────────────────────────────────────────────────────────
app.post("/tools/ssh_audit",  (q,r) => toolRoute(q,r,"nmap",
  b=>`nmap -p ${s(b.port||"22")} --script ssh2-enum-algos,ssh-auth-methods,ssh-hostkey,sshv1 --script-timeout 20s -T4 ${s(b.target)}`,
  "ssh_audit"));
app.post("/tools/ssh_brute",  (q,r) => toolRoute(q,r,"hydra",
  b=>`hydra -L ${s(b.userlist||"/usr/share/seclists/Usernames/top-usernames-shortlist.txt")} -P ${s(b.passlist||"/usr/share/wordlists/rockyou.txt")} ssh://${s(b.target)}:${s(b.port||"22")} -t 4 -V`,
  "ssh_brute"));

// ─── SMB / SAMBA ───────────────────────────────────────────────────────────
app.post("/tools/smb_full", async (req, res) => {
  setSseHeaders(res);
  const { target } = req.body;
  if (!target) { sendSSE(res,"fatal","target required"); sendSSE(res,"prompt","\n$ "); return res.end(); }
  const t = s(target);
  const cmd = [
    `echo "=== [1/4] nmap SMB scripts ==="`,
    `nmap -p 445,139 --script smb-vuln*,smb-enum-shares,smb-enum-users,smb-security-mode --script-timeout 30s -T4 ${t}`,
    `echo ""`,
    `echo "=== [2/4] enum4linux ==="`,
    `enum4linux -a ${t} 2>&1 | head -100`,
    `echo ""`,
    `echo "=== [3/4] smbmap ==="`,
    `smbmap -H ${t} 2>&1`,
    `echo ""`,
    `echo "=== [4/4] crackmapexec ==="`,
    `crackmapexec smb ${t} --shares --users 2>&1 | head -50`,
  ].join(" && ");
  runStreaming(cmd, res, 300000);
});

// EternalBlue / MS17-010 check
app.post("/tools/smb_eternalblue", (q,r) => toolRoute(q,r,"nmap",
  b=>`nmap -p 445 --script smb-vuln-ms17-010 --script-timeout 30s -T4 ${s(b.target)}`,
  "smb_eternalblue"));

// ─── HTTP / HTTPS ──────────────────────────────────────────────────────────
app.post("/tools/http_full", async (req, res) => {
  setSseHeaders(res);
  const { target, port } = req.body;
  if (!target) { sendSSE(res,"fatal","target required"); sendSSE(res,"prompt","\n$ "); return res.end(); }
  const t = s(target); const p = s(port||"80");
  const url = t.startsWith("http") ? t : `http://${t}:${p}`;
  const cmd = [
    `echo "=== [1/4] HTTP headers ==="`,
    `curl -sk -I ${url} 2>&1 | head -30`,
    `echo ""`,
    `echo "=== [2/4] whatweb ==="`,
    `whatweb -a3 ${url} 2>&1`,
    `echo ""`,
    `echo "=== [3/4] nmap http scripts ==="`,
    `nmap -p ${p} --script http-title,http-headers,http-methods,http-server-header,http-auth-finder,http-shellshock,http-robots.txt --script-timeout 20s -T4 ${t}`,
    `echo ""`,
    `echo "=== [4/4] nikto quick scan ==="`,
    `nikto -h ${url} -maxtime 60 2>&1`,
  ].join(" && ");
  runStreaming(cmd, res, 300000);
});

// ─── MYSQL ─────────────────────────────────────────────────────────────────
app.post("/tools/mysql_check", async (req, res) => {
  setSseHeaders(res);
  const { target, port } = req.body;
  if (!target) { sendSSE(res,"fatal","target required"); sendSSE(res,"prompt","\n$ "); return res.end(); }
  const t = s(target); const p = s(port||"3306");
  const cmd = [
    `echo "=== [1/3] nmap MySQL scripts ==="`,
    `nmap -p ${p} --script mysql-info,mysql-empty-password,mysql-databases,mysql-enum --script-timeout 30s -T4 ${t}`,
    `echo ""`,
    `echo "=== [2/3] MySQL anonymous login test ==="`,
    `mysql -h ${t} -P ${p} -u root --password= --connect-timeout=5 -e "show databases;" 2>&1 || echo "root/blank failed"`,
    `echo ""`,
    `echo "=== [3/3] hydra MySQL brute ==="`,
    `hydra -l root -P /usr/share/wordlists/rockyou.txt mysql://${t}:${p} -t 4 -V 2>&1 | head -30`,
  ].join(" && ");
  runStreaming(cmd, res, 300000);
});

// ─── REDIS ─────────────────────────────────────────────────────────────────
app.post("/tools/redis_check", async (req, res) => {
  setSseHeaders(res);
  const { target, port } = req.body;
  if (!target) { sendSSE(res,"fatal","target required"); sendSSE(res,"prompt","\n$ "); return res.end(); }
  const t = s(target); const p = s(port||"6379");
  const cmd = [
    `echo "=== [1/2] Redis unauthenticated access test ==="`,
    `redis-cli -h ${t} -p ${p} --no-auth-warning ping 2>&1`,
    `redis-cli -h ${t} -p ${p} --no-auth-warning INFO server 2>&1 | head -30`,
    `echo ""`,
    `echo "=== [2/2] nmap Redis scripts ==="`,
    `nmap -p ${p} --script redis-info --script-timeout 20s -T4 ${t}`,
  ].join(" && ");
  runStreaming(cmd, res, 60000);
});

// ─── SMTP ──────────────────────────────────────────────────────────────────
app.post("/tools/smtp_check", async (req, res) => {
  setSseHeaders(res);
  const { target, port } = req.body;
  if (!target) { sendSSE(res,"fatal","target required"); sendSSE(res,"prompt","\n$ "); return res.end(); }
  const t = s(target); const p = s(port||"25");
  const cmd = [
    `echo "=== [1/3] nmap SMTP scripts ==="`,
    `nmap -p ${p} --script smtp-commands,smtp-enum-users,smtp-open-relay,smtp-vuln* --script-timeout 30s -T4 ${t}`,
    `echo ""`,
    `echo "=== [2/3] SMTP user enum ==="`,
    `smtp-user-enum -M VRFY -U /usr/share/seclists/Usernames/top-usernames-shortlist.txt -t ${t} -p ${p} 2>&1 | head -30`,
    `echo ""`,
    `echo "=== [3/3] Open relay test ==="`,
    `nmap -p ${p} --script smtp-open-relay --script-args smtp-open-relay.to=test@test.com --script-timeout 20s ${t}`,
  ].join(" && ");
  runStreaming(cmd, res, 180000);
});

// ─── PORT VULNERABILITY CHAIN ─────────────────────────────────────────────
// This is the KEY endpoint: given target+port, auto-detect service version,
// search exploits, then attempt metasploit modules — full automated chain
app.post("/tools/port_vuln_scan", async (req, res) => {
  setSseHeaders(res);
  const { target, port, service } = req.body;
  if (!target || !port) {
    sendSSE(res, "fatal", "target and port are required");
    sendSSE(res, "prompt", "\n$ ");
    return res.end();
  }

  const t  = s(target);
  const p  = s(port);
  const svc = s(service || "");

  sendSSE(res, "stdout", `\n🔍  Starting full vulnerability chain for ${t}:${p}\n`);

  // ── Step 1: Version detection ──────────────────────────────────────────
  sendSSE(res, "stdout", "\n═══ STEP 1/4: Service Version Detection ═══\n");
  const nmapResult = await run(
    `nmap -p ${p} -sV -sC --script vulners,banner --script-timeout 20s -T4 ${t}`,
    60000
  );
  sendSSE(res, "stdout", nmapResult.stdout || nmapResult.stderr);

  // Extract version string from nmap output for searchsploit query
  const versionMatch = nmapResult.stdout.match(/\d+\/tcp\s+open\s+(\S+)\s+(.*)/);
  const detectedService = svc || (versionMatch ? versionMatch[1] : "");
  const versionBanner   = versionMatch ? versionMatch[2].trim() : "";

  sendSSE(res, "stdout", `\n📌  Detected: service="${detectedService}" version="${versionBanner}"\n`);

  // ── Step 2: SearchSploit ───────────────────────────────────────────────
  sendSSE(res, "stdout", "\n═══ STEP 2/4: SearchSploit Exploit Search ═══\n");

  // Search with version string first, fall back to service name
  const queries = [];
  if (versionBanner) queries.push(versionBanner.split(" ").slice(0,3).join(" "));
  if (detectedService) queries.push(detectedService);

  for (const q of queries) {
    if (!q) continue;
    sendSSE(res, "stdout", `\n$ searchsploit "${q}"\n`);
    const ss = await run(`searchsploit "${q}" 2>&1`, 30000);
    sendSSE(res, "stdout", ss.stdout || "(no results)");
  }

  // ── Step 3: Metasploit module search ──────────────────────────────────
  sendSSE(res, "stdout", "\n═══ STEP 3/4: Metasploit Module Search ═══\n");
  const msfQuery = versionBanner
    ? versionBanner.split(" ").slice(0,2).join(" ")
    : detectedService;

  if (msfQuery) {
    sendSSE(res, "stdout", `\n$ msfconsole -q -x "search ${msfQuery}; exit"\n`);
    const msfSearch = await run(`msfconsole -q -x "search ${msfQuery}; exit" 2>&1`, 60000);
    sendSSE(res, "stdout", msfSearch.stdout || "(no modules found)");
  }

  // ── Step 4: Service-specific auto-exploit chain ────────────────────────
  sendSSE(res, "stdout", "\n═══ STEP 4/4: Service-Specific Checks ═══\n");

  const svcLower = detectedService.toLowerCase();

  if (svcLower.includes("ftp") || p === "21") {
    sendSSE(res, "stdout", "\n🔓 FTP detected — testing anonymous login + vsftpd backdoor\n");
    const ftpCmd = [
      `curl -sv --connect-timeout 8 --user anonymous:anonymous ftp://${t}:${p}/ 2>&1 | head -30`,
      `nmap -p ${p} --script ftp-anon,ftp-vsftpd-backdoor --script-timeout 20s -T4 ${t}`,
    ].join(" ; echo '' ; ");
    const ftpRes = await run(ftpCmd, 60000);
    sendSSE(res, "stdout", ftpRes.stdout + ftpRes.stderr);

    // vsftpd 2.3.4 backdoor — MSF auto-attempt
    if (versionBanner.includes("vsftpd 2.3.4") || versionBanner.includes("2.3.4")) {
      sendSSE(res, "stdout", "\n💥 vsftpd 2.3.4 BACKDOOR detected! Auto-exploiting...\n");
      const exploit = await run(
        `msfconsole -q -x "use exploit/unix/ftp/vsftpd_234_backdoor; set RHOSTS ${t}; set RPORT ${p}; run; exit" 2>&1`,
        60000
      );
      sendSSE(res, "stdout", exploit.stdout);
    }

  } else if (svcLower.includes("ssh") || p === "22") {
    sendSSE(res, "stdout", "\n🔓 SSH detected — auditing algorithms and auth methods\n");
    const sshRes = await run(
      `nmap -p ${p} --script ssh2-enum-algos,ssh-auth-methods,sshv1 --script-timeout 20s -T4 ${t}`,
      40000
    );
    sendSSE(res, "stdout", sshRes.stdout);

  } else if (svcLower.includes("http") || svcLower.includes("web") || ["80","443","8080","8443","8000"].includes(p)) {
    sendSSE(res, "stdout", "\n🌐 HTTP detected — running web checks\n");
    const proto = (p === "443" || svcLower.includes("ssl")) ? "https" : "http";
    const httpRes = await run(
      `nmap -p ${p} --script http-vuln*,http-shellshock,http-title,http-headers --script-timeout 25s -T4 ${t}`,
      60000
    );
    sendSSE(res, "stdout", httpRes.stdout);

  } else if (svcLower.includes("smb") || svcLower.includes("microsoft-ds") || ["445","139"].includes(p)) {
    sendSSE(res, "stdout", "\n🪟 SMB detected — checking MS17-010 EternalBlue + share enum\n");
    const smbRes = await run(
      `nmap -p ${p} --script smb-vuln-ms17-010,smb-enum-shares,smb-security-mode --script-timeout 30s -T4 ${t}`,
      60000
    );
    sendSSE(res, "stdout", smbRes.stdout);

    if (smbRes.stdout.includes("VULNERABLE") || smbRes.stdout.includes("ms17-010")) {
      sendSSE(res, "stdout", "\n💥 MS17-010 VULNERABLE! Searching Metasploit module...\n");
      const ms17 = await run(
        `msfconsole -q -x "use exploit/windows/smb/ms17_010_eternalblue; set RHOSTS ${t}; check; exit" 2>&1`,
        60000
      );
      sendSSE(res, "stdout", ms17.stdout);
    }

  } else if (svcLower.includes("mysql") || p === "3306") {
    sendSSE(res, "stdout", "\n🗄️  MySQL detected — checking empty password\n");
    const sqlRes = await run(
      `nmap -p ${p} --script mysql-empty-password,mysql-info --script-timeout 20s -T4 ${t}`,
      40000
    );
    sendSSE(res, "stdout", sqlRes.stdout);

  } else if (svcLower.includes("rdp") || p === "3389") {
    sendSSE(res, "stdout", "\n🖥️  RDP detected — checking BlueKeep CVE-2019-0708\n");
    const rdpRes = await run(
      `nmap -p ${p} --script rdp-enum-encryption,rdp-vuln-ms12-020 --script-timeout 20s -T4 ${t}`,
      40000
    );
    sendSSE(res, "stdout", rdpRes.stdout);
    const bk = await run(
      `msfconsole -q -x "use auxiliary/scanner/rdp/cve_2019_0708_bluekeep; set RHOSTS ${t}; run; exit" 2>&1`,
      60000
    );
    sendSSE(res, "stdout", bk.stdout);

  } else if (svcLower.includes("redis") || p === "6379") {
    sendSSE(res, "stdout", "\n🔴 Redis detected — testing unauthenticated access\n");
    const redisRes = await run(
      `redis-cli -h ${t} -p ${p} --no-auth-warning ping 2>&1 && redis-cli -h ${t} -p ${p} --no-auth-warning INFO server 2>&1 | head -20`,
      20000
    );
    sendSSE(res, "stdout", redisRes.stdout + redisRes.stderr);

  } else if (svcLower.includes("smtp") || p === "25" || p === "587") {
    sendSSE(res, "stdout", "\n📧 SMTP detected — checking open relay + user enum\n");
    const smtpRes = await run(
      `nmap -p ${p} --script smtp-open-relay,smtp-enum-users,smtp-commands --script-timeout 25s -T4 ${t}`,
      60000
    );
    sendSSE(res, "stdout", smtpRes.stdout);

  } else if (svcLower.includes("telnet") || p === "23") {
    sendSSE(res, "stdout", "\n📡 Telnet detected — checking for default credentials\n");
    const telRes = await run(
      `nmap -p ${p} --script telnet-encryption,telnet-ntlm-info --script-timeout 20s -T4 ${t}`,
      40000
    );
    sendSSE(res, "stdout", telRes.stdout);

  } else {
    // Generic — run all vuln scripts
    sendSSE(res, "stdout", `\n🔧 Generic service — running vuln scripts\n`);
    const genRes = await run(
      `nmap -p ${p} --script vuln --script-timeout 30s -T4 ${t}`,
      120000
    );
    sendSSE(res, "stdout", genRes.stdout);
  }

  sendSSE(res, "stdout", `\n\n✅  Vulnerability chain complete for ${t}:${p}\n`);
  sendSSE(res, "done",   { code: 0 });
  sendSSE(res, "prompt", "\n$ ");
  res.end();
});

// ─── FULL HOST AUDIT ───────────────────────────────────────────────────────
// Runs port_vuln_scan chain on ALL open ports found on a target
app.post("/tools/full_host_audit", async (req, res) => {
  setSseHeaders(res);
  const { target } = req.body;
  if (!target) { sendSSE(res,"fatal","target required"); sendSSE(res,"prompt","\n$ "); return res.end(); }
  const t = s(target);

  sendSSE(res, "stdout", `\n🔎  Full host audit starting for ${t}...\n`);

  // First discover open ports quickly
  sendSSE(res, "stdout", "\n═══ Discovering open ports ═══\n");
  const disco = await run(`nmap -p- --open -T4 --min-rate=500 ${t} 2>&1`, 300000);
  sendSSE(res, "stdout", disco.stdout);

  // Extract open ports
  const portMatches = [...disco.stdout.matchAll(/(\d+)\/tcp\s+open\s+(\S+)/g)];
  if (!portMatches.length) {
    sendSSE(res, "stdout", "\nNo open ports found.\n");
    sendSSE(res, "prompt", "\n$ ");
    return res.end();
  }

  sendSSE(res, "stdout", `\n📋  Found ${portMatches.length} open ports: ${portMatches.map(m=>m[1]).join(", ")}\n`);
  sendSSE(res, "stdout", "Starting per-port vulnerability chains...\n");

  // Chain vuln scan per port (sequential to avoid overwhelming target)
  for (const [, port, service] of portMatches) {
    sendSSE(res, "stdout", `\n${"━".repeat(60)}\n🎯  Auditing port ${port} (${service})\n${"━".repeat(60)}\n`);
    // Inline the version detect + searchsploit for each port
    const nmapV = await run(`nmap -p ${port} -sV --script vulners,banner --script-timeout 15s -T4 ${t} 2>&1`, 45000);
    sendSSE(res, "stdout", nmapV.stdout);

    const vm = nmapV.stdout.match(/\d+\/tcp\s+open\s+\S+\s+(.*)/);
    const banner = vm ? vm[1].trim() : service;
    if (banner) {
      const ssRes = await run(`searchsploit "${banner.split(" ").slice(0,3).join(" ")}" 2>&1`, 20000);
      sendSSE(res, "stdout", `\n[searchsploit: ${banner.split(" ").slice(0,3).join(" ")}]\n${ssRes.stdout}`);
    }
  }

  sendSSE(res, "stdout", `\n\n✅  Full host audit complete for ${t}\n`);
  sendSSE(res, "done",   { code: 0 });
  sendSSE(res, "prompt", "\n$ ");
  res.end();
});

// ─── Start ─────────────────────────────────────────────────────────────────
// Prevent a single bad request from crashing the whole server
process.on("uncaughtException", (err) => {
  console.error("⚠  Uncaught exception (server kept alive):", err.message);
});
process.on("unhandledRejection", (reason) => {
  console.error("⚠  Unhandled rejection (server kept alive):", reason);
});

app.listen(PORT, "0.0.0.0", () => {
  console.log(`\n🔥  KaliAI MCP Server v3.2  →  http://0.0.0.0:${PORT}`);
  console.log(`📡  Streaming: SSE enabled on all endpoints`);
  console.log(`🔒  Root tools: ${[...NEEDS_ROOT].join(", ")}`);
  console.log(`🔧  Auto-install: ${Object.keys(INSTALL).length} tools covered`);
  console.log(`⛓️   Chain endpoints: port_vuln_scan, full_host_audit, ftp_anon, smb_full, http_full`);
  console.log(`📖  Self-heal docs: GET /docs/<toolname>`);
  console.log(`⛔  Kill all: POST /kill\n`);
});
