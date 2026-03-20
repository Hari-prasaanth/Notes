/**
 * KaliAI MCP Server v3.0
 * - SSE streaming: real-time terminal output
 * - Auto-install: installs missing tools via apt/pip/go/gem
 * - Self-healing: exposes tool docs so AI can correct itself
 * Run: npm install && node server.js
 */

const express = require("express");
const cors    = require("cors");
const { exec, spawn } = require("child_process");
const path    = require("path");
const fs      = require("fs");

const app  = express();
const PORT = 3001;

app.use(cors());
app.use(express.json());

// ─── Sanitise ──────────────────────────────────────────────────────────────
function s(v) { return String(v || "").replace(/[`$;&|><\n\r]/g, ""); }

// ─── Tool install map ──────────────────────────────────────────────────────
const INSTALL = {
  nmap:          "apt-get install -y nmap",
  masscan:       "apt-get install -y masscan",
  "arp-scan":    "apt-get install -y arp-scan",
  netdiscover:   "apt-get install -y netdiscover",
  dnsrecon:      "pip3 install dnsrecon --break-system-packages",
  fierce:        "pip3 install fierce --break-system-packages",
  sublist3r:     "apt-get install -y sublist3r",
  theharvester:  "apt-get install -y theharvester",
  whatweb:       "apt-get install -y whatweb",
  wafw00f:       "pip3 install wafw00f --break-system-packages",
  sslyze:        "pip3 install sslyze --break-system-packages",
  "testssl.sh":  "apt-get install -y testssl.sh",
  nikto:         "apt-get install -y nikto",
  gobuster:      "apt-get install -y gobuster",
  feroxbuster:   "apt-get install -y feroxbuster",
  ffuf:          "apt-get install -y ffuf",
  wfuzz:         "apt-get install -y wfuzz",
  dirb:          "apt-get install -y dirb",
  sqlmap:        "apt-get install -y sqlmap",
  xsstrike:      "apt-get install -y xsstrike 2>/dev/null; which xsstrike || (git clone https://github.com/s0md3v/XSStrike /opt/XSStrike --depth 1 2>/dev/null; pip3 install -r /opt/XSStrike/requirements.txt --break-system-packages 2>/dev/null); true",
  dalfox:        "apt-get install -y dalfox",
  commix:        "apt-get install -y commix",
  nuclei:        "apt-get install -y nuclei",
  wpscan:        "apt-get install -y wpscan",
  enum4linux:    "apt-get install -y enum4linux",
  smbmap:        "apt-get install -y smbmap",
  smbclient:     "apt-get install -y smbclient",
  nbtscan:       "apt-get install -y nbtscan",
  crackmapexec:  "apt-get install -y crackmapexec",
  snmpwalk:      "apt-get install -y snmp",
  onesixtyone:   "apt-get install -y onesixtyone",
  "smtp-user-enum": "apt-get install -y smtp-user-enum",
  hydra:         "apt-get install -y hydra",
  medusa:        "apt-get install -y medusa",
  ncrack:        "apt-get install -y ncrack",
  responder:     "apt-get install -y responder",
  tcpdump:       "apt-get install -y tcpdump",
  searchsploit:  "apt-get install -y exploitdb",
};

// ─── Tool docs (for self-healing) ─────────────────────────────────────────
const TOOL_DOCS = {
  nmap:        "nmap [flags] <target>. Common: -sT (TCP connect), -sV (version), -sC (scripts), -p- (all ports), -T4 (fast), -A (aggressive). Ex: nmap -sV -sC -p 1-1000 192.168.1.1",
  nikto:       "nikto -h <host> [-p port] [-ssl] [-id user:pass]. Ex: nikto -h http://192.168.1.1 -p 80",
  gobuster:    "gobuster dir -u <url> -w <wordlist> [-t threads] [-x extensions]. Ex: gobuster dir -u http://site.com -w /usr/share/wordlists/dirb/common.txt -t 50",
  ffuf:        "ffuf -u <url/FUZZ> -w <wordlist> [-mc status] [-t threads]. FUZZ keyword required in URL. Ex: ffuf -u http://site.com/FUZZ -w /usr/share/wordlists/dirb/common.txt",
  sqlmap:      "sqlmap -u <url?param=val> [--dbs] [--tables] [--dump] [--batch] [--level=1-5] [--risk=1-3]. Ex: sqlmap -u 'http://site.com/page?id=1' --batch --dbs",
  hydra:       "hydra [-l user|-L list] [-p pass|-P list] <target> <service> [-t threads] [-V verbose]. Ex: hydra -l admin -P /usr/share/wordlists/rockyou.txt 192.168.1.1 ssh",
  enum4linux:  "enum4linux [-a all] [-u user] [-p pass] <target>. Ex: enum4linux -a 192.168.1.1",
  wpscan:      "wpscan --url <url> [--enumerate u,p,vp,vt] [--api-token token]. Ex: wpscan --url http://site.com --enumerate u,vp",
  nuclei:      "nuclei -u <url> [-t templates/] [-severity low,medium,high,critical] [-stats]. Ex: nuclei -u http://site.com -severity high,critical",
  crackmapexec:"crackmapexec <smb|ssh|ldap> <target> [-u user] [-p pass] [--shares] [--users]. Ex: crackmapexec smb 192.168.1.0/24",
  feroxbuster: "feroxbuster -u <url> -w <wordlist> [-t threads] [-x ext] [--depth n]. Ex: feroxbuster -u http://site.com -w /usr/share/wordlists/dirb/common.txt -t 50",
  masscan:     "masscan <target> -p<ports> --rate=<rate>. Needs root. Ex: masscan 192.168.1.0/24 -p1-65535 --rate=1000",
  dirb:        "dirb <url> [wordlist] [-r no recurse] [-S silent] [-z ms delay]. Ex: dirb http://site.com /usr/share/dirb/wordlists/common.txt",
  sublist3r:   "sublist3r -d <domain> [-t threads] [-o output]. Ex: sublist3r -d example.com",
  theharvester:"theHarvester -d <domain> -b <sources>. Sources: google,bing,crtsh,certspotter. Ex: theHarvester -d example.com -b google,crtsh",
};

// ─── Helpers ───────────────────────────────────────────────────────────────
function run(cmd, timeout = 120000) {
  return new Promise((resolve) => {
    exec(cmd, { timeout, maxBuffer: 1024 * 1024 * 10 }, (err, stdout, stderr) => {
      resolve({ success: !err, stdout: stdout || "", stderr: stderr || "", error: err?.message || null });
    });
  });
}

function checkTool(bin) {
  return new Promise((resolve) => {
    exec(`which ${bin} 2>/dev/null`, (err, stdout) => resolve(!err && stdout.trim().length > 0));
  });
}

// ─── Active process registry ───────────────────────────────────────────────
const activeProcs = new Map(); // sessionId -> child process
let sessionCounter = 0;

// Kill all running processes
app.post("/kill", (req, res) => {
  const { sessionId } = req.body;
  if (sessionId && activeProcs.has(sessionId)) {
    const proc = activeProcs.get(sessionId);
    try { process.kill(-proc.pid, "SIGKILL"); } catch(e) { proc.kill("SIGKILL"); }
    activeProcs.delete(sessionId);
    return res.json({ killed: true, sessionId });
  }
  // Kill ALL if no sessionId
  let killed = 0;
  for (const [id, proc] of activeProcs) {
    try { process.kill(-proc.pid, "SIGKILL"); } catch(e) { try { proc.kill("SIGKILL"); } catch(e2){} }
    killed++;
  }
  activeProcs.clear();
  res.json({ killed, all: true });
});

// ─── SSE streaming runner ──────────────────────────────────────────────────
function runStreaming(cmd, res, timeout = 180000) {
  res.setHeader("Content-Type", "text/event-stream");
  res.setHeader("Cache-Control", "no-cache");
  res.setHeader("Connection", "keep-alive");
  res.setHeader("X-Accel-Buffering", "no");

  const sendEvent = (type, data) => {
    try { res.write(`data: ${JSON.stringify({ type, data })}\n\n`); } catch(e) {}
  };

  sendEvent("cmd", `$ ${cmd}`);

  const sessionId = ++sessionCounter;
  const proc = spawn("bash", ["-c", cmd], { detached: true });
  activeProcs.set(sessionId, proc);
  sendEvent("session", sessionId);  // tell client the session ID

  let fullOutput = "";

  proc.stdout.on("data", (chunk) => { const t=chunk.toString(); fullOutput+=t; sendEvent("stdout",t); });
  proc.stderr.on("data", (chunk) => { const t=chunk.toString(); fullOutput+=t; sendEvent("stderr",t); });

  proc.on("close", (code) => {
    activeProcs.delete(sessionId);
    sendEvent("done", { code, output: fullOutput });
    try { res.end(); } catch(e) {}
  });

  proc.on("error", (err) => {
    activeProcs.delete(sessionId);
    sendEvent("error", err.message);
    try { res.end(); } catch(e) {}
  });

  const timer = setTimeout(() => {
    try { process.kill(-proc.pid, "SIGKILL"); } catch(e) { proc.kill("SIGKILL"); }
    activeProcs.delete(sessionId);
    sendEvent("error", "Command timed out");
    try { res.end(); } catch(e) {}
  }, timeout);

  proc.on("close", () => clearTimeout(timer));

  // If client disconnects, kill the process
  res.on("close", () => {
    clearTimeout(timer);
    if (activeProcs.has(sessionId)) {
      try { process.kill(-proc.pid, "SIGKILL"); } catch(e) { try { proc.kill("SIGKILL"); } catch(e2){} }
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
    res.write(`data: ${JSON.stringify({ type: "warn", data: `⚠ No install recipe for '${binName}'. Trying apt...` })}\n\n`);
    await run(`apt-get install -y ${binName} 2>&1`);
    return await checkTool(binName);
  }

  res.write(`data: ${JSON.stringify({ type: "install", data: `📦 '${binName}' not found. Installing...\n$ ${installCmd}` })}\n\n`);

  // Send heartbeat every 5s during install so SSE doesn't timeout
  const heartbeat = setInterval(() => {
    try { res.write(`: heartbeat\n\n`); } catch(e) { clearInterval(heartbeat); }
  }, 5000);

  const result = await run(`DEBIAN_FRONTEND=noninteractive ${installCmd} 2>&1`, 120000);
  clearInterval(heartbeat);

  res.write(`data: ${JSON.stringify({ type: installResult(result), data: result.stdout + result.stderr })}\n\n`);

  const now = await checkTool(binName);
  res.write(`data: ${JSON.stringify({ type: now ? "install_ok" : "install_fail", data: now ? `✅ ${binName} installed successfully.` : `❌ Failed to install ${binName}.` })}\n\n`);
  return now;
}

function installResult(r) { return r.success ? "stdout" : "stderr"; }

// ─── Routes ────────────────────────────────────────────────────────────────

// Serve the web app — looks for index.html next to server.js
app.get("/", (req, res) => {
  const htmlPath = path.join(__dirname, "index.html");
  if (fs.existsSync(htmlPath)) {
    res.sendFile(htmlPath);
  } else {
    res.json({ name: "KaliAI MCP Server", version: "3.0", status: "online", note: "Place index.html next to server.js to serve the web app here." });
  }
});
app.use(express.static(__dirname));

app.get("/health", (req, res) => res.json({ status: "online", tools: Object.keys(INSTALL), streaming: true }));

// Self-healing: return docs for a tool
app.get("/docs/:tool", (req, res) => {
  const doc = TOOL_DOCS[req.params.tool];
  res.json({ tool: req.params.tool, doc: doc || `Run 'man ${req.params.tool}' or '${req.params.tool} --help' for usage.` });
});

// Generic streaming endpoint — used by all tools
// POST /run  { cmd, bin }
app.post("/run", async (req, res) => {
  const { cmd, bin } = req.body;
  if (!cmd) return res.status(400).json({ error: "cmd required" });

  res.setHeader("Content-Type", "text/event-stream");
  res.setHeader("Cache-Control", "no-cache");
  res.setHeader("Connection", "keep-alive");
  res.setHeader("X-Accel-Buffering", "no");

  if (bin) {
    const ok = await ensureTool(s(bin), res);
    if (!ok) {
      res.write(`data: ${JSON.stringify({ type: "fatal", data: `Cannot proceed: ${bin} could not be installed.` })}\n\n`);
      return res.end();
    }
  }

  runStreaming(s(cmd), res);
});

// ─── Individual tool endpoints (non-streaming JSON fallback) ───────────────

async function toolRoute(req, res, bin, buildCmd) {
  const cmd = buildCmd(req.body);
  // check streaming preference
  if (req.query.stream === "1" || req.headers["accept"] === "text/event-stream") {
    res.setHeader("Content-Type", "text/event-stream");
    res.setHeader("Cache-Control", "no-cache");
    res.setHeader("Connection", "keep-alive");
    res.setHeader("X-Accel-Buffering", "no");
    if (bin) { const ok = await ensureTool(bin, res); if (!ok) { res.write(`data: ${JSON.stringify({ type:"fatal", data:"Cannot install "+bin })}\n\n`); return res.end(); } }
    runStreaming(cmd, res);
  } else {
    if (bin) { const present = await checkTool(bin); if (!present) { return res.json({ success:false, stdout:"", stderr:`Tool '${bin}' not installed. Use /run endpoint with stream=1 for auto-install.` }); } }
    res.json(await run(cmd));
  }
}

// RECON
app.post("/tools/ping_host",    (q,r) => toolRoute(q,r,"ping",      b=>`ping -c 4 ${s(b.target)}`));
app.post("/tools/nmap_scan",    (q,r) => toolRoute(q,r,"nmap",      b=>`nmap ${s(b.flags||"-sT -sV -sC --top-ports 1000 -T4")} ${s(b.target)}`));
app.post("/tools/masscan",      (q,r) => toolRoute(q,r,"masscan",   b=>`masscan ${s(b.target)} -p${s(b.ports||"1-65535")} --rate=${s(b.rate||"1000")}`));
app.post("/tools/arp_scan",     (q,r) => toolRoute(q,r,"arp-scan",  b=>`arp-scan -I ${s(b.interface||"eth0")} ${s(b.range)||"--localnet"}`));
app.post("/tools/netdiscover",  (q,r) => toolRoute(q,r,"netdiscover",b=>`netdiscover -i ${s(b.interface||"eth0")} ${b.range?"-r "+s(b.range):""} -P -N`));
app.post("/tools/dns_lookup",   async (q,r) => {
  const t = s(q.body.target);
  const [a,mx,ns,txt] = await Promise.all([run(`dig +short A ${t}`),run(`dig +short MX ${t}`),run(`dig +short NS ${t}`),run(`dig +short TXT ${t}`)]);
  r.json({ success:true, stdout:`[A]\n${a.stdout}\n[MX]\n${mx.stdout}\n[NS]\n${ns.stdout}\n[TXT]\n${txt.stdout}` });
});
app.post("/tools/dnsrecon",     (q,r) => toolRoute(q,r,"dnsrecon",  b=>`dnsrecon -d ${s(b.target)} ${s(b.flags||"-t std,brt")}`));
app.post("/tools/fierce",       (q,r) => toolRoute(q,r,"fierce",    b=>`fierce --domain ${s(b.domain)}`));
app.post("/tools/sublist3r",    (q,r) => toolRoute(q,r,"sublist3r", b=>`sublist3r -d ${s(b.domain)}`));
app.post("/tools/theharvester", (q,r) => toolRoute(q,r,"theHarvester",b=>`theHarvester -d ${s(b.domain)} -b ${s(b.source||"google,crtsh,certspotter")}`));
app.post("/tools/whois_lookup", (q,r) => toolRoute(q,r,"whois",     b=>`whois ${s(b.target)}`));
app.post("/tools/whatweb",      (q,r) => toolRoute(q,r,"whatweb",   b=>`whatweb -a${s(b.aggression||"3")} ${s(b.url)}`));
app.post("/tools/wafw00f",      (q,r) => toolRoute(q,r,"wafw00f",   b=>`wafw00f ${s(b.url)}`));
app.post("/tools/sslyze",       (q,r) => toolRoute(q,r,"sslyze",    b=>`sslyze ${s(b.host)} ${s(b.flags||"--tlsv1_2 --tlsv1_3 --certinfo --heartbleed")}`));
app.post("/tools/testssl",      (q,r) => toolRoute(q,r,"testssl.sh",b=>`testssl.sh --quiet ${s(b.host)}`));

// WEB APP
app.post("/tools/nikto_scan",   (q,r) => toolRoute(q,r,"nikto",    b=>`nikto -h ${s(b.target).startsWith("http")?s(b.target):"http://"+s(b.target)} ${s(b.flags||"")}`));
app.post("/tools/gobuster_dir", (q,r) => toolRoute(q,r,"gobuster", b=>`gobuster dir -u ${s(b.url)} -w ${s(b.wordlist||"/usr/share/wordlists/dirb/common.txt")} ${s(b.flags||"-t 50 -q")}`));
app.post("/tools/gobuster_vhost",(q,r)=> toolRoute(q,r,"gobuster", b=>`gobuster vhost -u ${s(b.url)} -w ${s(b.wordlist||"/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt")} -t 50 -q`));
app.post("/tools/feroxbuster",  (q,r) => toolRoute(q,r,"feroxbuster",b=>`feroxbuster -u ${s(b.url)} -w ${s(b.wordlist||"/usr/share/wordlists/dirb/common.txt")} ${s(b.flags||"-t 50 -q --no-state")}`));
app.post("/tools/ffuf",         (q,r) => toolRoute(q,r,"ffuf",     b=>{ const u=s(b.url).includes("FUZZ")?s(b.url):s(b.url)+"/FUZZ"; return `ffuf -u ${u} -w ${s(b.wordlist||"/usr/share/wordlists/dirb/common.txt")} ${s(b.flags||"-t 50 -mc 200,301,302,403")}`; }));
app.post("/tools/wfuzz",        (q,r) => toolRoute(q,r,"wfuzz",    b=>{ const u=s(b.url).includes("FUZZ")?s(b.url):s(b.url)+"/FUZZ"; return `wfuzz -w ${s(b.wordlist||"/usr/share/wordlists/dirb/common.txt")} ${s(b.flags||"--hc 404 -t 50")} ${u}`; }));
app.post("/tools/dirb_scan",    (q,r) => toolRoute(q,r,"dirb",     b=>`dirb ${s(b.url)} ${s(b.wordlist||"/usr/share/dirb/wordlists/common.txt")} -r -S`));
app.post("/tools/sqlmap_scan",  (q,r) => toolRoute(q,r,"sqlmap",   b=>`sqlmap -u "${s(b.url)}" ${s(b.flags||"--batch --level=2 --risk=2")}`));
app.post("/tools/xsstrike",     (q,r) => toolRoute(q,r,"xsstrike",  b=>`xsstrike -u "${s(b.url)}" ${s(b.flags||"")} 2>/dev/null || python3 /opt/XSStrike/xsstrike.py -u "${s(b.url)}" ${s(b.flags||"")}`));
app.post("/tools/dalfox",       (q,r) => toolRoute(q,r,"dalfox",   b=>`dalfox url "${s(b.url)}" ${s(b.flags||"")}`));
app.post("/tools/commix",       (q,r) => toolRoute(q,r,"commix",   b=>`commix --url="${s(b.url)}" ${s(b.flags||"--batch")}`));
app.post("/tools/nuclei",       (q,r) => toolRoute(q,r,"nuclei",   b=>`nuclei -u ${s(b.target)} ${b.templates?"-t "+s(b.templates):""} ${s(b.flags||"-severity low,medium,high,critical")}`));
app.post("/tools/wpscan",       (q,r) => toolRoute(q,r,"wpscan",   b=>`wpscan --url ${s(b.url)} ${s(b.flags||"--enumerate vp,vt,u --detection-mode aggressive")}`));
app.post("/tools/curl_request", (q,r) => toolRoute(q,r,"curl",     b=>`curl -s -o - -w "\\n\\n[HTTP %{http_code}] [%.3fs]" -X ${s(b.method||"GET")} ${b.headers?'-H "'+s(b.headers)+'"':""} ${b.data?"-d '"+s(b.data)+"'":""} "${s(b.url)}"`));
app.post("/tools/jwt_tool",     (q,r) => toolRoute(q,r,"python3",  b=>`python3 /opt/jwt_tool/jwt_tool.py ${s(b.token)} ${s(b.flags||"-t")}`));

// NETWORK
app.post("/tools/enum4linux",   (q,r) => toolRoute(q,r,"enum4linux",  b=>`enum4linux ${s(b.flags||"-a")} ${s(b.target)}`));
app.post("/tools/smbmap",       (q,r) => toolRoute(q,r,"smbmap",      b=>`smbmap -H ${s(b.target)} ${s(b.flags||"")}`));
app.post("/tools/smbclient",    (q,r) => toolRoute(q,r,"smbclient",   b=>`smbclient ${s(b.flags||"-N -L")} ${s(b.target)}`));
app.post("/tools/nbtscan",      (q,r) => toolRoute(q,r,"nbtscan",     b=>`nbtscan -r ${s(b.range)}`));
app.post("/tools/crackmapexec", (q,r) => toolRoute(q,r,"crackmapexec",b=>`crackmapexec ${s(b.protocol||"smb")} ${s(b.target)} ${s(b.flags||"")}`));
app.post("/tools/snmpwalk",     (q,r) => toolRoute(q,r,"snmpwalk",    b=>`snmpwalk -v${s(b.version||"2c")} -c ${s(b.community||"public")} ${s(b.target)}`));
app.post("/tools/onesixtyone",  (q,r) => toolRoute(q,r,"onesixtyone", b=>`onesixtyone -c ${s(b.wordlist||"/usr/share/seclists/Discovery/SNMP/common-snmp-community-strings.txt")} ${s(b.target)}`));
app.post("/tools/smtp_user_enum",(q,r)=> toolRoute(q,r,"smtp-user-enum",b=>`smtp-user-enum -M ${s(b.mode||"VRFY")} -U ${s(b.wordlist||"/usr/share/seclists/Usernames/top-usernames-shortlist.txt")} -t ${s(b.target)}`));
app.post("/tools/hydra",        (q,r) => toolRoute(q,r,"hydra",       b=>`hydra ${b.user?"-l "+s(b.user):"-L /usr/share/seclists/Usernames/top-usernames-shortlist.txt"} -P ${s(b.wordlist||"/usr/share/wordlists/rockyou.txt")} ${s(b.flags||"-t 4 -V")} ${s(b.target)} ${s(b.service||"ssh")}`));
app.post("/tools/medusa",       (q,r) => toolRoute(q,r,"medusa",      b=>`medusa -h ${s(b.target)} ${b.user?"-u "+s(b.user):"-U /usr/share/seclists/Usernames/top-usernames-shortlist.txt"} -P ${s(b.wordlist||"/usr/share/wordlists/rockyou.txt")} -M ${s(b.service||"ssh")} ${s(b.flags||"-t 4")}`));
app.post("/tools/ncrack",       (q,r) => toolRoute(q,r,"ncrack",      b=>`ncrack ${s(b.flags||"-v")} ${s(b.target)} -p ${s(b.service||"ssh")}`));
app.post("/tools/responder",    (q,r) => toolRoute(q,r,"responder",   b=>`timeout 30 responder -I ${s(b.interface||"eth0")} ${s(b.flags||"-A")}`));
app.post("/tools/tcpdump",      (q,r) => toolRoute(q,r,"tcpdump",     b=>`tcpdump -i ${s(b.interface||"eth0")} -c ${s(b.count||"100")} ${s(b.filter||"")} -A`));
app.post("/tools/searchsploit", (q,r) => toolRoute(q,r,"searchsploit",b=>`searchsploit "${s(b.query)}"`));
app.post("/tools/curl_headers", (q,r) => toolRoute(q,r,"curl",        b=>`curl -s -I "${s(b.url)}"`));
app.post("/tools/run_command",  (q,r) => toolRoute(q,r,null,          b=>s(b.command)));

// ─── Start ─────────────────────────────────────────────────────────────────
app.listen(PORT, "0.0.0.0", () => {
  console.log(`\n🔥  KaliAI MCP Server v3.0  →  http://0.0.0.0:${PORT}`);
  console.log(`📡  Streaming: SSE enabled on all tool endpoints`);
  console.log(`🔧  Auto-install: ${Object.keys(INSTALL).length} tools covered`);
  console.log(`📖  Self-heal docs: GET /docs/<toolname>\n`);
});
