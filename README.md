<div align="center">

# 🐉 KaliAI MCP Pentest Tool

**A containerized AI-powered pentesting assistant built on the Model Context Protocol**

[![Docker](https://img.shields.io/badge/Docker-hariprasaanth%2Fkaliai-2496ED?style=flat-square&logo=docker&logoColor=white)](https://hub.docker.com/r/hariprasaanth/kaliai)
[![Node.js](https://img.shields.io/badge/Node.js-MCP%20Server-339933?style=flat-square&logo=node.js&logoColor=white)](https://nodejs.org)
[![Kali Linux](https://img.shields.io/badge/Kali_Linux-Full%20Suite-557C94?style=flat-square&logo=kalilinux&logoColor=white)](https://www.kali.org)
[![License](https://img.shields.io/badge/License-Ethical%20Use%20Only-red?style=flat-square)](#%EF%B8%8F-security--legal-warning)

> Run a full **Kali Linux** security suite with an integrated **Node.js MCP server** for automated, AI-assisted security workflows — all in a single Docker container.

</div>

---

## 📖 Overview

This repository provides a containerized environment and server-side implementation for **KaliAI** — a pentesting assistant leveraging the [Model Context Protocol (MCP)](https://modelcontextprotocol.io). It combines the power of Kali Linux's security toolkit with an AI-driven server layer, enabling intelligent, automated security testing pipelines.

---

## ⚡ Quick Start

### 1. 🐳 Pull the Docker Image

The `kaliai` image comes pre-configured with all necessary security tools and environment variables.

```bash
docker pull hariprasaanth/kaliai
```

### 2. 🚀 Run the Container

Run the container in interactive mode with privileged access to allow network scanning and tool execution.

```bash
docker run -it --rm --privileged -p 3001:3001 hariprasaanth/kaliai:latest /bin/bash
```

| Flag | Description |
|------|-------------|
| `-it` | Interactive terminal |
| `--rm` | Auto-remove container on exit |
| `--privileged` | Grants access to host network stack *(required for many Kali tools)* |
| `-p 3001:3001` | Maps the MCP server port for communication |

---

## 🛠️ Local Setup & Development

Once inside the container (or on your local machine), follow these steps to set up the MCP server.

### 3. 📦 Clone the Repository

```bash
git clone https://github.com/Hari-prasaanth/pentest-mcp.git
cd pentest-mcp
```

### 4. 🟢 Install Node.js and NPM

If NPM is not already installed, use the official installer:

```bash
curl -L https://www.npmjs.com/install.sh | sh
```

### 5. 📥 Initialize and Install Dependencies

Set up the Node.js environment and install the Express framework.

```bash
npm init -y
npm install express
```

### 6. ▶️ Start the Server

Run the MCP server to begin handling requests.

```bash
node server.js
```

The server will start listening on **port 3001** and is ready to accept MCP requests. 🎯

---

## 🗂️ Project Structure

```
pentest-mcp/
├── 🖥️  server.js          # Entry point for the MCP pentest server
├── 📦  package.json       # Node.js dependencies and scripts
└── 📁  src/               # MCP protocol implementation source
```

| Component | Description |
|-----------|-------------|
| `hariprasaanth/kaliai` | Base Docker image with the full Kali Linux toolset |
| `server.js` | Entry point for the MCP pentest server |
| `pentest-mcp/` | Source code for the Model Context Protocol implementation |

---

## ⚠️ Security & Legal Warning

> [!CAUTION]
> **Usage of this tool for attacking targets without prior mutual consent is illegal.**

- 🔴 Only use this tool on systems you **own** or have **explicit written permission** to test.
- 🔴 The end user is solely responsible for compliance with all applicable **local, state, and federal laws**.
- 🔴 Developers **assume no liability** and are not responsible for any misuse or damage caused by this program.
- 🟢 This tool is intended for **authorized penetration testing**, **CTF challenges**, **security research**, and **educational purposes** only.

---

## 🤝 Contributing

Contributions, issues, and feature requests are welcome! Feel free to open a [pull request](https://github.com/Hari-prasaanth/pentest-mcp/pulls) or file an [issue](https://github.com/Hari-prasaanth/pentest-mcp/issues).

---

<div align="center">

Made with ☕ and 🔐 by [Hari Prasaanth](https://github.com/Hari-prasaanth)

</div>
