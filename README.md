# ☢️ NPM Detonator

**NPM Detonator** is an advanced, eBPF-powered malware analysis sandbox designed specifically for detecting software supply chain attacks in the Node.js ecosystem. 

It isolates `npm install` executions inside restricted Docker containers, tracks their kernel-level syscalls using an invisible eBPF sensor, streams telemetry to Apache Kafka, and analyzes the behavior using a hybrid AI threat engine (Heuristics + OpenRouter LLM).

![License](https://img.shields.io/badge/license-MIT-blue)
![Go Version](https://img.shields.io/badge/go-1.24.2+-00ADD8.svg)
![Python](https://img.shields.io/badge/python-3.10+-3776AB.svg)

---

## ✨ Key Features

- **🛡️ Containerized Detonation:** Runs `npm install` inside an ephemeral, network-isolated, PID-restricted `node:22-alpine` container.
- **👁️ Invisible eBPF Sensor:** Uses kernel tracepoints (`sys_enter_execve`, `openat`, `connect`, `write`, `unlinkat`) to track exactly what the package does at the host level, bypassing container boundaries and anti-analysis tricks.
- **📡 Kafka Telemetry:** Streams massive volumes of syscall data in real-time to an Apache Kafka cluster (KRaft mode).
- **🧠 AI Threat Analyst:** A Python-based rule engine that catches credential theft, persistence, and C2 activity, backed by OpenRouter LLM to generate staged Attack Chain Narratives.
- **📊 Embedded Web Dashboard:** A beautiful, single-page HTML dashboard served directly from the Go binary to visualize threat reports.
- **🔍 Static Source Scanning:** Analyzes package source code before detonation for obfuscated payloads and dangerous lifecycle hooks.

---

## 🏗️ Architecture

```text
1. Orchestrator (Go)     2. Sensor (eBPF)       3. Telemetry (Kafka)      4. AI Analyst (Python)
┌─────────────────┐      ┌───────────────┐      ┌─────────────────┐       ┌──────────────────┐
│ docker run node │ ───▶ │ sys_enter_*   │ ───▶ │ topic: syscalls │ ────▶ │ rules + LLM      │
└─────────────────┘      └───────────────┘      └─────────────────┘       └──────────────────┘
        │                                                                           │
        └───────────────────────────────────────────────────────────────────────────┘
                                       5. Web Dashboard (Go)
```

---

## 🚀 Installation & Setup

### Prerequisites
- **Linux** (WSL2 Ubuntu 22.04+ recommended)
- **Kernel** with eBPF support (`CONFIG_BPF=y`)
- **Go** 1.24.2 or higher
- **Python** 3.10+
- **Docker Desktop** (with WSL Integration enabled)

### 1. Build the Detonator Binary
```bash
git clone https://github.com/yourusername/npm-detonator.git
cd npm-detonator
go build -o detonator ./cmd/detonator
```

### 2. Start Kafka
```bash
docker compose -f infra/docker-compose.yml up -d
```

### 3. Setup the AI Analyzer
```bash
cd analyzer
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
```
*Note: Edit `analyzer/.env` and add your free OpenRouter API key.*

---

## 💻 Usage

### 1. Start the AI Threat Analyst (Terminal 1)
The analyzer listens to Kafka and evaluates packages in real-time.
```bash
source analyzer/.venv/bin/activate
python3 -m analyzer
```

### 2. Detonate a Package (Terminal 2)
Detonate a package directly from the npm registry (requires `--allow-network`):
```bash
sudo ./detonator --package lodash --allow-network
```

Or detonate a local `.tgz` tarball (completely air-gapped):
```bash
sudo ./detonator --package evil-pkg --local-package ./evil-pkg-1.0.0.tgz
```

### 3. Pre-Detonation Static Scan
Scan a package's source code before running it:
```bash
python3 -m analyzer --scan ./test-packages/evil-pkg/
```

### 4. View the Threat Dashboard
Serve the embedded HTML dashboard:
```bash
./detonator --dashboard --port 8080
```
Then navigate to `http://localhost:8080` to view historical threat reports, scores, and AI attack chain narratives.

### 5. Batch Scan Dependencies
Scan all transitive dependencies of an entire project using a lockfile (`package-lock.json`, `pnpm-lock.yaml`, or plain `package.json`):
```bash
sudo ./detonator --lockfile /path/to/project/package-lock.json --allow-network --limit 50
```

---

## 🔬 Threat Detection Capabilities

The AI Analyst maps findings to **MITRE ATT&CK** techniques:

| Threat Category | Detected Behavior | MITRE ID |
|-----------------|-------------------|----------|
| **Credential Theft** | Reading `/etc/shadow`, `~/.ssh/id_rsa`, `.npmrc` | T1003.008, T1552 |
| **Reconnaissance** | Executing `whoami`, `uname`, reading `/etc/passwd` | T1082, T1087 |
| **Persistence** | Modifying `/etc/crontab`, `chmod` payload execution | T1053.003, T1222 |
| **Exfiltration** | Executing `curl`, `wget`, or unexpected outbound TCP | T1105, T1071.001 |
| **Anti-Forensics**| Deleting files (`unlinkat`), clearing bash history | T1070.004 |

---

## ⚠️ Disclaimer

**This tool executes actual malware.** While the Docker container restricts network access and limits memory/PIDs, zero-day container escapes exist. 

**DO NOT** run this on your personal host machine without understanding the risks. Use a dedicated, disposable Virtual Machine or WSL2 environment. The authors are not responsible for compromised hosts.

---

## 📝 License

This project is licensed under the MIT License - see the LICENSE file for details.
