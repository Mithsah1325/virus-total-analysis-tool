# 🛡️ Local File Analyzer — "Mini VirusTotal"

A **Python-based malware analysis and file inspection tool** that mimics the core functionality of **VirusTotal** — completely local, fast, and privacy-friendly.  
This project can **analyze, score, and report the risk** of single or multiple files, combining **hashing**, **entropy analysis**, **string inspection**, **pattern detection**, and optional **VirusTotal integration** via API.

---

## 🚀 Key Features

### 🔍 File Analysis
- Calculates **MD5, SHA1, and SHA256** hashes for each file  
- Retrieves detailed **file metadata** (size, timestamps, extension, etc.)  
- Computes **Shannon entropy** to detect packed/encrypted files  
- Extracts **suspicious keywords** from file contents  
- Scans for **low-level system API patterns** (registry, file, process, network, crypto operations)

### ⚠️ Risk Scoring System
- Assigns a **0–100 score** based on entropy, keywords, and patterns  
- Categorizes files as:
  - ✅ **LOW**
  - ⚠ **MEDIUM**
  - ⚠⚠ **HIGH**
  - ⚠⚠⚠ **CRITICAL**

### 🧠 Multi-File / Directory Scanning
- Supports:
  - Single file
  - Directory scans (recursive optional)
  - Wildcard patterns (`*.exe`, `folder/*.dll`)
  - Comma-separated paths
- Skips oversized files automatically (>100 MB)

### ☁️ VirusTotal API Integration
- Optional **real-time VirusTotal lookup**
- Handles **rate limits** gracefully with exponential backoff

### 📊 Automated Reports
- Saves **individual scan reports** and **batch summaries**
- Includes:
  - File info
  - Hashes
  - Entropy
  - Suspicious strings & patterns
  - VirusTotal results
  - Risk level & recommendations

---

## 🧩 Skills Demonstrated

| Category | Skills |
|-----------|---------|
| 🐍 Python | File I/O, OS operations, data structures, modular design |
| 🧠 Security | Hashing, entropy analysis, signature detection |
| ☁️ API Integration | REST API requests, rate-limit handling, JSON parsing |
| ⚙️ DevOps | Environment variable management via `.env` |
| 🧾 Reporting | Automated report generation, structured file output |
| 🧰 Software Design | CLI menus, error handling, scalable architecture |

---

## 🖼️ Example CLI Interface

