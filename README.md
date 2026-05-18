# Spider Striker — Web Crawler & Vulnerability Scanner

> **Lightweight · Modular · Security-Oriented**  
> Built for educational purposes and authorized penetration testing.

---

## Overview

**Spider Striker** is a lightweight web crawling and vulnerability scanning tool designed to:
- Map web applications and discover hidden endpoints
- Perform basic security checks on extracted URLs
- Help identify potential attack surfaces in web applications

> Intended for **educational** and **ethical security testing** purposes only.

---

## Features

### 🕷️ Web Crawling Engine
- Recursive crawling of target websites with depth control
- URL discovery, extraction, and normalization
- JavaScript-based endpoint detection
- Parameter discovery in URLs

### 🔍 Smart Discovery
- `robots.txt` parsing support
- `sitemap.xml` detection and extraction
- Hidden endpoint enumeration
- Basic JS file analysis for endpoints

### 🔗 URL Management
- Duplicate URL filtering
- Query parameter extraction
- Structured URL storage

### 🛡️ Vulnerability Scanning
- Detection of common injection patterns
- Basic parameter fuzzing
- Reflection-based checks (XSS indicators)
- Heuristic-based risk scoring

---

## Architecture

```
Spider-Striker/
├── core/
│   ├── crawler.py       → Web crawling logic (BFS + threading)
│   ├── parser.py        → HTML, JS, robots.txt, sitemap parsing
│   ├── requester.py     → HTTP request handling
│   └── utils.py         → URL normalization, filtering helpers
├── scanners/
│   ├── sqli_scanner.py      → SQL Injection checks
│   ├── xss_scanner.py       → XSS reflection detection
│   ├── traversal_scanner.py → Path traversal checks
│   ├── redirect_scanner.py  → Open redirect detection
│   ├── headers_scanner.py   → Security headers analysis
│   └── tech_scanner.py      → Technology fingerprinting
├── payloads/
│   ├── sqli.txt
│   ├── xss.txt
│   └── traversal.txt
├── reports/             → Scan output reports
├── main.py              → Entry point
└── requirements.txt
```

---

## Workflow

```
[1] Input Target URL
        ↓
[2] Crawl Website (BFS + Threading)
        ↓
[3] Extract Endpoints (robots, sitemap, HTML, JS)
        ↓
[4] Clean & Normalize URLs
        ↓
[5] Run Vulnerability Scanners
        ↓
[6] Output Structured Report
```

---

## Requirements

```
python >= 3.8
requests
beautifulsoup4
lxml
```

---

## Installation

```bash
git clone https://github.com/OmarDLLFile/Spyder-Strick-Web-Scanner-Project.git
cd Spyder-Strick-Web-Scanner-Project
pip install -r requirements.txt
```

---

## Usage

```bash
python main.py -u https://example.com
```

---

## Output Example

```
[+] Crawling started...
[+] Found 124 URLs
[+] Discovered 12 hidden endpoints
[+] Scanning completed

[!] Potential Issues:
  - XSS reflection detected:     /search?q=
  - Suspicious parameter:        /login?redirect=
  - Missing security header:     X-Frame-Options
```

---

## Limitations

| Limitation | Details |
|---|---|
| Not full DAST | Heuristic-based, not comprehensive |
| No auth handling | Cannot scan authenticated pages |
| No WAF bypass | Basic payloads only |
| False positives | Heuristics may flag false issues |

---

## Future Improvements

- [ ] Advanced JS reverse engineering
- [ ] Better crawler scheduling system
- [ ] ML-based anomaly detection
- [ ] Authentication-aware crawling
- [ ] Burp Suite integration

---

## Ethical Use

This tool is intended **only** for:
- Educational purposes
- Authorized penetration testing
- Security research in controlled environments

> Unauthorized use against systems without explicit permission is **strictly prohibited**.

---

## Author

**Omar**  
Security & Systems Enthusiast  
[GitHub: OmarDLLFile](https://github.com/OmarDLLFile)
