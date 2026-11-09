# Spyder-Strick — AI-Powered Enterprise Security Assessment Platform

> **Crawl · Detect · Correlate · Report** — for authorized security assessments only.

Spyder-Strick discovers and tests web applications, APIs and enterprise apps,
correlates findings into attack paths, optionally analyses them with a local or
OpenAI-compatible LLM, and produces JSON/CSV/HTML reports plus a static dashboard.

## Authorization — read first

Only scan targets you are authorised to test. Local targets (`localhost`,
`127.0.0.1`, `*.test`, `*.local`) need no flag; any other target requires
`--authorize`, and every request is scope-checked (out-of-scope requests are blocked).
Destructive testing is disabled by default: no `DROP`/`DELETE`/`xp_cmdshell`/
shutdown payloads are ever sent, no data is exfiltrated, and SSRF is reported as
`potential` only.

## Installation

```bash
git clone https://github.com/OmarDLLFile/Spyder-Strick-Web-Scanner-Project.git
cd Spyder-Strick-Web-Scanner-Project
python -m venv .venv && .venv/bin/pip install -r requirements.txt
```

## Usage

```bash
# Local test target
.venv/bin/python main.py -u http://localhost:8000

# Remote target (only with written permission)
.venv/bin/python main.py -u https://target.example --authorize --depth 2 --intensity medium

# SAST + AI (Ollama local model; OpenAI-compatible needs AI_API_KEY in env)
.venv/bin/python main.py -u http://localhost:8000 --sast ./myapp --ai-provider ollama --ai-model llama3.1

# History, dashboard, serving reports
.venv/bin/python main.py --list-scans
.venv/bin/python main.py --dashboard
.venv/bin/python main.py --serve --serve-port 8080
```

See `docs/CONFIG.md` for the full CLI and `config.example.yaml` for YAML config.

## Features

- **Crawling:** BFS threaded crawl, robots/sitemap, JS-file endpoint extraction,
  OpenAPI/Swagger + GraphQL discovery, framework fingerprinting, forms
- **Detection:** SQLi (error + boolean-blind), NoSQL, XSS (reflected + stored check),
  traversal/LFI, open redirect, command injection, SSTI, SSRF, headers/cookies/CORS,
  clickjacking, CSRF, JWT, sensitive-data exposure, rate-limit probe
- **API security:** OpenAPI parsing, BOLA/IDOR, missing auth, GraphQL introspection,
  excessive data exposure
- **Enterprise:** SSO/SAML/OAuth/OIDC discovery, admin exposure, cross-tenant IDOR
- **SAST:** pattern scanner for Python, JS/TS, PHP, Java, C#, Go (+ optional bandit)
- **AI:** Ollama / OpenAI-compatible providers; redaction, prompt-injection
  resistance, JSON validation, audit log; AI never marks a finding `confirmed`
- **Correlation:** attack paths, MITRE ATT&CK mapping, OWASP/CWE/CVSS, risk scoring, dedup
- **Reporting:** JSON, CSV, HTML (executive summary, attack paths, AI analysis),
  SQLite history, static dashboard

## Testing

```bash
.venv/bin/python -m pytest tests/ -q   # 20 tests against a local vulnerable fixture app
```

## Limitations (honest)

- No headless-browser JS rendering — SPA routes are found by static JS analysis only.
- No PDF export (JSON/CSV/HTML only). No distributed scanning or scan resumption.
- AI was tested in disabled/unavailable mode here; live Ollama/OpenAI verification
  needs a running provider. See `docs/TECHNICAL_ASSESSMENT.md`.
