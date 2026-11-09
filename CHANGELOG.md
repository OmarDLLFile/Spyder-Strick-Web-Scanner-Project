# Changelog

## 2.0.0 — 2026-11-09 (`feature/ai-enterprise-security-upgrade`)

### Added
- `core/finding.py` — Finding model (evidence, confidence, CWE/OWASP/CVSS, dedup key)
- `core/scope.py`, `core/config.py`, `core/rate_limiter.py`, `core/taxonomy.py`,
  `core/correlation.py`, `core/store.py` — scope enforcement, YAML/CLI config,
  token-bucket limiting, OWASP/CWE/CVSS/MITRE mapping, attack-path correlation,
  risk scoring, SQLite scan history
- Crawler: JS-file endpoint extraction, OpenAPI/GraphQL/security.txt discovery,
  framework markers, structured `CrawlResult`; dead commented code removed
- Parser: textarea/select, resolved actions, CSRF/login awareness
- Scanners: blind SQLi, NoSQL, command injection (safe markers), SSTI (safe math),
  SSRF (potential only), JWT, CSRF, cookies, CORS, clickjacking, sensitive-data
  exposure (redacted), rate-limit probe; payload files now loaded with a
  destructive-payload filter
- `scanners/api_scanner.py` — OpenAPI parsing, BOLA/IDOR, missing auth, GraphQL
  introspection, excessive data exposure, mass assignment (opt-in)
- `scanners/enterprise_scanner.py` — SSO/SAML/OAuth discovery, admin exposure,
  cross-tenant IDOR
- `sast/` — pattern SAST for Python/JS/TS/PHP/Java/C#/Go + optional bandit
- `ai/` — Ollama + OpenAI-compatible providers, redaction, prompt-injection
  resistance, strict JSON parsing, audit log; AI never confirms findings
- Reporting: CSV, professional HTML (executive summary, attack paths, AI section),
  static dashboard (`--dashboard`), `--serve`, `--list-scans`
- `engine/scanner.py` — ScanEngine orchestrating crawl→scan→AI→correlate→report→store
- `main.py` — full argparse CLI (backwards-compatible positional URL)
- `tests/` — 20 pytest tests against a local intentionally-vulnerable fixture app
- Docs: `docs/TECHNICAL_ASSESSMENT.md`, `docs/CONFIG.md`, `config.example.yaml`

### Fixed
- SQLi GET bug (payload never sent on GET forms)
- `verify=False` always → TLS verification on by default
- Requester discarding non-200/500/403 responses
- Traversal/redirect scanners bypassing Requester/session/scope
- Cloudflare detection always-true bug
- BOLA host corruption (`127.0.0.1` → `227.0.0.1`)
- SQLite store placeholder mismatch

### Dependencies
- Added `pyyaml`, `pytest` (dev). No framework added; dashboard is static HTML.
