# Technical Assessment — Spyder-Strick (Phase 1, verified 2026-11-09)

## 1. Original architecture (2075 LOC, Python)

- `main.py` — `MiniScanner`, CLI was only `python main.py <url>`, depth hardcoded 2, workers 20.
- `core/requester.py` — single `requests.Session`, `verify=False` always.
- `core/crawler.py` — BFS threaded crawler, robots + sitemap, `<a>` links only; ~200 lines of dead commented-out crawler code; `extract_js_endpoints()` defined but never called.
- `core/parser.py` — forms: `<input>` only.
- `core/reporter.py` — JSON + HTML only, incomplete severity mapping, no CWE/CVSS/OWASP/confidence/evidence.
- `scanners/` — sqli (error-based), xss (reflection), traversal, redirect, headers (4 headers), tech (regex fingerprints).
- `payloads/` — `sqli.txt`, `traversal.txt`, `xss.txt` existed but were never loaded.
- No tests, no CI, no config, `engine/scanner.py` was 0 bytes, `aiohttp`/`selenium` declared but unused.

## 2. Existing capabilities (kept)

Crawling, robots/sitemap discovery, form extraction, error-based SQLi, reflected XSS,
traversal, open redirect, header checks, technology fingerprinting, JSON/HTML reports.

## 3. Critical bugs found (all fixed in `feature/ai-enterprise-security-upgrade`)

1. **SQLi GET bug (critical):** `SQLiScanner.scan_form` called `requester.get(target_url)` with no
   `params`, so the payload was never sent for GET forms. Fixed via `submit_form()` in
   `scanners/common.py`, which sends data as query params for GET.
2. **`verify=False` always** in `Requester` — TLS verification disabled for every scan.
   Now configurable, default `True`; `--no-verify` is opt-in with a warning.
3. **Requester discarded non-200/500/403 responses** (returned `None`), hiding 404/301/302
   evidence. Now returns all responses; retries with backoff only on transient errors.
4. **Traversal/redirect scanners used raw `requests.get`**, bypassing the session, scope and
   rate limiting. Now use the shared `Requester`.
5. **Cloudflare detection bug:** `"Server"` was in the header list, so the check was
   effectively always true. Now checks `CF-RAY`/`CF-Cache-Status` or a Cloudflare `Server` value.
6. **BOLA URL replacement (found during e2e testing):** naive `str.replace("/1", "/2")`
   corrupted `127.0.0.1` into `227.0.0.1`. Fixed to replace only in the URL path.
7. **SQLite store placeholder mismatch** (15 placeholders for 16 columns) — scan history
   silently failed. Fixed; verified `scan_id=1`.

## 4. Missing capabilities (implemented in this upgrade)

Scope/authorization enforcement, rate limiting, config system, Finding model with
confidence + dedup, JS-file endpoint extraction, OpenAPI/GraphQL discovery, blind
SQLi, NoSQL/command/SSTI/SSRF/JWT/CSRF/sensitive-data checks, API scanner (BOLA,
missing auth, GraphQL introspection, excessive data exposure), enterprise scanner
(SSO discovery, admin exposure, cross-tenant IDOR), SAST (7 languages, pattern
rules + optional bandit), modular AI engine (Ollama / OpenAI-compatible, redaction,
prompt-injection resistance, JSON validation, audit log, never confirms), correlation
+ attack paths, risk scoring, CSV reports, SQLite scan history, static dashboard,
argparse CLI, pytest suite with a local vulnerable fixture app.

## 5. AI integration strategy

Traditional detection is independent and runs first. The AI engine (`ai/`) receives
only redacted, delimited finding summaries, returns validated JSON (summary,
correlations, per-finding confidence adjustments, prioritisation), and may only
downgrade/upgrade confidence up to `strong`. Providers are pluggable (`ai/providers.py`).
If no provider is reachable, scanning continues unchanged.

## 6. Enterprise scalability

Threaded scanning with configurable workers, token-bucket rate limiting, request
budget (`--max-requests`), SQLite history, resumable-by-design stateless scans.
Not implemented: distributed scanning, async (aiohttp) engine, scan resumption
from a checkpoint, headless-browser JS rendering (static JS analysis only),
PDF export, DOM/stored XSS beyond re-fetch checks, time-based blind SQLi,
authenticated multi-role SSO flow testing.

## 7. Remaining limitations (honest)

- No headless browser: SPA routes are found only via static JS/link analysis.
- Blind SQLi uses boolean response comparison; echoing apps can produce false positives.
- SSRF is `potential` only by design — no internal fetch is ever performed.
- Mass-assignment write probe is disabled by default (requires code-level opt-in).
- AI was tested only in disabled/unavailable mode (no live Ollama/OpenAI server in
  this environment); provider code paths are implemented but not live-verified.
- PDF export not implemented (JSON/CSV/HTML only).
