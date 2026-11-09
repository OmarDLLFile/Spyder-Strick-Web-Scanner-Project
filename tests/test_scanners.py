"""Scanner / core tests against the local vulnerable fixture app."""
import os, json, tempfile
import pytest

from core.config import ScanConfig
from core.crawler import Crawler
from core.finding import Finding, dedupe
from core.parser import FormParser
from core.rate_limiter import RateLimiter
from core.requester import Requester
from core.scope import Scope
from core.correlation import correlate, risk_score
from scanners.sqli_scanner import SQLiScanner
from scanners.xss_scanner import XSS_Scanner
from scanners.traversal_scanner import DirectoryTraversalScanner
from scanners.redirect_scanner import OpenRedirectScanner
from scanners.headers_scanner import HeaderScanner
from scanners.api_scanner import APIScanner
from scanners.enterprise_scanner import EnterpriseScanner
from scanners.advanced_scanner import AdvancedScanner


def _req(base):
    cfg = ScanConfig(target_url=base, verify_tls=True, delay=0)
    scope = Scope(base, authorized=True)
    return Requester(cfg, scope=scope, rate_limiter=RateLimiter(0))


def test_scope_blocks_out_of_scope():
    scope = Scope("http://127.0.0.1:8000", authorized=False)
    assert not scope.is_allowed("http://evil.example/x")
    with pytest.raises(PermissionError):
        scope.enforce("http://evil.example/x")


def test_scope_requires_authorization_for_remote():
    with pytest.raises(ValueError, match="--authorize"):
        Scope("https://example.com", authorized=False).check_authorization()
    Scope("https://example.com", authorized=True).check_authorization()
    Scope("http://localhost:8000").check_authorization()  # local needs no flag


def test_requester_returns_non_200(app_server):
    r = _req(app_server)
    resp = r.get(f"{app_server}/does-not-exist")
    assert resp is not None and resp.status_code == 404  # old code discarded non-200/500/403


def test_finding_dedup_and_confidence_guard():
    a = Finding(type="SQL Injection", url="http://x/a?id=1", param="id", evidence="err")
    b = Finding(type="SQL Injection", url="http://x/a?id=1", param="id", evidence="err2")
    assert len(dedupe([a, b])) == 1
    c = Finding(type="SQL Injection", url="http://x/a", confidence="confirmed")  # no evidence
    assert c.confidence == "potential"


def test_sqli_get_fix(app_server):
    # GET form: payload must actually be sent (old bug: requester.get(target) without data)
    r = _req(app_server)
    form = {"action": "/search", "method": "get",
            "inputs": [{"name": "q", "type": "text"}]}
    findings = SQLiScanner(r).scan_form(f"{app_server}/", form)
    assert findings, "SQLi error-based detection failed on GET form"
    assert findings[0].confidence == "confirmed"
    assert findings[0].cwe == "CWE-89"


def test_sqli_url_scan(app_server):
    r = _req(app_server)
    findings = SQLiScanner(r).scan_url(f"{app_server}/search?q=test")
    assert any(f.type == "SQL Injection" for f in findings)


def test_xss_reflection(app_server):
    r = _req(app_server)
    findings = XSS_Scanner(r).scan_url(f"{app_server}/search?q=test")
    assert any(f.type == "Cross-Site Scripting" for f in findings)


def test_traversal(app_server):
    r = _req(app_server)
    findings = DirectoryTraversalScanner(r).scan_url(f"{app_server}/file?file=x")
    assert any(f.type == "Directory Traversal" and f.confidence == "confirmed" for f in findings)


def test_redirect(app_server):
    r = _req(app_server)
    findings = OpenRedirectScanner(r).scan_url(f"{app_server}/go?next=/home")
    assert any(f.type == "Open Redirect" for f in findings)


def test_headers(app_server):
    r = _req(app_server)
    resp = r.get(f"{app_server}/page")
    missing = HeaderScanner().scan(resp)
    assert "Content-Security-Policy" in missing
    findings = HeaderScanner().scan_findings(f"{app_server}/page", resp)
    assert any(f.type == "Missing Security Headers" for f in findings)
    assert any(f.type == "Clickjacking" for f in findings)


def test_parser_textarea_select_and_action_resolution():
    html = ('<form action="/login" method="post"><textarea name="bio">x</textarea>'
            '<select name="role"><option value="user">user</option></select>'
            '<input type="hidden" name="csrf_token" value="1"></form>')
    forms = FormParser.extract_forms(html, page_url="http://127.0.0.1:1/page")
    assert forms[0]["action"] == "http://127.0.0.1:1/login"
    names = {i["name"] for i in forms[0]["inputs"]}
    assert {"bio", "role", "csrf_token"} <= names
    assert forms[0]["has_csrf_token"] is True


def test_crawler_js_endpoints(app_server):
    r = _req(app_server)
    c = Crawler(r, app_server, depth=1)
    result = c.crawl()
    assert f"{app_server}/search?q=test" in result.urls or any("/search" in u for u in result.urls)
    assert any("/api/users" in e for e in result.js_endpoints), result.js_endpoints
    assert any(f["form"]["action"].endswith("/search") for f in result.forms)
    assert any(s["url"].endswith("/openapi.json") for s in result.api_specs)


def test_api_bola_and_graphql(app_server):
    r = _req(app_server)
    api = APIScanner(r)
    spec = api.load_spec(f"{app_server}/openapi.json")
    assert spec and "paths" in spec
    eps = api.endpoints_from_spec(spec, app_server)
    assert eps
    findings = api.scan_endpoints(eps, app_server)
    # /api/users returns sensitive fields unauthenticated
    assert any(f.type in ("Missing Authentication", "Broken Object Level Authorization") for f in findings)
    gql = api.scan_graphql(f"{app_server}/graphql")
    assert any(f.type == "GraphQL Introspection Enabled" for f in gql)


def test_bola_does_not_corrupt_host(app_server):
    # Regression: naive str.replace of "/1" corrupted 127.0.0.1 -> 227.0.0.1
    r = _req(app_server)
    findings = APIScanner(r)._test_bola(f"{app_server}/api/users/1")
    assert any(f.type == "Broken Object Level Authorization" for f in findings)
    assert all("127.0.0.1" in f.url for f in findings)


def test_enterprise_admin_and_sso(app_server):
    r = _req(app_server)
    ent = EnterpriseScanner(r)
    assert any(f.type == "Admin Interface Exposed" for f in ent.scan_admin_exposure(app_server))
    assert any(f.type == "SSO Misconfiguration" for f in ent.scan_sso_discovery(app_server))


def test_correlation_attack_path():
    fs = [Finding(type="Missing Authentication", url="http://x/api/users/1", evidence="200", confidence="strong", severity="high"),
          Finding(type="Broken Object Level Authorization", url="http://x/api/users/1", evidence="diff", confidence="strong", severity="high"),
          Finding(type="Excessive Data Exposure", url="http://x/api/users/1", evidence="keys", confidence="potential", severity="medium")]
    corr = correlate(fs)
    assert corr["attack_paths"], "expected an attack path chain"
    assert 0 < risk_score(fs[0]) <= 10


def test_sast(tmp_path):
    from sast.engine import SASTScanner
    f = tmp_path / "bad.py"
    f.write_text('api_key = "AKIAIOSFODNN7EXAMPLE"\nimport pickle\npickle.loads(data)\n')
    findings = SASTScanner().scan_file(str(f))
    types = [x.type for x in findings]
    assert any("Hardcoded credential" in t for t in types)
    assert any("pickle" in t for t in types)
    assert all("AKIAIOSFODNN7EXAMPLE" not in x.evidence for x in findings)  # redacted


def test_ai_disabled_fallback():
    from ai.engine import AIEngine, AIConfig
    ai = AIEngine(AIConfig(provider="none"))
    out = ai.analyse([Finding(type="SQL Injection", url="http://x/", evidence="err", confidence="confirmed")])
    assert out["ai_enabled"] is False
    ai2 = AIEngine(AIConfig(provider="ollama", base_url="http://127.0.0.1:1"))
    out2 = ai2.analyse([])
    assert out2["ai_enabled"] is False  # no server -> graceful, no crash


def test_reporter_formats(tmp_path):
    from core.reporter import ReportGenerator
    rg = ReportGenerator(str(tmp_path))
    rg.target = "http://127.0.0.1/test"
    rg.add_result(Finding(type="SQL Injection", url="http://127.0.0.1/search?q=1", param="q",
                          payload="'", evidence="sql syntax error", confidence="confirmed", severity="high"))
    paths = rg.generate_all()
    assert os.path.exists(paths["json"]) and os.path.exists(paths["html"]) and os.path.exists(paths["csv"])
    data = json.load(open(paths["json"]))
    assert data["total_findings"] == 1 and data["findings"][0]["cwe"] == "CWE-89"
    assert "Executive Summary" in open(paths["html"]).read()
    assert "SQL Injection" in open(paths["csv"]).read()


def test_sensitive_data_redaction(app_server):
    r = _req(app_server)
    resp = r.get(f"{app_server}/api/users/1")
    findings = AdvancedScanner(r).scan_sensitive_data(f"{app_server}/api/users/1", resp)
    assert findings
    assert "secret1" not in json.dumps([f.to_dict() for f in findings])
