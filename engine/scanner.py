"""ScanEngine: orchestrates crawl -> discover -> scan -> AI -> correlate -> report -> store.
main.py is a thin CLI over this engine. MiniScanner is kept as an alias.
"""
from __future__ import annotations
import logging, threading, time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from urllib.parse import urlparse, parse_qs

from core.config import ScanConfig
from core.correlation import correlate
from core.crawler import Crawler
from core.finding import dedupe
from core.rate_limiter import RateLimiter
from core.reporter import ReportGenerator
from core.requester import Requester
from core.scope import Scope
from core.store import ScanStore
from core.taxonomy import enrich
from core.utils import Utils
from ai.engine import AIEngine, AIConfig
from scanners.advanced_scanner import AdvancedScanner
from scanners.api_scanner import APIScanner
from scanners.enterprise_scanner import EnterpriseScanner
from scanners.headers_scanner import HeaderScanner
from scanners.redirect_scanner import OpenRedirectScanner
from scanners.sqli_scanner import SQLiScanner
from scanners.tech_scanner import TechnologyScanner
from scanners.traversal_scanner import DirectoryTraversalScanner
from scanners.xss_scanner import XSS_Scanner

log = logging.getLogger("spyder.engine")
STATIC_EXT = (".jpg", ".jpeg", ".png", ".gif", ".css", ".svg", ".woff", ".woff2", ".ico", ".mp4", ".pdf")


class ScanEngine:
    def __init__(self, config: ScanConfig):
        self.config = config
        self.scope = Scope(config.target_url, authorized=config.authorize, allow_hosts=config.allow_hosts)
        self.scope.check_authorization()
        self.rate_limiter = RateLimiter(delay=config.delay, max_requests=config.max_requests)
        self.requester = Requester(config, scope=self.scope, rate_limiter=self.rate_limiter)
        self.crawler = Crawler(self.requester, config.target_url, depth=config.depth)
        self.reporter = ReportGenerator(config.output_dir)
        self.reporter.target = config.target_url
        self.lock = threading.Lock()
        self._seen_urls = set()

    # -- orchestration -----------------------------------------------------
    def run(self):
        started = datetime.now(timezone.utc).isoformat()
        Utils.print_banner()
        print(f"[+] Target: {self.config.target_url}  (intensity={self.config.intensity}, depth={self.config.depth})")
        t0 = time.time()
        crawl = self.crawler.crawl()
        print(f"[+] Crawled {len(crawl.urls)} URLs, {len(crawl.forms)} forms, "
              f"{len(crawl.endpoints)} endpoints, {len(crawl.js_endpoints)} JS endpoints; "
              f"technologies: {', '.join(crawl.technologies) or 'none'}")
        findings = []
        findings.extend(self._scan_urls(crawl.urls))
        findings.extend(self._scan_forms(crawl.forms))
        findings.extend(self._scan_apis(crawl))
        findings.extend(self._scan_enterprise(crawl))
        if self.config.sast_path:
            from sast.engine import SASTScanner
            sast = SASTScanner().scan_path(self.config.sast_path)
            print(f"[+] SAST: {len(sast)} findings in {self.config.sast_path}")
            findings.extend(sast)
        findings = dedupe(findings)
        for f in findings:
            enrich(f)
        self.reporter.results = findings
        # AI (optional, never blocks traditional results)
        ai = AIEngine(AIConfig(provider=self.config.ai_provider, model=self.config.ai_model,
                               base_url=self.config.ai_base_url),
                      audit_path=f"{self.config.output_dir}/ai_audit.log.jsonl")
        ai_result = ai.analyse(findings, target=self.config.target_url, crawl_summary=crawl.to_dict())
        self.reporter.ai_analysis = ai_result
        self.reporter.correlation = correlate(findings)
        paths = self.reporter.generate_all()
        scan_id = None
        try:
            store = ScanStore(f"{self.config.output_dir}/spyder.db")
            scan_id = store.save_scan(self.config.target_url, findings, started_at=started)
            store.close()
        except Exception as exc:
            log.warning("scan history store failed: %s", exc)
        self.reporter.print_summary()
        print(f"[+] Scan finished in {time.time() - t0:.1f}s; scan_id={scan_id}; reports: {paths}")
        return {"findings": findings, "crawl": crawl, "ai": ai_result,
                "correlation": self.reporter.correlation, "reports": paths, "scan_id": scan_id}

    # -- per-URL scanning ----------------------------------------------------
    def _should_scan(self, url):
        if url.lower().endswith(STATIC_EXT):
            return False
        return self.scope.is_allowed(url)

    def _scan_urls(self, urls):
        findings = []
        header_scanner = HeaderScanner(self.requester)
        tech = TechnologyScanner()
        adv = AdvancedScanner(self.requester)
        sqli, xss = SQLiScanner(self.requester, self.config.payload_limit), XSS_Scanner(self.requester)
        trav, redir = DirectoryTraversalScanner(self.requester), OpenRedirectScanner(self.requester)

        def scan_one(url):
            if not self._should_scan(url):
                return []
            with self.lock:
                if url in self._seen_urls:
                    return []
                self._seen_urls.add(url)
            out = []
            try:
                resp = self.requester.get(url)
                if not resp:
                    return out
                techs = tech.scan(resp)
                if techs:
                    out.append(self._info(url, "Technology Fingerprint", ", ".join(techs)))
                out.extend(header_scanner.scan_findings(url, resp))
                out.extend(header_scanner.scan_cookies(url, resp))
                out.extend(header_scanner.scan_cors(url))
                out.extend(adv.scan_sensitive_data(url, resp))
                out.extend(adv.scan_jwt(url, resp))
                out.extend(trav.scan_url(url))
                out.extend(redir.scan_url(url))
                out.extend(sqli.scan_url(url))
                out.extend(xss.scan_url(url))
                out.extend(adv.scan_nosql(url))
                out.extend(adv.scan_command_injection(url))
                out.extend(adv.scan_ssti(url))
                out.extend(adv.scan_ssrf(url))
                out.extend(adv.scan_rate_limit(url) if self.config.intensity == "high" else [])
            except Exception as exc:
                log.debug("scan %s failed: %s", url, exc)
            return out

        with ThreadPoolExecutor(max_workers=self.config.workers) as ex:
            for f in as_completed([ex.submit(scan_one, u) for u in urls]):
                try:
                    findings.extend(f.result())
                except Exception as exc:
                    log.debug("scan task failed: %s", exc)
        return findings

    def _scan_forms(self, forms):
        findings = []
        sqli = SQLiScanner(self.requester, self.config.payload_limit)
        xss = XSS_Scanner(self.requester)
        adv = AdvancedScanner(self.requester)
        for entry in forms:
            page, form = entry.get("page", ""), entry.get("form", {})
            try:
                findings.extend(xss.scan_form(page, form))
                findings.extend(sqli.scan_form(page, form))
                findings.extend(adv.scan_csrf(page, [entry]))
                findings.extend(adv.scan_auth_forms(page, [entry]))
            except Exception as exc:
                log.debug("form scan failed on %s: %s", page, exc)
        return findings

    def _scan_apis(self, crawl):
        findings = []
        api = APIScanner(self.requester)
        spec_endpoints = []
        if self.config.openapi:
            spec = api.load_spec(self.config.openapi)
            if spec:
                spec_endpoints = api.endpoints_from_spec(spec, self.config.target_url)
        else:
            for spec in crawl.api_specs:
                spec_endpoints.extend(api.endpoints_from_spec(spec["spec"], self.config.target_url))
        for ep in crawl.endpoints:
            if ep not in [e["url"] for e in spec_endpoints]:
                spec_endpoints.append({"url": ep, "method": "GET"})
        if spec_endpoints:
            print(f"[+] API scan: {len(spec_endpoints)} endpoints")
            findings.extend(api.scan_endpoints(spec_endpoints, self.config.target_url))
        for gql in crawl.graphql_endpoints:
            findings.extend(api.scan_graphql(gql))
        return findings

    def _scan_enterprise(self, crawl):
        ent = EnterpriseScanner(self.requester)
        findings = []
        findings.extend(ent.scan_sso_discovery(self.config.target_url))
        findings.extend(ent.scan_admin_exposure(self.config.target_url))
        for url in crawl.urls:
            if parse_qs(urlparse(url).query):
                findings.extend(ent.scan_cross_tenant(url))
        return findings

    @staticmethod
    def _info(url, ftype, evidence):
        from core.finding import Finding
        return Finding(type=ftype, url=url, evidence=evidence, severity="info",
                       confidence="informational", scanner="tech")


# Backwards-compatible alias: the old CLI class name.
MiniScanner = ScanEngine
