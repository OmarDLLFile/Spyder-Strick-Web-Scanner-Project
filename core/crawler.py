"""BFS threaded crawler with structured discovery.

Discovers: links, forms, JS files + JS endpoints, robots/sitemap,
security.txt, OpenAPI specs, GraphQL endpoints, framework markers,
API/WebSocket endpoints. Headless JS rendering / SPA execution is NOT
implemented — JS is analysed statically (see README limitations).
"""
from __future__ import annotations
import json, re, threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from urllib.parse import urljoin, urlparse, urldefrag, parse_qs, urlencode, urlunparse

from bs4 import BeautifulSoup
from core.parser import FormParser
from core.utils import Utils

JS_ENDPOINT_PATTERNS = [
    r"""["'](/api/[^"'\s]*)["']""",
    r"""["'](/graphql[^"'\s]*)["']""",
    r"""fetch\(\s*["']([^"']+)["']""",
    r"""axios\.(?:get|post|put|delete)\(\s*["']([^"']+)["']""",
    r"""XMLHttpRequest[^;]*open\(\s*["'][A-Z]+["']\s*,\s*["']([^"']+)["']""",
    r"""url\s*:\s*["']([^"']+/api/[^"']*)["']""",
    r"""["'](https?://[^"'\s]+/api/[^"'\s]*)["']""",
]
FRAMEWORK_MARKERS = {
    "React": [r"_reactRootContainer", r"react-dom", r"data-reactroot", r"__REACT"],
    "Vue.js": [r"vue(\.min)?\.js", r"data-v-", r"__VUE__"],
    "Angular": [r"ng-app", r"ng-version", r"angular(\.min)?\.js"],
    "Next.js": [r"__NEXT_DATA__", r"_next/static"],
    "Nuxt": [r"__NUXT__"],
    "Svelte": [r"svelte"],
}
OPENAPI_PATHS = ["/openapi.json", "/swagger.json", "/api-docs", "/v3/api-docs",
                 "/swagger/v1/swagger.json", "/openapi.yaml"]
GRAPHQL_PATHS = ["/graphql", "/api/graphql"]
WELL_KNOWN = ["/.well-known/security.txt", "/.well-known/openid-configuration"]
WS_PATTERN = re.compile(r"""wss?://[^\s"'<>]+|new\s+WebSocket\(\s*["']([^"']+)["']""", re.I)


@dataclass
class CrawlResult:
    urls: list = field(default_factory=list)
    forms: list = field(default_factory=list)          # {"page": url, "form": {...}}
    endpoints: list = field(default_factory=list)      # discovered API/JS endpoints (absolute)
    js_endpoints: list = field(default_factory=list)
    js_files: list = field(default_factory=list)
    api_specs: list = field(default_factory=list)      # {"url":..., "spec": dict}
    technologies: list = field(default_factory=list)
    graphql_endpoints: list = field(default_factory=list)
    websocket_endpoints: list = field(default_factory=list)

    def to_dict(self):
        return {"urls": self.urls, "forms": self.forms, "endpoints": self.endpoints,
                "js_endpoints": self.js_endpoints, "js_files": self.js_files,
                "api_specs": self.api_specs, "technologies": self.technologies,
                "graphql_endpoints": self.graphql_endpoints,
                "websocket_endpoints": self.websocket_endpoints}


class Crawler:
    def __init__(self, requester, base_url, depth=2):
        self.requester = requester
        self.base_url = urldefrag(base_url).url
        self.depth = depth
        self._lock = threading.Lock()

    # -- helpers ---------------------------------------------------------
    def is_valid(self, url):
        parsed = urlparse(url)
        if parsed.scheme not in ("http", "https"):
            return False
        if "windows" in url.lower() or url.lower().startswith("c:"):
            return False
        if any(x in url.lower() for x in (".md", ".txt", ".zip", ".git", "composer", "readme")):
            return False
        return parsed.netloc == urlparse(self.base_url).netloc

    @staticmethod
    def extract_js_endpoints(html):
        endpoints = set()
        for pattern in JS_ENDPOINT_PATTERNS:
            for m in re.findall(pattern, html, re.I):
                if isinstance(m, tuple):
                    m = next((x for x in m if x), "")
                if m:
                    endpoints.add(m)
        return endpoints

    @staticmethod
    def detect_frameworks(html, headers_text=""):
        combined = html + "\n" + headers_text
        found = []
        for name, pats in FRAMEWORK_MARKERS.items():
            if any(re.search(p, combined, re.I) for p in pats):
                found.append(name)
        return found

    def parse_robots(self):
        return self._paths_from_text("/robots.txt", r"(?im)^(?:allow|disallow):\s*(\S+)")

    def parse_sitemap(self):
        urls = set()
        try:
            resp = self.requester.get(urljoin(self.base_url, "/sitemap.xml"))
            if resp and resp.status_code == 200:
                for m in re.findall(r"<loc>(.*?)</loc>", resp.text):
                    urls.add(m.strip())
        except Exception:
            pass
        return urls

    def _paths_from_text(self, path, pattern):
        urls = set()
        try:
            resp = self.requester.get(urljoin(self.base_url, path))
            if resp and resp.status_code == 200:
                for m in re.findall(pattern, resp.text):
                    urls.add(urljoin(self.base_url, m.strip()))
        except Exception:
            pass
        return urls

    def _probe_wellknown_and_api(self, result: CrawlResult):
        for path in WELL_KNOWN + OPENAPI_PATHS + GRAPHQL_PATHS:
            url = urljoin(self.base_url, path)
            try:
                resp = self.requester.get(url)
            except Exception:
                continue
            if not resp or resp.status_code != 200:
                continue
            if path in GRAPHQL_PATHS:
                result.graphql_endpoints.append(url)
            if path in OPENAPI_PATHS:
                try:
                    spec = resp.json()
                    if isinstance(spec, dict) and ("openapi" in spec or "swagger" in spec or "paths" in spec):
                        result.api_specs.append({"url": url, "spec": spec})
                        for p in spec.get("paths", {}):
                            result.endpoints.append(urljoin(self.base_url, p))
                except Exception:
                    pass
            if path in WELL_KNOWN:
                result.endpoints.append(url)

    # -- main crawl ------------------------------------------------------
    def crawl(self, start_url=None, depth=None):
        """Returns a CrawlResult. `crawl_urls()` keeps the old list return."""
        depth = self.depth if depth is None else depth
        start_url = urldefrag(start_url or self.base_url).url
        result = CrawlResult()
        visited, discovered = set(), set()
        lock = threading.Lock()

        self._probe_wellknown_and_api(result)

        with ThreadPoolExecutor(max_workers=2) as ex:
            futs = [ex.submit(self.parse_robots), ex.submit(self.parse_sitemap)]
            for f in as_completed(futs):
                try:
                    for u in f.result():
                        if self.is_valid(u) and not Utils.is_static(u):
                            discovered.add(u)
                except Exception:
                    pass

        def fetch(url, d):
            with lock:
                if url in visited or d > depth:
                    return []
                visited.add(url)
            resp = self.requester.get(url)
            if not resp or not resp.text:
                return []
            soup = BeautifulSoup(resp.text, "lxml")
            for tech in self.detect_frameworks(resp.text):
                with lock:
                    if tech not in result.technologies:
                        result.technologies.append(tech)
            for form in FormParser.extract_forms(resp.text, page_url=url):
                with lock:
                    result.forms.append({"page": url, "form": form})
            for tag in soup.find_all("script", src=True):
                src = urljoin(url, tag["src"])
                with lock:
                    if src not in result.js_files:
                        result.js_files.append(src)
            links = []
            for tag in soup.find_all("a", href=True):
                full = urljoin(url, tag["href"])
                if self.is_valid(full) and not Utils.is_static(full):
                    links.append((full, d + 1))
            # JS endpoints in page + linked JS files
            js_eps = self.extract_js_endpoints(resp.text)
            for m in WS_PATTERN.findall(resp.text):
                ws = m if isinstance(m, str) else (m[0] if m else "")
                if ws:
                    with lock:
                        if ws not in result.websocket_endpoints:
                            result.websocket_endpoints.append(ws)
            for src in list(result.js_files):
                try:
                    js = self.requester.get(src)
                    if js and js.status_code == 200:
                        js_eps |= self.extract_js_endpoints(js.text)
                except Exception:
                    pass
            for ep in js_eps:
                abs_ep = urljoin(url, ep) if ep.startswith("/") else ep
                with lock:
                    if abs_ep not in result.js_endpoints:
                        result.js_endpoints.append(abs_ep)
                    if "/api" in abs_ep or "graphql" in abs_ep:
                        if abs_ep not in result.endpoints:
                            result.endpoints.append(abs_ep)
            return links

        level = [(start_url, 0)] + [(u, 1) for u in discovered]
        while level:
            nxt = []
            with ThreadPoolExecutor(max_workers=10) as ex:
                futs = {ex.submit(fetch, u, d): (u, d) for u, d in level}
                for f in as_completed(futs):
                    try:
                        for link, ld in f.result():
                            with lock:
                                if link not in visited and link not in discovered:
                                    discovered.add(link)
                                    nxt.append((link, ld))
                    except Exception:
                        pass
            level = nxt
        result.urls = sorted(discovered | {start_url})
        return result

    def crawl_urls(self, start_url=None, depth=None):
        """Backwards-compatible: return a plain list of URLs."""
        return self.crawl(start_url, depth).urls

    def discover_parameters(self, url):
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        out = set()
        for param in params:
            qp = params.copy()
            qp[param] = ["FUZZ"]
            out.add(urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params,
                                urlencode(qp, doseq=True), parsed.fragment)))
        return out
