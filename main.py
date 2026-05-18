import sys
import time
import os
from urllib.parse import *
from concurrent.futures import ThreadPoolExecutor, as_completed
import threading

from core.requester import Requester
from core.crawler import Crawler
from core.parser import FormParser
from core.reporter import ReportGenerator
from core.utils import Utils

from scanners.xss_scanner import XSS_Scanner
from scanners.sqli_scanner import SQLiScanner
from scanners.redirect_scanner import OpenRedirectScanner
from scanners.traversal_scanner import DirectoryTraversalScanner
from scanners.headers_scanner import HeaderScanner
from scanners.tech_scanner import TechnologyScanner


class MiniScanner:

    def __init__(self, target_url):
        self.target_url = target_url

        self.requester = Requester()
        self.crawler = Crawler(self.requester, self.target_url)
        self.reporter = ReportGenerator()

        # scanners
        self.xss_scanner = XSS_Scanner(self.requester)
        self.sqli_scanner = SQLiScanner(self.requester)
        self.redirect_scanner = OpenRedirectScanner(self.requester)
        self.traversal_scanner = DirectoryTraversalScanner(self.requester)
        self.header_scanner = HeaderScanner()
        self.tech_scanner = TechnologyScanner()
        
        self.lock = threading.Lock()
        self.scanned_urls = set()
        
    def normalize_url(self, url):
        p = urlsplit(url)
        return urlunsplit((p.scheme, p.netloc, p.path, "", ""))

    # --------------------------
    # START
    # --------------------------
    def start(self):

        Utils.print_banner()

        print(Utils.color_text(f"[+] Target: {self.target_url}", "blue"))

        start_time = time.time()

        urls = self.run_crawler()
        self.scan_urls(urls)
        self.generate_reports()

        end_time = time.time()

        print(
            Utils.color_text(
                f"\n[+] Scan Finished in {Utils.calculate_response_time(start_time, end_time)} seconds",
                "green"
            )
        )

    # --------------------------
    # CRAWLER WRAPPER
    # --------------------------
    def run_crawler(self):

        print(Utils.color_text("\n[+] Starting Crawling...", "yellow"))

        urls = self.crawler.crawl(self.target_url, depth=2) or []

        urls = list(set(urls))

        if self.target_url not in urls:
            urls.append(self.target_url)

        print(Utils.color_text(f"[+] Found {len(urls)} URLs", "green"))

        return urls

    # --------------------------
    # URL FILTER
    # --------------------------
    def should_scan(self, url):

        # avoid static junk (performance boost)
        static_ext = (".jpg", ".png", ".css", ".js", ".svg", ".woff", ".ico", ".mp4")

        if url.lower().endswith(static_ext):
            return False

        # same domain only
        return Utils.is_same_domain(self.target_url, url)

    # --------------------------
    # SINGLE URL SCAN
    # --------------------------
    def scan_single_url(self, url):

        # --------------------------
        # THREAD SAFE DEDUP
        # --------------------------
        
        url = self.normalize_url(url)

        if not self.should_scan(url):
            return

        with self.lock:
            if url in self.scanned_urls:
                return
            self.scanned_urls.add(url)

        # --------------------------
        # FILTER CHECK
        # --------------------------
        if not self.should_scan(url):
            return

        print(Utils.color_text(f"\n[+] Scanning: {url}", "blue"))

        try:
            response = self.requester.get(url)
            
            technologies = self.tech_scanner.scan(response)

            if technologies:

                with self.lock:
                    self.reporter.add_result({
                        "type": "Technology Fingerprint",
                        "url": url,
                        "technologies": technologies,
                        "severity": "INFO"
                    })

                print(
                    Utils.color_text(
                        f"[+] Technologies Detected: {', '.join(technologies)}",
                        "cyan"
                    )
                )

            if not response:
                return

            # --------------------------
            # HEADERS SCAN
            # --------------------------
            missing_headers = self.header_scanner.scan(response)

            if missing_headers:
                with self.lock:
                    self.reporter.add_result({
                        "type": "Missing Security Headers",
                        "url": url,
                        "missing_headers": missing_headers,
                        "status_code": response.status_code
                    })

            # --------------------------
            # OPEN REDIRECT
            # --------------------------
            redirect_results = self.redirect_scanner.scan_url(url) or []

            if redirect_results:
                with self.lock:
                    self.reporter.add_results(redirect_results)

            # --------------------------
            # DIRECTORY TRAVERSAL
            # --------------------------
            traversal_results = self.traversal_scanner.scan_url(url) or []

            if traversal_results:
                with self.lock:
                    self.reporter.add_results(traversal_results)

            # --------------------------
            # FORM PARSING
            # --------------------------
            # forms = FormParser.extract_forms(response.text) or []
            forms = [
                f for f in (FormParser.extract_forms(response.text) or [])
                if f and isinstance(f, dict)
            ]

            if forms:
                print(Utils.color_text(f"[+] Found {len(forms)} Forms", "green"))

            # --------------------------
            # FORM SCANNING
            # --------------------------
            for form in forms:

                # XSS
                xss_result = self.xss_scanner.scan_form(url, form)
                if xss_result:
                    with self.lock:
                        self.reporter.add_result(xss_result)

                # SQLi
                sqli_results = self.sqli_scanner.scan_form(url, form)
                if sqli_results:
                    with self.lock:
                        self.reporter.add_results(sqli_results)

        except Exception as e:

            # thread-safe error logging
            with self.lock:
                self.reporter.add_result({
                    "type": "ERROR",
                    "url": url,
                    "error": str(e)
                })
        
    # --------------------------
    # PARALLEL SCAN ENGINE
    # --------------------------
    def scan_urls(self, urls):

        # max_workers = min(40, (os.cpu_count() or 4) * 5)
        max_workers = min(20, (os.cpu_count() or 4) * 2)

        print(
            Utils.color_text(
                f"\n[+] Starting Parallel Scan with {max_workers} workers...",
                "yellow"
            )
        )

        with ThreadPoolExecutor(max_workers=max_workers) as executor:

            futures = [
                executor.submit(self.scan_single_url, url)
                for url in urls
            ]

            for future in as_completed(futures):
                try:
                    future.result()
                except Exception as e:
                    self.reporter.add_result({
                        "type": "THREAD_ERROR",
                        "error": str(e)
                    })

    # --------------------------
    # REPORT
    # --------------------------
    def generate_reports(self):

        print(Utils.color_text("\n[+] Generating Reports...", "yellow"))

        self.reporter.print_summary()
        self.reporter.generate_json_report()
        self.reporter.generate_html_report()


# --------------------------
# ENTRY POINT
# --------------------------
if __name__ == "__main__":

    if len(sys.argv) != 2:
        print("Usage: python main.py <target_url>")
        sys.exit(1)

    scanner = MiniScanner(sys.argv[1])
    scanner.start()