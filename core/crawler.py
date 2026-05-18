from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse, urldefrag, parse_qs, urlencode, urlunparse
from core.utils import Utils
import re
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed

#// ============================================================================

 # OLD CRAWLER
 
# class Crawler:
#     def __init__(self, requester, base_url):
#         self.requester = requester
#         self.base_url = base_url
#         self.visited = set()

#     def crawl(self, url, depth=2):

#         if depth == 0:
#             return []

#         if url in self.visited:
#             return []

#         self.visited.add(url)

#         response = self.requester.get(url)

#         if not response:
#             return []

#         soup = BeautifulSoup(response.text, "lxml")

#         links = set()

#         for tag in soup.find_all("a"):
#             href = tag.get("href")
            
#             if href:
#                 full_url = urljoin(url, href)

#                 if not self.is_valid(full_url):
#                     continue
                    
#                 if Utils.is_static(full_url):
#                     continue     
                    
#                 links.add(full_url)

#         result = list(links)

#         for link in list(links):
#             result += self.crawl(link, depth - 1)

#         return list(set(result))

#     def is_valid(self, url):
#         return urlparse(url).netloc == urlparse(self.base_url).netloc


#// ===================================================================================


class Crawler:
    def __init__(self, requester, base_url):
        self.requester = requester
        self.base_url = urldefrag(base_url).url
        self._lock = threading.Lock()

    ### Old Crawler

    """
   
    def crawl(self, url, depth=2, visited=None):
        
        ## Freezing

        # discovered_urls = set()
                
        # robots_urls = self.parse_robots()
        # discovered_urls.update(robots_urls)
        
        # sitemap_urls = self.parse_sitemap()
        # discovered_urls.update(sitemap_urls)
        
        if visited is None:
            visited = set()

        if depth == 0 or url in visited:
            return []

        visited.add(url)

        response = self.requester.get(url)
        if not response:
            return []

        soup = BeautifulSoup(response.text, features="lxml")

        links = set()

        for tag in soup.find_all("a"):
            href = tag.get("href")

            if not href:
                continue

            full_url = urljoin(url, href)

            if not self.is_valid(full_url):
                continue

            if Utils.is_static(full_url):
                continue

            links.add(full_url)

        result = set(links)

        for link in links:
            result.update(self.crawl(link, depth - 1, visited))

        return list(result)
    
    def parse_robots(self):

        robots_url = urljoin(self.base_url, "/robots.txt")

        urls = set()

        try:
            response = self.requester.get(robots_url)

            if not response or response.status_code != 200:
                return urls

            for line in response.text.splitlines():

                line = line.strip()

                if line.lower().startswith(("allow:", "disallow:")):

                    path = line.split(":", 1)[1].strip()

                    if path:
                        urls.add(urljoin(self.base_url, path))

        except Exception:
            pass

        return urls
        
    """
    
    #// ============================================================================================
    
    
    ### Single Thread Crawl
    
    # def crawl(self, start_url, depth=2):

    #     visited = set()
    #     queue = [(start_url, 0)]

    #     discovered_urls = set()

    #     # ── robots.txt discovery ──────────────────────────────
    #     robots_urls = self.parse_robots()
    #     discovered_urls.update(robots_urls)
    #     for url in robots_urls:
    #         if self.is_valid(url) and not Utils.is_static(url):
    #             queue.append((url, 1))

    #     # ── sitemap.xml discovery ─────────────────────────────
    #     sitemap_urls = self.parse_sitemap()
    #     discovered_urls.update(sitemap_urls)
    #     for url in sitemap_urls:
    #         if self.is_valid(url) and not Utils.is_static(url):
    #             queue.append((url, 1))

    #     # ── main crawl loop ───────────────────────────────────
    #     while queue:

    #         current_url, current_depth = queue.pop(0)

    #         if current_url in visited:
    #             continue

    #         if current_depth > depth:
    #             continue

    #         visited.add(current_url)

    #         response = self.requester.get(current_url)
    #         if not response:
    #             continue

    #         soup = BeautifulSoup(response.text, features="lxml")

    #         for tag in soup.find_all("a"):
    #             href = tag.get("href")
    #             if not href:
    #                 continue

    #             full_url = urljoin(current_url, href)

    #             if not self.is_valid(full_url):
    #                 continue

    #             if Utils.is_static(full_url):
    #                 continue

    #             if full_url not in visited:
    #                 discovered_urls.add(full_url)
    #                 queue.append((full_url, current_depth + 1))

    #     return list(discovered_urls)
    
    
    #// ============================================================================================
    
    ### Multi Thread Crawl
    def crawl(self, start_url, depth=2):

        visited = set()
        discovered_urls = set()
        visited_lock = threading.Lock()

        # ── Phase 1: parallel discovery (robots + sitemap) ──
        with ThreadPoolExecutor(max_workers=2) as executor:
            futures = {
                executor.submit(self.parse_robots): "robots",
                executor.submit(self.parse_sitemap): "sitemap",
            }
            for future in as_completed(futures):
                try:
                    urls = future.result()
                    for url in urls:
                        if self.is_valid(url) and not Utils.is_static(url):
                            discovered_urls.add(url)
                except Exception:
                    pass

        # ── Phase 2: BFS crawl with thread pool ─────────────
        queue = [(start_url, 0)] + [(u, 1) for u in discovered_urls]

        def fetch_and_extract(url, current_depth):
            """Fetch a URL and return (found_links, url)"""
            with visited_lock:
                if url in visited or current_depth > depth:
                    return [], url
                visited.add(url)

            response = self.requester.get(url)
            if not response:
                return [], url

            soup = BeautifulSoup(response.text, features="lxml")
            links = []

            for tag in soup.find_all("a"):
                href = tag.get("href")
                if not href:
                    continue
                full_url = urljoin(url, href)
                if self.is_valid(full_url) and not Utils.is_static(full_url):
                    links.append((full_url, current_depth + 1))

            return links, url

        # BFS levels
        current_level = queue
        while current_level:
            next_level = []

            with ThreadPoolExecutor(max_workers=10) as executor:
                futures = {
                    executor.submit(fetch_and_extract, url, d): (url, d)
                    for url, d in current_level
                }
                for future in as_completed(futures):
                    try:
                        found_links, parent_url = future.result()
                        for link, link_depth in found_links:
                            with visited_lock:
                                if link not in visited and link not in discovered_urls:
                                    discovered_urls.add(link)
                                    next_level.append((link, link_depth))
                    except Exception:
                        pass

            current_level = next_level

        return list(discovered_urls)
    
    def discover_parameters(self, url):

        generated = set()

        parsed = urlparse(url)

        params = parse_qs(parsed.query)

        for param in params:

            test_params = params.copy()

            test_params[param] = ["FUZZ"]

            new_query = urlencode(test_params, doseq=True)

            fuzzed = urlunparse((
                parsed.scheme,
                parsed.netloc,
                parsed.path,
                parsed.params,
                new_query,
                parsed.fragment
            ))

            generated.add(fuzzed)

        return generated
    
    def parse_sitemap(self):

        sitemap_url = urljoin(self.base_url, "/sitemap.xml")

        urls = set()

        try:
            response = self.requester.get(sitemap_url)

            if not response or response.status_code != 200:
                return urls

            matches = re.findall(r"<loc>(.*?)</loc>", response.text)

            for match in matches:
                urls.add(match.strip())

        except Exception:
            pass

        return urls
    
    
    def parse_robots(self):

        robots_url = urljoin(self.base_url, "/robots.txt")

        urls = set()

        try:
            response = self.requester.get(robots_url)

            if not response or response.status_code != 200:
                return urls

            for line in response.text.splitlines():

                line = line.strip()

                if line.lower().startswith(("allow:", "disallow:")):

                    path = line.split(":", 1)[1].strip()

                    if path:
                        urls.add(urljoin(self.base_url, path))

        except Exception:
            pass

        return urls
    
    
    def extract_js_endpoints(self, html):

        endpoints = set()

        patterns = [
            r'["\'](\/api\/.*?|\/.*?\.php.*?)["\']',
            r'["\'](https?:\/\/.*?)[\"\']',
            r'fetch\(["\'](.*?)["\']\)',
            r'axios\.(get|post)\(["\'](.*?)["\']'
        ]

        for pattern in patterns:

            matches = re.findall(pattern, html, re.I)

            for match in matches:

                if isinstance(match, tuple):
                    match = match[-1]

                endpoints.add(match)

        return endpoints
    
    

    def is_valid(self, url):
        parsed = urlparse(url)

        if not parsed.scheme in ["http", "https"]:
            return False

        if "windows" in url.lower() or "c:" in url.lower():
            return False
        
        if any(x in url.lower() for x in [".md", ".txt", ".zip", ".git", "composer", "readme"]):
            return False

        return parsed.netloc == urlparse(self.base_url).netloc