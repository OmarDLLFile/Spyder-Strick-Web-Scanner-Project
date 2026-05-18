from urllib.parse import urljoin, urlparse, parse_qs, urlencode
import requests


class OpenRedirectScanner:

    def __init__(self, requester):

        self.requester = requester

        self.payloads = [
            "https://evil.com",
            "//evil.com",
            "///evil.com",
            "https:evil.com",
            "//google.com"
        ]

        self.redirect_params = [
            "next",
            "url",
            "redirect",
            "redirect_url",
            "redir",
            "return",
            "return_url",
            "continue",
            "dest",
            "destination"
        ]

    def scan_url(self, url):

        findings = []

        parsed = urlparse(url)

        query_params = parse_qs(parsed.query)

        if not query_params:
            return findings

        for param in query_params:

            if param.lower() in self.redirect_params:

                for payload in self.payloads:

                    vulnerable_url = self.build_payload_url(
                        url,
                        param,
                        payload
                    )

                    result = self.test_redirect(
                        vulnerable_url,
                        payload
                    )

                    if result:
                        findings.append(result)

        return findings

    def build_payload_url(self, url, target_param, payload):

        parsed = urlparse(url)

        query_params = parse_qs(parsed.query)

        query_params[target_param] = payload

        encoded_query = urlencode(query_params, doseq=True)

        malicious_url = parsed._replace(
            query=encoded_query
        ).geturl()

        return malicious_url

    def test_redirect(self, url, payload):

        try:

            response = requests.get(
                url,
                allow_redirects=False,
                timeout=10,
                verify=False
            )

            location = response.headers.get("Location")

            if location:

                if payload.replace("https://", "") in location:

                    return {
                        "type": "Open Redirect",
                        "url": url,
                        "payload": payload,
                        "location": location,
                        "status_code": response.status_code
                    }

        except Exception as e:

            print(f"[ERROR] {e}")

        return None