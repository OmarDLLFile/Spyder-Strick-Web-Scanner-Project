from urllib.parse import urljoin

class XSS_Scanner:
    def __init__(self, requester):
        self.requester = requester

        self.payloads = [
            "<script>alert(1)</script>",
            "\"><script>alert(1)</script>",
            "'><img src=x onerror=alert(1)>"
        ]

    def scan_form(self, url, form):

        target_url = urljoin(url, form.get("action", ""))

        inputs = form.get("inputs", [])

        data = {}

        for field in inputs:
            name = field.get("name")
            if name:
                data[name] = self.payloads[0]

        method = form.get("method", "get").lower()

        if method == "post":
            response = self.requester.post(target_url, data)
        else:
            response = self.requester.get(target_url, data)  # FIX هنا

        if response and data and any(p in response.text for p in self.payloads):
            return {
                "url": target_url,
                "type": "XSS",
                "payload": "detected"
            }

        return None