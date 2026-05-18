class HeaderScanner:

    REQUIRED_HEADERS = [
        "Content-Security-Policy",
        "X-Frame-Options",
        "Strict-Transport-Security",
        "X-Content-Type-Options"
    ]

    def scan(self, response):

        missing = []

        for header in self.REQUIRED_HEADERS:

            if header not in response.headers:
                missing.append(header)

        return missing