import re


class TechnologyScanner:

    def __init__(self):

        self.fingerprints = {

            # --------------------------
            # CMS
            # --------------------------
            "WordPress": [
                r"wp-content",
                r"wp-includes"
            ],

            "Joomla": [
                r"/media/system/js/",
                r"Joomla!"
            ],

            "Drupal": [
                r"Drupal.settings",
                r"/sites/default/files/"
            ],

            # --------------------------
            # Frontend Frameworks
            # --------------------------
            "React": [
                r"_reactRootContainer",
                r"react-dom",
                r"data-reactroot"
            ],

            "Vue.js": [
                r"vue(.min)?\.js",
                r"data-v-"
            ],

            "Angular": [
                r"ng-app",
                r"ng-version",
                r"angular(.min)?\.js"
            ],

            "Next.js": [
                r"__NEXT_DATA__"
            ],

            # --------------------------
            # CSS Frameworks
            # --------------------------
            "Bootstrap": [
                r"bootstrap(.min)?\.css",
                r"bootstrap(.min)?\.js"
            ],

            "Tailwind CSS": [
                r"tailwind(.min)?\.css",
                r"--tw-"
            ],

            # --------------------------
            # JavaScript Libraries
            # --------------------------
            "jQuery": [
                r"jquery(.min)?\.js"
            ],

            # --------------------------
            # Backend Technologies
            # --------------------------
            "PHP": [
                r"X-Powered-By:\s*PHP",
                r"\.php"
            ],

            "Laravel": [
                r"laravel_session",
                r"XSRF-TOKEN",
                r"Laravel"
            ],

            "Django": [
                r"csrftoken",
                r"django",
                r"__admin_media_prefix__"
            ],

            "Flask": [
                r"flask",
                r"werkzeug"
            ],

            "Express.js": [
                r"X-Powered-By:\s*Express",
                r"express"
            ],

            "ASP.NET": [
                r"ASP.NET",
                r"__VIEWSTATE",
                r"__EVENTVALIDATION",
                r"X-AspNet-Version"
            ]
        }

    # --------------------------
    # MAIN SCAN
    # --------------------------
    def scan(self, response):

        detected = []

        # headers as text
        headers_text = "\n".join(
            [f"{k}: {v}" for k, v in response.headers.items()]
        )

        # body content
        content = response.text

        combined = headers_text + "\n" + content

        # --------------------------
        # Fingerprint Matching
        # --------------------------
        for tech, patterns in self.fingerprints.items():

            for pattern in patterns:

                if re.search(pattern, combined, re.I):

                    detected.append(tech)
                    break

        # --------------------------
        # Server Detection
        # --------------------------
        server = response.headers.get("Server", "")

        if server:

            if "nginx" in server.lower():
                detected.append("nginx")

            elif "apache" in server.lower():
                detected.append("Apache")

        # --------------------------
        # Cloudflare Detection
        # --------------------------
        cloudflare_headers = [
            "CF-RAY",
            "CF-Cache-Status",
            "Server"
        ]

        if any(h in response.headers for h in cloudflare_headers):

            server_header = response.headers.get("Server", "")

            if "cloudflare" in server_header.lower():
                detected.append("Cloudflare")

        # remove duplicates
        return list(set(detected))