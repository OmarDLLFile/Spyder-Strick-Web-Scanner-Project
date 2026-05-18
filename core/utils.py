from urllib.parse import urlparse, urljoin, urlunparse
import re
import random
import string


class Utils:

    @staticmethod
    def normalize_url(base_url, link):

        """
        تحويل الروابط النسبية إلى روابط كاملة
        """

        return urljoin(base_url, link)
    
    from urllib.parse import urlparse, urlunparse

    @staticmethod
    def clean_url(url):
        parsed = urlparse(url)
        return urlunparse(parsed._replace(fragment=""))

    @staticmethod
    def is_valid_url(url):

        """
        التحقق من صحة الرابط
        """

        parsed = urlparse(url)

        return bool(parsed.scheme) and bool(parsed.netloc)

    @staticmethod
    def is_same_domain(base_url, target_url):

        """
        التأكد أن الرابط داخل نفس الدومين
        """

        base_domain = urlparse(base_url).netloc
        target_domain = urlparse(target_url).netloc

        return base_domain == target_domain

    @staticmethod
    def clean_url(url):

        """
        حذف الـ fragments مثل:
        #section
        """

        parsed = urlparse(url)

        clean = parsed._replace(fragment="")

        return clean.geturl()

    @staticmethod
    def remove_duplicates(urls):

        """
        حذف الروابط المكررة
        """

        return list(set(urls))

    @staticmethod
    def extract_query_params(url):

        """
        استخراج أسماء الـ query parameters
        """

        parsed = urlparse(url)

        query = parsed.query

        params = {}

        if query:

            pairs = query.split("&")

            for pair in pairs:

                if "=" in pair:

                    key, value = pair.split("=", 1)

                    params[key] = value

        return params

    @staticmethod
    def generate_random_string(length=8):

        """
        توليد string عشوائي
        """

        characters = string.ascii_letters + string.digits

        return ''.join(
            random.choice(characters)
            for _ in range(length)
        )

    @staticmethod
    def contains_sensitive_keywords(text):

        """
        البحث عن كلمات حساسة داخل الـ response
        """

        keywords = [
            "password",
            "token",
            "secret",
            "apikey",
            "authorization",
            "bearer"
        ]

        text = text.lower()

        for keyword in keywords:

            if keyword in text:

                return True

        return False

    @staticmethod
    def extract_links(html):

        """
        استخراج الروابط باستخدام regex
        """

        pattern = r'href=["\\\'](.*?)["\\\']'

        return re.findall(pattern, html)

    @staticmethod
    def print_banner():

        banner = r"""
███████╗██████╗ ██╗   ██╗██████╗ ███████╗██████╗ 
██╔════╝██╔══██╗╚██╗ ██╔╝██╔══██╗██╔════╝██╔══██╗
███████╗██████╔╝ ╚████╔╝ ██║  ██║█████╗  ██████╔╝
╚════██║██╔═══╝   ╚██╔╝  ██║  ██║██╔══╝  ██╔══██╗
███████║██║        ██║   ██████╔╝███████╗██║  ██║
╚══════╝╚═╝        ╚═╝   ╚═════╝ ╚══════╝╚═╝  ╚═╝

███████╗████████╗██████╗ ██╗ ██████╗██╗  ██╗
██╔════╝╚══██╔══╝██╔══██╗██║██╔════╝██║ ██╔╝
███████╗   ██║   ██████╔╝██║██║     █████╔╝ 
╚════██║   ██║   ██╔══██╗██║██║     ██╔═██╗ 
███████║   ██║   ██║  ██║██║╚██████╗██║  ██╗
╚══════╝   ╚═╝   ╚═╝  ╚═╝╚═╝ ╚═════╝╚═╝  ╚═╝

        Web Recon & Vulnerability Scanner
"""

        print(banner)

    @staticmethod
    def calculate_response_time(start, end):

        """
        حساب زمن الاستجابة
        """

        return round(end - start, 2)

    @staticmethod
    def detect_waf(response_headers):

        """
        محاولة اكتشاف WAF
        """

        waf_signatures = {

            "Cloudflare": [
                "cloudflare"
            ],

            "Akamai": [
                "akamai"
            ],

            "Sucuri": [
                "sucuri"
            ],

            "Imperva": [
                "imperva"
            ]
        }

        headers = str(response_headers).lower()

        for waf, signatures in waf_signatures.items():

            for signature in signatures:

                if signature in headers:

                    return waf

        return None
    
    @staticmethod
    def is_static(url):
        return any(ext in url for ext in [".jpg", ".png", ".css", ".js", ".svg"])

    @staticmethod
    def color_text(text, color):

        """
        تلوين النصوص داخل الترمينال
        """

        colors = {

            "red": "\033[91m",
            "green": "\033[92m",
            "yellow": "\033[93m",
            "blue": "\033[94m",
            "reset": "\033[0m"
        }

        return (
            colors.get(color, "")
            + text
            + colors["reset"]
        )
       
 
class Dedup:
    seen = set()

    @staticmethod
    def is_new(finding):
        key = f"{finding['url']}-{finding['type']}"
        if key in Dedup.seen:
            return False
        Dedup.seen.add(key)
        return True