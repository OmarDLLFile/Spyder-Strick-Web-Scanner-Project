"""HTML form parser: inputs, textarea, select, hidden fields, CSRF awareness."""
from __future__ import annotations
from urllib.parse import urljoin
from bs4 import BeautifulSoup

CSRF_NAMES = {"csrf_token", "csrfmiddlewaretoken", "_csrf", "authenticity_token",
              "__requestverificationtoken", "xsrf-token", "csrf"}


class FormParser:
    @staticmethod
    def extract_forms(html, page_url: str = ""):
        if not html:
            return []
        soup = BeautifulSoup(html, "lxml")
        forms_data = []
        for form in soup.find_all("form"):
            action = form.attrs.get("action", "")
            if page_url:
                action = urljoin(page_url, action) if action else page_url
            inputs = []
            for tag in form.find_all(["input", "textarea", "select"]):
                name = tag.attrs.get("name")
                if not name:
                    continue
                if tag.name == "select":
                    options = [o.attrs.get("value", o.get_text(strip=True)) for o in tag.find_all("option")]
                    inputs.append({"type": "select", "name": name, "value": options[0] if options else "",
                                   "options": options})
                elif tag.name == "textarea":
                    inputs.append({"type": "textarea", "name": name, "value": tag.get_text()})
                else:
                    inputs.append({"type": tag.attrs.get("type", "text"), "name": name,
                                   "value": tag.attrs.get("value", "")})
            forms_data.append({
                "action": action,
                "method": (form.attrs.get("method") or "get").lower(),
                "enctype": form.attrs.get("enctype", "application/x-www-form-urlencoded"),
                "inputs": inputs,
                "has_csrf_token": any(i["name"].lower() in CSRF_NAMES for i in inputs),
                "is_login": any("pass" in i["name"].lower() for i in inputs),
            })
        return forms_data
