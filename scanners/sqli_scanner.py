from urllib.parse import urljoin
import re


class SQLiScanner:

    def __init__(self, requester):

        self.requester = requester

        self.payloads = [
            "'",
            "\"",
            "' OR '1'='1",
            "\" OR \"1\"=\"1",
            "'--",
            "' OR 1=1 --",
            "\" OR 1=1 --"
        ]

        # Database Error Patterns
        self.sql_errors = {

            "MySQL": [
                r"you have an error in your sql syntax",
                r"warning.*mysql",
                r"mysql_fetch",
                r"mysql_num_rows"
            ],

            "PostgreSQL": [
                r"postgresql.*error",
                r"warning.*pg_",
                r"pg_query"
            ],

            "MSSQL": [
                r"unclosed quotation mark",
                r"microsoft sql server",
                r"odbc sql server driver"
            ],

            "SQLite": [
                r"sqlite error",
                r"sqlite3.operationalerror"
            ],

            "Oracle": [
                r"oracle error",
                r"ora-\d+"
            ]
        }

    def scan_form(self, url, form):

        findings = []

        target_url = urljoin(url, form.get("action"))

        method = form.get("method", "get").lower()

        for payload in self.payloads:

            data = {}

            for input_field in form.get("inputs", []):

                input_name = input_field.get("name")

                input_type = input_field.get("type", "text")

                if input_name:

                    # تجاهل submit buttons
                    if input_type == "submit":
                        continue

                    data[input_name] = payload

            try:

                if method == "post":

                    response = self.requester.post(
                        target_url,
                        data
                    )

                else:

                    response = self.requester.get(
                        target_url
                    )

                if response:

                    vulnerability = self.detect_sql_errors(
                        response.text
                    )

                    if vulnerability:

                        findings.append({
                            "type": "SQL Injection",
                            "url": target_url,
                            "method": method.upper(),
                            "payload": payload,
                            "database": vulnerability,
                            "status_code": response.status_code
                        })

            except Exception as e:

                print(f"[ERROR] {e}")

        return findings

    def detect_sql_errors(self, html):

        html = html.lower()

        for dbms, errors in self.sql_errors.items():

            for error in errors:

                if re.search(error, html):

                    return dbms

        return None