import json
import os
from datetime import datetime


class ReportGenerator:

    def __init__(self):

        self.results = []

        self.report_dir = "reports"

        self.create_reports_directory()

    def create_reports_directory(self):

        if not os.path.exists(self.report_dir):

            os.makedirs(self.report_dir)

    def add_result(self, result):

        if result:
            self.results.append(result)

    def add_results(self, results):

        if results:

            if isinstance(results, list):

                self.results.extend(results)

            else:

                self.results.append(results)

    def generate_json_report(self):

        timestamp = datetime.now().strftime(
            "%Y-%m-%d_%H-%M-%S"
        )

        filename = f"report_{timestamp}.json"

        filepath = os.path.join(
            self.report_dir,
            filename
        )

        report_data = {

            "generated_at": timestamp,

            "total_findings": len(self.results),

            "findings": self.results
        }

        with open(filepath, "w", encoding="utf-8") as report_file:

            json.dump(
                report_data,
                report_file,
                indent=4,
                ensure_ascii=False
            )

        print(f"[+] JSON Report Saved: {filepath}")

        return filepath

    def generate_html_report(self):

        timestamp = datetime.now().strftime(
            "%Y-%m-%d_%H-%M-%S"
        )

        filename = f"report_{timestamp}.html"

        filepath = os.path.join(
            self.report_dir,
            filename
        )

        html_content = self.build_html_report()

        with open(filepath, "w", encoding="utf-8") as report_file:

            report_file.write(html_content)

        print(f"[+] HTML Report Saved: {filepath}")

        return filepath

    def build_html_report(self):

        html = f"""
<!DOCTYPE html>
<html lang="en">

<head>

<meta charset="UTF-8">

<title>Mini Scanner Report</title>

<style>

body {{

    background-color: #111;
    color: #eee;
    font-family: Arial;
    padding: 20px;
}}

h1 {{

    color: #00ff99;
}}

.card {{

    background: #1b1b1b;
    border: 1px solid #333;
    padding: 15px;
    margin-bottom: 15px;
    border-radius: 10px;
}}

.high {{
    border-left: 5px solid red;
}}

.medium {{
    border-left: 5px solid orange;
}}

.low {{
    border-left: 5px solid yellow;
}}

pre {{

    white-space: pre-wrap;
    word-wrap: break-word;
}}

</style>

</head>

<body>

<h1>Mini Vulnerability Scanner Report</h1>

<p>Total Findings: {len(self.results)}</p>

"""

        for result in self.results:

            severity = self.calculate_severity(result)

            html += f"""
<div class="card {severity.lower()}">

<h2>{result.get("type", "Unknown")}</h2>

<p><strong>Severity:</strong> {severity}</p>

<p><strong>URL:</strong> {result.get("url", result.get("target", "N/A"))}</p>

<p><strong>Status Code:</strong> {result.get("status_code", "N/A")}</p>

<pre>{json.dumps(result, indent=4)}</pre>

</div>
"""

        html += """
</body>
</html>
"""

        return html

    def calculate_severity(self, result):

        vulnerability_type = result.get("type", "").lower()

        if vulnerability_type in [
            "sql injection",
            "xss",
            "directory traversal"
        ]:

            return "HIGH"

        elif vulnerability_type in [
            "open redirect"
        ]:

            return "MEDIUM"

        elif vulnerability_type in [
            "missing security headers"
        ]:

            return "LOW"

        return "INFO"

    def print_summary(self):

        print("\n========== Scan Summary ==========")

        print(f"Total Findings: {len(self.results)}")

        severity_count = {
            "HIGH": 0,
            "MEDIUM": 0,
            "LOW": 0,
            "INFO": 0
        }

        for result in self.results:

            severity = self.calculate_severity(result)

            severity_count[severity] += 1

        print(f"HIGH:   {severity_count['HIGH']}")
        print(f"MEDIUM: {severity_count['MEDIUM']}")
        print(f"LOW:    {severity_count['LOW']}")
        print(f"INFO:   {severity_count['INFO']}")

        print("==================================")