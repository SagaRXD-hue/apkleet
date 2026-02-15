import os
import re

DANGEROUS_APIS = [
    "addJavascriptInterface",
    "setAllowFileAccess(true)",
    "setAllowUniversalAccessFromFileURLs",
]

def scan_m1(source_dir):
    results = []

    for root, _, files in os.walk(source_dir):
        print(f"Scanning {root}...")
        for f in files:
            if f.endswith(".java"):
                path = os.path.join(root, f)

                with open(path, errors="ignore") as file:
                    content = file.read()

                for api in DANGEROUS_APIS:
                    if api in content:
                        results.append({
                            "title": "Improper Platform Usage",
                            "severity": "High",
                            "owasp": "M1",
                            "path": path,
                            "description": f"Dangerous API: {api}",
                            "remediation": "Avoid insecure WebView or system APIs"
                        })

    return results
