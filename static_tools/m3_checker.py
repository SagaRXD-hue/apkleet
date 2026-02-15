import os
import re

from static_tools.utility.filter import should_ignore


from .scan_utils import (
    is_valid_source_file,
    remove_comments,
    load_whitelist
)

"""
M3: Insecure Communication Checker
Detects insecure network protocols in source code
"""


def scan_m3(source_dir):

    findings = []

    insecure_patterns = [
        r"http://[^\s\"']+",
        r"ftp://[^\s\"']+",
        r"smtp://[^\s\"']+",
        r"ws://[^\s\"']+"
    ]

    compiled_patterns = [
        re.compile(p, re.IGNORECASE) for p in insecure_patterns
    ]


    for root, _, files in os.walk(source_dir):
        for file in files:
            if should_ignore(file):
                continue

            if not is_valid_source_file(file):
                continue

            file_path = os.path.join(root, file)
            print(f"Scanning {file_path}...")

            try:
                with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                    content = f.read()

                content = remove_comments(content)


                for regex in compiled_patterns:

                    matches = regex.findall(content)

                    for match in matches:

                        findings.append({
                            "title": "Insecure Communication",
                            "severity": "High",
                            "confidence": "High",
                            "owasp": "M3: Insecure Communication",
                            "path": os.path.relpath(file_path, source_dir),
                            "description": f"Insecure protocol detected: {match}",
                            "remediation": "Use HTTPS and enable TLS certificate validation"
                        })


            except Exception:
                continue


    return findings
