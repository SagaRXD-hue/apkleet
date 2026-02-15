import os
import re


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
        print(f"Scanning {root}...")    
        for file in files:

            if not file.endswith((".java", ".kt", ".xml", ".txt")):
                continue

            file_path = os.path.join(root, file)

            try:
                with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                    content = f.read()


                for regex in compiled_patterns:

                    matches = regex.findall(content)

                    for match in matches:

                        findings.append({
                            "title": "Insecure Communication",
                            "severity": "High",
                            "owasp": "M3: Insecure Communication",
                            "path": os.path.relpath(file_path, source_dir),
                            "description": f"Insecure protocol detected: {match}",
                            "remediation": "Use HTTPS and enable TLS certificate validation"
                        })


            except Exception:
                continue


    return findings
