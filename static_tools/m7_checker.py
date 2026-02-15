import os
import re


def scan_m7(source_dir):

    findings = []

    patterns = {
        "printStackTrace": r"printStackTrace\s*\(",
        "debug_log": r"Log\.d\s*\(",
        "system_print": r"System\.out\.println\s*\(",
        "todo": r"TODO|FIXME",
        "empty_catch": r"catch\s*\(\s*Exception\s+\w+\s*\)\s*\{\s*\}"
    }

    compiled = {
        k: re.compile(v) for k, v in patterns.items()
    }


    for root, _, files in os.walk(source_dir):

        for file in files:

            if not file.endswith(".java"):
                continue

            path = os.path.join(root, file)

            try:
                with open(path, "r", encoding="utf-8", errors="ignore") as f:
                    content = f.read()


                for key, regex in compiled.items():

                    if regex.search(content):

                        findings.append({
                            "title": "Poor Code Quality",
                            "severity": "Low",
                            "owasp": "M7: Client Code Quality",
                            "path": os.path.relpath(path, source_dir),
                            "description": f"Detected {key} pattern in source code",
                            "remediation": "Remove debug and development code before release"
                        })


            except Exception:
                continue


    return findings
