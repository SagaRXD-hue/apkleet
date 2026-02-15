import os
import re


"""
M9: Reverse Engineering Protection Checker
Detects lack of obfuscation, debug flags, anti-debug, root checks
"""


def scan_m9(source_dir):

    findings = []

    patterns = {
        "debuggable": r"android:debuggable\s*=\s*\"true\"",
        "frida": r"frida",
        "xposed": r"xposed",
        "root_check": r"su\s+|/system/bin/su",
        "debug": r"Debug\.isDebuggerConnected",
        "ptrace": r"ptrace",
        "system_exit": r"System\.exit"
    }

    compiled = {
        k: re.compile(v, re.IGNORECASE)
        for k, v in patterns.items()
    }


    for root, _, files in os.walk(source_dir):
        print(f"Scanning {root}...")
        for file in files:

            if not file.endswith((".java", ".kt", ".smali", ".xml")):
                continue

            file_path = os.path.join(root, file)

            try:
                with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                    content = f.read()


                for key, regex in compiled.items():

                    if regex.search(content):

                        findings.append({
                            "title": "Insufficient Reverse Engineering Protection",
                            "severity": "High",
                            "owasp": "M9: Reverse Engineering",
                            "path": os.path.relpath(file_path, source_dir),
                            "description": f"Detected reverse engineering indicator: {key}",
                            "remediation": "Enable code obfuscation, anti-debugging, and root detection"
                        })


            except Exception:
                continue


    # If nothing found → means no protection
    if not findings:

        findings.append({
            "title": "Missing Reverse Engineering Protection",
            "severity": "Medium",
            "owasp": "M9: Reverse Engineering",
            "path": "N/A",
            "description": "No anti-debugging, obfuscation, or protection detected",
            "remediation": "Use ProGuard/R8 and anti-tampering techniques"
        })


    return findings
