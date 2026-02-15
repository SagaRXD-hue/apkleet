import os

import re


from static_tools.utility.filter import should_ignore

from .scan_utils import (
    is_valid_source_file,
    remove_comments,
    load_whitelist
)


# Debug / Backdoor Patterns
DEBUG_PATTERNS = {

    "debug_flag": r"\bBuildConfig\.DEBUG\b",

    "log_debug": r"\bLog\.d\(",

    "test_mode": r"\btestMode\s*=\s*true\b",

    "dev_mode": r"\bdevMode\s*=\s*true\b",

    "bypass_auth": r"\b(skipAuth|bypassAuth|noAuth)\b"
}


# Common dev endpoints
DEV_ENDPOINTS = [
    r'"/debug"',
    r'"/test"',
    r'"/dev"',
    r'"/admin"',
    r'"/staging"'
]



def scan_m10(source_dir, manifest_path):

    findings = []

    # -------------------------
    # 1. Check Debuggable Flag
    # -------------------------

    try:
        with open(manifest_path, "r", encoding="utf-8", errors="ignore") as f:
            manifest_data = f.read()
            

        if 'android:debuggable="true"' in manifest_data:

            findings.append({
                "title": "Debug Mode Enabled",
                "severity": "Medium",
                "confidence": "Medium",
                "owasp": "M10: Extraneous Functionality",
                "path": "AndroidManifest.xml",
                "description": "Application is debuggable in production",
                "remediation": "Disable android:debuggable before release"
            })

    except:
        pass


    # -------------------------
    # 2. Scan Source Code
    # -------------------------

    for root, dirs, files in os.walk(source_dir):
        SKIP_DIRS = [
            "androidx",
            "kotlin",
            "google",
            "okhttp",
            "retrofit",
            "squareup",
            "apache",
            "firebase",
            "glide"
        ]

        if any(lib in root.lower() for lib in SKIP_DIRS):
            continue

        for file in files:
            if should_ignore(file):
                continue

            if not is_valid_source_file(file):
                continue


            path = os.path.join(root, file)
            print(f"Scanning {path}...")

            try:
                with open(path, "r", encoding="utf-8", errors="ignore") as f:
                    data = f.read()
                data = remove_comments(data)
            except:
                continue


            # Check debug patterns
            for name, pattern in DEBUG_PATTERNS.items():

                if re.search(pattern, data):

                    findings.append({
                        "title": "Debug / Backdoor Code",
                        "type": name,
                        "severity": "Medium",
                        "owasp": "M10: Extraneous Functionality",
                        "path": os.path.relpath(path, source_dir),
                        "description": f"Debug/backdoor logic detected: {name}",
                        "remediation": "Remove debug/test code"
                    })


            # Check dev endpoints
            for ep in DEV_ENDPOINTS:

                if re.search(ep, data):

                    findings.append({
                        "title": "Extraneous Functionality",
                        "severity": "Low",
                        "owasp": "M10: Extraneous Functionality",
                        "path": path,
                        "description": "Debug/test/backdoor code detected",
                        "remediation": "Remove development and test code from production"
                    })


    print(f"[*] Extraneous functionality findings: {len(findings)}")
    unique = []
    seen = set()

    for f in findings:

        key = (f["title"], f["path"])

        if key not in seen:
            seen.add(key)
            unique.append(f)

    return unique
