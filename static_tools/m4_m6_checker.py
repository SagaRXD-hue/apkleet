import os
import re


def scan_m4_m6(source_dir):

    findings = []

    auth_patterns = {
        "hardcoded_token": r"(token|auth|jwt|bearer)\s*=\s*\".+\"",
        "hardcoded_password": r"(password|passwd|pwd)\s*=\s*\".+\"",
        "shared_prefs_auth": r"SharedPreferences.*(token|auth|session)",
        "no_auth_api": r"http[s]?://.*/(login|auth|user|account)"
    }

    access_patterns = {
        "no_permission_check": r"checkCallingPermission\s*\(",
        "exported_component": r"android:exported\s*=\s*\"true\"",
        "weak_role_check": r"if\s*\(\s*user\.isAdmin\s*\)"
    }


    auth_regex = {k: re.compile(v, re.I) for k, v in auth_patterns.items()}
    access_regex = {k: re.compile(v, re.I) for k, v in access_patterns.items()}


    for root, _, files in os.walk(source_dir):

        for file in files:

            if not file.endswith(".java"):
                continue

            path = os.path.join(root, file)

            try:
                with open(path, "r", encoding="utf-8", errors="ignore") as f:
                    content = f.read()


                # ---- M4 Checks ----
                for key, regex in auth_regex.items():

                    if regex.search(content):

                        findings.append({
                            "title": "Weak Authentication Implementation",
                            "severity": "High",
                            "owasp": "M4: Insecure Authentication",
                            "path": os.path.relpath(path, source_dir),
                            "description": f"Detected {key} pattern",
                            "remediation": "Avoid hardcoded credentials and use secure auth flows"
                        })


                # ---- M6 Checks ----
                for key, regex in access_regex.items():

                    if regex.search(content):

                        findings.append({
                            "title": "Weak Authorization Control",
                            "severity": "High",
                            "owasp": "M6: Insecure Authorization",
                            "path": os.path.relpath(path, source_dir),
                            "description": f"Detected {key} pattern",
                            "remediation": "Implement strict access control checks"
                        })


            except Exception:
                continue


    return findings
