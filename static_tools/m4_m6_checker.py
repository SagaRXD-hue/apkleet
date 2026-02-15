import os
import re


def scan_m4_m6(source_dir):

    findings = []

    # -------- M4: Authentication --------
    auth_patterns = {
        "hardcoded_password": r"(password|passwd|pwd)\s*=\s*[\"'].*?[\"']",
        "hardcoded_token": r"(token|auth|jwt|session)\s*=\s*[\"'].*?[\"']",
        "login_method": r"login\s*\(",
        "auth_manager": r"AuthManager|LoginManager|SessionManager",
        "basic_auth": r"Authorization:\s*Basic"
    }

    # -------- M6: Authorization --------
    access_patterns = {
        "is_admin_check": r"isAdmin|isRoot|isSuperUser",
        "role_check": r"hasRole|checkRole|userRole",
        "permission_check": r"checkPermission|hasPermission",
        "missing_check": r"if\s*\(.*user.*\)",
        "exported_component": r"android:exported\s*=\s*\"true\""
    }


    auth_regex = {k: re.compile(v, re.I) for k, v in auth_patterns.items()}
    access_regex = {k: re.compile(v, re.I) for k, v in access_patterns.items()}


    for root, _, files in os.walk(source_dir):
        print(f"Scanning {root}...")
        
        for file in files:

            if not file.endswith(".java"):
                continue

            path = os.path.join(root, file)

            try:
                with open(path, "r", encoding="utf-8", errors="ignore") as f:
                    content = f.read()


                # -------- M4 Detection --------
                for key, regex in auth_regex.items():

                    if regex.search(content):

                        findings.append({
                            "title": "Weak Authentication Implementation",
                            "severity": "High",
                            "owasp": "M4: Insecure Authentication",
                            "path": os.path.relpath(path, source_dir),
                            "description": f"Authentication weakness detected ({key})",
                            "remediation": "Use OAuth2, JWT with expiration, and secure auth flows"
                        })


                # -------- M6 Detection --------
                for key, regex in access_regex.items():

                    if regex.search(content):

                        findings.append({
                            "title": "Weak Authorization Control",
                            "severity": "Medium",
                            "owasp": "M6: Insecure Authorization",
                            "path": os.path.relpath(path, source_dir),
                            "description": f"Authorization weakness detected ({key})",
                            "remediation": "Enforce server-side role and permission checks"
                        })


            except Exception:
                continue


    return findings
