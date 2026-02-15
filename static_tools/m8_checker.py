import os
import re


ANTI_TAMPER_PATTERNS = {

    "debugger_check": r"\bDebug\.isDebuggerConnected\(",

    "root_su": r"/system/(xbin|bin)/su\b|\bwhich\s+su\b",

    "frida": r"\bfrida\b|\bgum-js-loop\b",

    "xposed": r"\bxposed\b|de\.robv\.android\.xposed",

    "signature_check": r"getPackageInfo\([^,]+,\s*PackageManager\.GET_SIGNATURES"
}



def scan_m8(source_dir):

    findings = []

    protection_found = False


    for root, dirs, files in os.walk(source_dir):
        print(f"Scanning {root}...")
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

            if not (file.endswith(".java") or file.endswith(".kt")):
                continue

            path = os.path.join(root, file)

            try:
                with open(path, "r", encoding="utf-8", errors="ignore") as f:
                    data = f.read()
            except:
                continue


            for name, pattern in ANTI_TAMPER_PATTERNS.items():

                if re.search(pattern, data, re.IGNORECASE):

                    protection_found = True

                    findings.append({
                        "title": "Anti-Tampering Logic Detected",
                        "type": name,
                        "severity": "Low",
                        "owasp": "M8: Code Tampering",
                        "path": os.path.relpath(path, source_dir),
                        "description": f"Tamper protection found: {name}",
                        "remediation": "Ensure protections are not bypassable"
                    })


    # If NO protection at all
    if not protection_found:

        findings.append({
            "title": "Missing Anti-Tampering Protection",
            "severity": "Medium",
            "owasp": "M8: Code Tampering",
            "path": path,
            "description": "No anti-debug/root/tamper protection detected",
            "remediation": "Implement root, debugger, and integrity checks"
        })


    print(f"[*] Anti-tampering findings: {len(findings)}")
    unique = []
    seen = set()

    for f in findings:

        key = (f["title"], f["path"])

        if key not in seen:
            seen.add(key)
            unique.append(f)

    return unique
