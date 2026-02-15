import os
import re


WEAK_CRYPTO_PATTERNS = {

    # Broken hashes
    "MD5": r'MessageDigest\.getInstance\("MD5"\)',
    "SHA1": r'MessageDigest\.getInstance\("SHA-?1"\)',

    # Weak symmetric crypto
    "DES": r'Cipher\.getInstance\("DES/(ECB|CBC|CFB|OFB)',

    "RC4": r'Cipher\.getInstance\("RC4/',

    # Explicit ECB mode
    "ECB": r'Cipher\.getInstance\("AES/ECB/'
}




def scan_crypto(source_dir):

    findings = []

    for root, dirs, files in os.walk(source_dir):
        print(f"Scanning {root}...")
        # Skip test and example code
        if "test" in root.lower() or "example" in root.lower():
            continue

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

                    # Remove comments (Java/Kotlin)
                    data = re.sub(r'//.*', '', data)
                    data = re.sub(r'/\*.*?\*/', '', data, flags=re.S)

            except:
                continue

            for algo, pattern in WEAK_CRYPTO_PATTERNS.items():

                if re.search(pattern, data):

                    findings.append({
                        "title": "Weak Cryptography",
                        "severity": "High" if algo == "MD5" or algo == "ECB" else "Medium",
                        "owasp": "M5: Insufficient Cryptography",
                        "path": path,
                        "description": f"Insecure crypto algorithm detected: {algo}",
                        "remediation": "Use AES-GCM / SHA-256 / SHA-3"
                    })

    print(f"[*] Weak crypto findings: {len(findings)}")

    unique = []
    seen = set()

    for f in findings:

        key = (f["title"], f["path"])

        if key not in seen:
            seen.add(key)
            unique.append(f)

    return unique
