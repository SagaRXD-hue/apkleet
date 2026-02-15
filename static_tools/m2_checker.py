import os

KEYWORDS = [
    "SharedPreferences",
    "MODE_WORLD_READABLE",
    "openFileOutput"
]

def scan_m2(source_dir):
    results = []

    for root, _, files in os.walk(source_dir):
        print(f"Scanning {root}...")
        for f in files:
            if f.endswith(".java"):
                path = os.path.join(root, f)

                with open(path, errors="ignore") as file:
                    content = file.read()

                for key in KEYWORDS:
                    if key in content:
                        results.append({
                            "title": "Insecure Data Storage",
                            "severity": "High",
                            "owasp": "M2",
                            "path": path,
                            "description": f"Possible insecure storage: {key}",
                            "remediation": "Use EncryptedSharedPreferences"
                        })

    return results
