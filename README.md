# 📱 APKHUNTER --- Android APK Security Analyzer

APKHUNTER is a comprehensive static analysis framework for Android APK
files. It scans decompiled source code to identify security
vulnerabilities based on the **OWASP Mobile Top 10** and generates
detailed security reports with a global risk score.

------------------------------------------------------------------------

## 🚀 Features

-   APK decompilation using JADX\
-   Static source code analysis\
-   Hardcoded secrets detection\
-   Insecure communication detection\
-   Weak cryptography detection\
-   Extraneous functionality analysis\
-   Anti-tampering & reverse engineering checks\
-   Global risk scoring\
-   Report generation (JSON / PDF / HTML / TXT)\
-   Centralized logging

------------------------------------------------------------------------

## 📌 OWASP Mobile Top 10 Coverage

  ID    Category                    Support
  ----- --------------------------- ---------
  M1    Improper Platform Usage     Partial
  M2    Insecure Data Storage       ✅
  M3    Insecure Communication      ✅
  M4    Insecure Authentication     ✅
  M5    Insufficient Cryptography   ✅
  M6    Broken Authorization        ✅
  M7    Client Code Quality         Partial
  M8    Code Tampering              ✅
  M9    Reverse Engineering         ✅
  M10   Extraneous Functionality    ✅

------------------------------------------------------------------------

## 📥 Installation

This repository includes a pre-configured virtual environment.

``` bash
git clone https://github.com/SagaRXD-hue/APKHUNTER.git
cd APKHUNTER
```

Activate venv:

### Windows

``` bash
venv\Scripts\activate
```

### Linux / macOS

``` bash
source venv/bin/activate
```

------------------------------------------------------------------------

## ▶️ Usage

``` bash
python APKHUNTER.py -apk sample.apk
```

Generate report:

``` bash
python APKHUNTER.py -apk sample.apk -report json -o reports
```

------------------------------------------------------------------------

## 📁 Output

    reports/
     ├── report_app.json
     └── last_scan.log

    app_source/
     └── app/

------------------------------------------------------------------------

## 📊 Risk Scoring

  Severity   Score
  ---------- -------
  Critical   20
  High       10
  Medium     5
  Low        2

------------------------------------------------------------------------

## 🏗️ Structure

    APKHUNTER/
    ├── APKHUNTER.py
    ├── static_tools/
    ├── analyzer/
    ├── report_gen/
    ├── risk_engine.py
    ├── reports/
    └── venv/

------------------------------------------------------------------------

## ⚠️ Limitations

-   Static analysis only
-   Possible false positives
-   Partial M1/M7 support

------------------------------------------------------------------------

## 📜 License

MIT License

------------------------------------------------------------------------

## 👨‍💻 Author

SagaRXD-hue

https://github.com/SagaRXD-hue
