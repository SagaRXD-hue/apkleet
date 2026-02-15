IGNORE_PACKAGES = [
    "com/google/",
    "androidx/",
    "kotlin/",
    "kotlinx/",
    "com/google/android/gms/",
    "google/",
    "okhttp3/",
    "retrofit2/",
    "org/apache/",
    "com/facebook/",
    "com/firebase/",
    "com/squareup/"
]


def normalize_path(path: str) -> str:
    return path.replace("\\", "/").lower()


def should_ignore(path: str) -> bool:

    normalized = normalize_path(path)

    for pkg in IGNORE_PACKAGES:
        if pkg in normalized:
            return True

    return False   # ✅ IMPORTANT
