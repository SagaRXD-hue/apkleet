SEVERITY_SCORES = {
    "Critical": 20,
    "High": 10,
    "Medium": 5,
    "Low": 2
}


def calculate_risk(results):

    total = 0
    count = 0


    def extract_from_list(data):

        nonlocal total, count

        if not isinstance(data, list):
            return

        for item in data:

            if not isinstance(item, dict):
                continue

            severity = item.get("severity", "Low")

            score = SEVERITY_SCORES.get(severity, 2)

            total += score
            count += 1


    # Scan all sections
    for key in results:

        extract_from_list(results[key])


    # Cap score at 100
    if total > 100:
        total = 100


    # Determine risk level
    if total >= 80:
        level = "Critical"
    elif total >= 60:
        level = "High"
    elif total >= 30:
        level = "Medium"
    else:
        level = "Low"


    return {
        "score": total,
        "level": level,
        "issues_found": count
    }
