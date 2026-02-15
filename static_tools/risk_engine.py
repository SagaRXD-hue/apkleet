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
            confidence = item.get("confidence", "Low")

            base_score = SEVERITY_SCORES.get(severity, 2)

            # Confidence multipliers:
            MULT = {"High": 1.0, "Medium": 0.6, "Low": 0.3}

            score = base_score * MULT.get(confidence, 0.3)


            total += score
            count += 1


    # Scan all sections
    for key, value in results.items():
        if isinstance(value, list):
            extract_from_list(value)




    # Normalize score
    if count > 0:
        total = int((total / (count * 20)) * 100)
    else:
        total = 0



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
