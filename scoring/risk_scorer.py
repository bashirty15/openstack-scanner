SEVERITY_WEIGHTS = {
    "CRITICAL": 40,
    "HIGH": 25,
    "MEDIUM": 15,
    "LOW": 5,
}


def calculate_score(findings):
    score = 0

    for f in findings:
        score += SEVERITY_WEIGHTS.get(f.get("severity", "LOW"), 0)

    return min(score, 100)
