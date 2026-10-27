SEVERITY_ORDER = ["high", "medium", "low", "info", "pass"]
CATEGORY_ORDER = ["Headers", "SSL/TLS", "Misconfiguration", "Ports"]

PENALTY = {"high": 15, "medium": 8, "low": 3, "info": 0, "pass": 0}
# For category scores: how much each result "fails" (info isn't scored)
WEIGHT = {"high": 1.0, "medium": 0.6, "low": 0.3, "pass": 0.0}

GRADES = [
    (90, "A", "Excellent! This website follows most security best practices."),
    (80, "B", "Good security setup, with a few improvements to make."),
    (70, "C", "Fair. Several security settings are missing or weak."),
    (60, "D", "Weak. Important security protections are missing."),
    (0,  "F", "Poor. This website is missing many basic security protections."),
]


def _grade(score):
    for minimum, grade, summary in GRADES:
        if score >= minimum:
            return grade, summary


def _category_score(items):
    scored = [f for f in items if f["severity"] in WEIGHT]
    if not scored:
        return 100
    lost = sum(WEIGHT[f["severity"]] for f in scored)
    return round(100 * (1 - lost / len(scored)))


def build_report(findings):
    findings = sorted(findings, key=lambda f: SEVERITY_ORDER.index(f["severity"]))

    counts = {s: 0 for s in SEVERITY_ORDER}
    for f in findings:
        counts[f["severity"]] += 1

    score = max(0, 100 - sum(PENALTY[f["severity"]] for f in findings))
    grade, summary = _grade(score)

    names = [c for c in CATEGORY_ORDER if any(f["category"] == c for f in findings)]
    categories = []
    for name in names:
        items = [f for f in findings if f["category"] == name]
        categories.append({
            "name": name,
            "score": _category_score(items),
            "issues": sum(1 for f in items if f["severity"] in ("high", "medium", "low")),
            "passed": sum(1 for f in items if f["severity"] == "pass"),
        })

    return {
        "score": score,
        "grade": grade,
        "summary": summary,
        "counts": counts,
        "categories": categories,
        "findings": findings,
    }