"""
Security score and report.

Method:
  - Start at 100 and subtract a penalty per finding:
      high -15, medium -8, low -3, info/pass 0
  - Any HIGH finding caps the score at 74 (max Grade C): a site with a critical
    problem (e.g. no HTTPS, untrusted certificate) shouldn't get an A or B.
  - Grade: A 90+, B 80+, C 70+, D 60+, F below 60
  - Category score: how many checks in that category passed, weighted by severity
"""
SEVERITY_ORDER = ["high", "medium", "low", "info", "pass"]
CATEGORY_ORDER = ["Headers", "SSL/TLS", "Misconfiguration", "Ports"]

PENALTY = {"high": 15, "medium": 8, "low": 3, "info": 0, "pass": 0}
WEIGHT = {"high": 1.0, "medium": 0.6, "low": 0.3, "pass": 0.0}  # for category scores (info isn't scored)
HIGH_SEVERITY_CAP = 74

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


def _severity_rank(finding):
    sev = finding.get("severity")
    return SEVERITY_ORDER.index(sev) if sev in SEVERITY_ORDER else len(SEVERITY_ORDER)


def _category_score(items):
    scored = [f for f in items if f["severity"] in WEIGHT]
    if not scored:
        return 100
    lost = sum(WEIGHT[f["severity"]] for f in scored)
    return round(100 * (1 - lost / len(scored)))


def build_report(findings):
    findings = sorted(findings, key=_severity_rank)

    counts = {s: 0 for s in SEVERITY_ORDER}
    for f in findings:
        if f["severity"] in counts:
            counts[f["severity"]] += 1

    score = max(0, 100 - sum(PENALTY.get(f["severity"], 0) for f in findings))
    capped = counts["high"] > 0 and score > HIGH_SEVERITY_CAP
    if capped:
        score = HIGH_SEVERITY_CAP

    grade, summary = _grade(score)
    if capped:
        summary += " The grade is capped at C because of a high-severity issue."

    present = {f["category"] for f in findings}
    names = [c for c in CATEGORY_ORDER if c in present] + sorted(present - set(CATEGORY_ORDER))
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