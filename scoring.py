"""Educational security-configuration score (not an industry rating)."""
DEDUCTIONS = {"High": 20, "Medium": 10, "Low": 3, "Informational": 0}

def compute_score(findings, deductions=DEDUCTIONS):
    seen, score = set(), 100
    for f in findings:
        if f["id"] in seen:  # never double-count the same issue
            continue
        seen.add(f["id"])
        score -= deductions.get(f["severity"], 0)
    return max(score, 0)

def risk_category(score):
    return "Low risk" if score >= 85 else "Moderate risk" if score >= 60 else "High risk"
