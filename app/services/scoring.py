# in scoring.py

def calculate_risk(ai_text, vt, url_ai):

    score = 0
    reasons = []

    if ai_text.get("label") == "Scam":
        score += 4
        reasons.append("Scam-like message")

    if ai_text.get("label") == "Fake":
        score += 3
        reasons.append("Fake news pattern")

    if vt.get("malicious", 0) > 0:
        score += 5
        reasons.append("Malicious domain")

    if url_ai.get("is_scam"):
        score += 3
        reasons.append("AI flagged URL")

    if score >= 7:
        risk = "HIGH"
    elif score >= 3:
        risk = "MEDIUM"
    else:
        risk = "LOW"

    return {
        "score": score,
        "risk": risk,
        "reasons": reasons
    }
