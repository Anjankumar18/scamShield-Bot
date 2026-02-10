def calculate_risk(ai_text, nlp, vt, url_ai):

    score = 0
    reasons = []

    # AI text
    if ai_text.get("label") == "Scam":
        score += 3
        reasons.append("Scam-like message")

    if ai_text.get("label") == "Fake":
        score += 3
        reasons.append("Fake news pattern")

    # NLP
    if nlp.get("label") == "NEGATIVE":
        score += 1
        reasons.append("Emotional manipulation")

    # VirusTotal
    if vt.get("malicious", 0) > 0:
        score += 5
        reasons.append("Malicious domain")

    if vt.get("suspicious", 0) > 0:
        score += 3
        reasons.append("Suspicious domain")

    # URL AI
    if url_ai.get("is_scam") is True:
        score += 3
        reasons.append("AI flagged URL")

    # Final
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
