def calculate_risk(ai_text, vt, url_ai, domain_age=None, rules=None, known_scam=False):

    score = 0
    reasons = []

    # -------- Text AI --------
    if ai_text and ai_text.get("is_scam") == True:
        score += 3
        reasons.append("AI detected scam language")

    # print(ai_text,"---ai_text")

    # -------- URL AI --------
    if url_ai and url_ai.get("is_scam"):
        score += 3
        reasons.append("AI flagged domain")

    # print(url_ai,"----url_ai--")

    # -------- VirusTotal --------
    if vt:
        if vt["malicious"] > 0:
            score += 4
            reasons.append("VirusTotal: malicious")

        if vt["suspicious"] > 0:
            score += 2
            reasons.append("VirusTotal: suspicious")

    # print(vt,"----vt--")

    # -------- Domain Age --------
    if domain_age is not None:

        if domain_age < 30:
            score += 3
            reasons.append("Very new domain")

        elif domain_age < 90:
            score += 2
            reasons.append("Recently registered domain")

    # print(domain_age,"----domain_age--")

    # -------- Rules --------
    if rules and len(rules) > 0:
        score += len(rules)
        reasons.append("Scam text patterns found")


    # -------- History --------
    if known_scam:
        score += 5
        reasons.append("Previously reported scam")


    # -------- Final --------
    if score >= 9:
        risk = "HIGH"
    elif score >= 5:
        risk = "MEDIUM"
    else:
        risk = "LOW"


    return {
        "score": score,
        "risk": risk,
        "reasons": reasons
    }
