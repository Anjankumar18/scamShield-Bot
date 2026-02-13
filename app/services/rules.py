import re


SCAM_PATTERNS = [
    r"won\s+\₹?\d+",
    r"free\s+money",
    r"urgent",
    r"verify\s+now",
    r"account\s+blocked",
    r"limited\s+time",
    r"click\s+here",
    r"gift\s+card",
    r"lottery",
]


def rule_check(text: str):

    hits = []

    text = text.lower()

    for p in SCAM_PATTERNS:
        if re.search(p, text):
            hits.append(p)

    return hits
