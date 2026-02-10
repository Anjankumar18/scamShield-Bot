import json
from app.services.ai_engine import client


async def analyze_url_ai(url: str) -> dict:

    prompt = f"""
    Analyze this URL for phishing or scam:

    {url}

    Respond ONLY in JSON:
    {{
      "is_scam": true/false,
      "risk": "low/medium/high",
      "reason": ""
    }}
    """

    response = client.chat.completions.create(
        model="gpt-4.1-mini",
        messages=[
            {"role": "system", "content": "You analyze malicious URLs."},
            {"role": "user", "content": prompt}
        ],
        temperature=0.1
    )

    content = response.choices[0].message.content

    # ✅ Parse JSON safely
    try:
        return json.loads(content)
    except Exception:
        return {
            "is_scam": False,
            "risk": "unknown",
            "reason": "AI parse error"
        }
