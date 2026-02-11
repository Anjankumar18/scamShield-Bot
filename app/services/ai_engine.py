import os
import json
from openai import OpenAI

client = OpenAI(api_key=os.getenv("OPENAI_API_KEY"))


async def analyze_with_ai(text: str) -> dict:

    prompt = f"""
    You are a cybersecurity assistant.

    Analyze this message and decide:
    - Is it Scam, Fake News, or Safe?
    - Risk level: Low, Medium, High
    - Short reason

    Message:
    {text}

    Respond ONLY in JSON:
    {{
      "label": "",
      "risk": "",
      "reason": ""
    }}
    """

    response = client.chat.completions.create(
        model="gpt-3.5-turbo",
        messages=[
            {"role": "system", "content": "You detect scams and fake news."},
            {"role": "user", "content": prompt}
        ],
        temperature=0.2
    )

    content = response.choices[0].message.content

    # ✅ Parse JSON safely
    try:
        return json.loads(content)
    except Exception:
        return {
            "label": "Unknown",
            "risk": "Unknown",
            "reason": "AI parse error"
        }
