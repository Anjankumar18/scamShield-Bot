import os
import json
from openai import OpenAI

# Initialize client
client = OpenAI(
    api_key=os.getenv("OPENAI_API_KEY")
)


async def analyze_with_ai(text: str) -> dict:

    try:

        prompt = f"""
You are a cybersecurity assistant.

Analyze this message and decide:
- Is it Scam, respond true or false(BOOLEAN)?
- Risk level: Low, Medium, High
- Short reason

Message:
{text}

Respond ONLY in JSON:
{{
  "is_scam": "",
  "risk": "",
  "reason": ""
}}
"""

        response = client.responses.create(
            model="gpt-4.1-mini",
            input=prompt,
            temperature=0.2
        )

        content = response.output_text

        print("AI RAW:", content)


        # Parse JSON
        try:
            return json.loads(content)

        except Exception:
            return {
                "is_scam": "Unknown",
                "risk": "Unknown",
                "reason": "AI parse error"
            }


    except Exception as e:

        print("🔥 OPENAI ERROR:", e)

        return {
            "is_scam": "Unknown",
            "risk": "Unknown",
            "reason": "AI unavailable"
        }
