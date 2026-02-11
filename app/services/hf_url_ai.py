from gradio_client import Client
import os


HF_SPACE = "Anjan18/scamshield-url-ai"
HF_TOKEN = os.getenv("HF_TOKEN")


if not HF_TOKEN:
    raise Exception("HF_TOKEN not set")


client = Client(
    HF_SPACE,
    token=HF_TOKEN
)


def analyze_url_hf(url: str):

    try:
        result = client.predict(
            url,
            api_name="/predict"   # ✅ FIXED
        )
        print(result,"----result")
        return result

    except Exception as e:

        print("🔥 HF CLIENT ERROR:", e)

        return {
            "is_scam": False,
            "risk": "unknown",
            "reason": "HF unavailable"
        }
