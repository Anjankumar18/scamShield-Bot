from fastapi import APIRouter, Request, HTTPException
import requests
import os

from twilio.twiml.messaging_response import MessagingResponse

from app.db.mongo import messages_collection
from app.models.message import create_message_doc

from app.services.ai_engine import analyze_with_ai
from app.services.url_engine import extract_urls
from app.services.scoring import calculate_risk
from app.services.hf_url_ai import analyze_url_hf


router = APIRouter()


# -------------------------------
# HuggingFace API Config
# -------------------------------

# HF_API_URL = os.getenv("HF_API_URL")


# def analyze_url_hf(url: str):
#     if not HF_API_URL:
#         raise Exception("HF_API_URL not set")

#     payload = {
#         "data": [url]
#     }
#     print(HF_API_URL,"---url")
#     print(payload,"----payload")
#     res = requests.post(
#         HF_API_URL,
#         json=payload,
#         timeout=30
#     )

#     if res.status_code != 200:
#         raise Exception(f"HF Error {res.status_code}: {res.text}")

#     result = res.json()

#     return result["data"][0]


# -------------------------------
# WhatsApp Webhook
# -------------------------------

@router.post("/webhook/whatsapp")
async def whatsapp_webhook(request: Request):

    try:

        # Read Twilio Form Data
        data = await request.form()

        message = data.get("Body")
        sender = data.get("From")

        if not message or not sender:
            raise HTTPException(status_code=400, detail="Missing fields")

        print("📩 Message:", message)
        print("👤 From:", sender)

        # -------------------------------
        # 1. Save Message
        # -------------------------------

        doc = create_message_doc(sender, message)

        db_result = messages_collection.insert_one(doc)

        message_id = db_result.inserted_id

        # -------------------------------
        # 2. Text AI Analysis
        # -------------------------------

        ai_text_result = await analyze_with_ai(message)

        # -------------------------------
        # 3. Extract URLs
        # -------------------------------

        urls = extract_urls(message)

        url_ai_result = {
            "is_scam": False,
            "risk": "low",
            "score": 0,
            "reasons": ["No URL found"]
        }

        # -------------------------------
        # 4. HuggingFace URL Scan
        # -------------------------------

        if urls:

            first_url = urls[0]

            print("🔗 Scanning URL:", first_url)

            url_ai_result = analyze_url_hf(first_url)


        # -------------------------------
        # 5. Risk Calculation
        # -------------------------------

        final_risk = calculate_risk(
            ai_text=ai_text_result,
            vt=None,             # Disabled
            url_ai=url_ai_result
        )


        # -------------------------------
        # 6. Update Database
        # -------------------------------

        messages_collection.update_one(
            {"_id": message_id},
            {
                "$set": {
                    "analyzed": True,
                    "ai_text": ai_text_result,
                    "urls": urls,
                    "url_ai": url_ai_result,
                    "risk": final_risk
                }
            }
        )


        # -------------------------------
        # 7. Build WhatsApp Reply
        # -------------------------------

        resp = MessagingResponse()

        reasons_text = ""

        if final_risk["reasons"]:
            reasons_text = "\n- " + "\n- ".join(final_risk["reasons"])


        reply_text = f"""
🛡️ ScamShield AI

📊 Risk Level: {final_risk['risk']}
📈 Score: {final_risk['score']}

🔍 Reasons:{reasons_text}

⚠️ Always verify before clicking links.
Stay safe!
""".strip()


        resp.message(reply_text)

        return str(resp)


    except Exception as e:

        print("🔥 WEBHOOK ERROR:", str(e))

        resp = MessagingResponse()

        resp.message(
            "⚠️ ScamShield Error\n\nUnable to analyze message right now. Please try again later."
        )

        return str(resp)
