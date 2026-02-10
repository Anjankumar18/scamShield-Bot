from fastapi import APIRouter, Request, HTTPException

from twilio.twiml.messaging_response import MessagingResponse

from app.db.mongo import messages_collection
from app.models.message import create_message_doc

from app.services.ai_engine import analyze_with_ai
from app.services.nlp_engine import analyze_nlp
from app.services.url_engine import extract_urls
from app.services.url_reputation import scan_url
from app.services.url_ai import analyze_url_ai
from app.services.scoring import calculate_risk


router = APIRouter()


@router.post("/webhook/whatsapp")
async def whatsapp_webhook(request: Request):

    try:
        # Read Twilio form data
        data = await request.form()

        message = data.get("Body")
        sender = data.get("From")

        if not message or not sender:
            raise HTTPException(status_code=400, detail="Missing fields")

        # -------------------------------
        # 1. Store raw message
        # -------------------------------

        doc = create_message_doc(sender, message)

        db_result = messages_collection.insert_one(doc)

        message_id = db_result.inserted_id

        # -------------------------------
        # 2. AI Text Analysis
        # -------------------------------

        ai_text_result = await analyze_with_ai(message)

        # -------------------------------
        # 3. NLP Analysis
        # -------------------------------

        nlp_result = analyze_nlp(message)

        # -------------------------------
        # 4. URL Extraction
        # -------------------------------

        urls = extract_urls(message)

        vt_result = None
        url_ai_result = None

        # -------------------------------
        # 5. URL Reputation (If Any URL)
        # -------------------------------

        if urls:

            first_url = urls[0]

            try:
                vt_result = scan_url(first_url)
            except Exception as e:
                vt_result = {
                    "malicious": 0,
                    "suspicious": 0,
                    "harmless": 0,
                    "error": str(e)
                }

            try:
                url_ai_result = await analyze_url_ai(first_url)
            except Exception as e:
                url_ai_result = {
                    "is_scam": False,
                    "risk": "unknown",
                    "reason": str(e)
                }

        else:
            vt_result = {
                "malicious": 0,
                "suspicious": 0,
                "harmless": 0
            }

            url_ai_result = {
                "is_scam": False,
                "risk": "low",
                "reason": "No URL found"
            }

        # -------------------------------
        # 6. Final Risk Scoring
        # -------------------------------

        final_risk = calculate_risk(
            ai_text=ai_text_result,
            nlp=nlp_result,
            vt=vt_result,
            url_ai=url_ai_result
        )

        # -------------------------------
        # 7. Update Database
        # -------------------------------

        messages_collection.update_one(
            {"_id": message_id},
            {
                "$set": {
                    "analyzed": True,
                    "ai_text": ai_text_result,
                    "nlp": nlp_result,
                    "urls": urls,
                    "virustotal": vt_result,
                    "url_ai": url_ai_result,
                    "risk": final_risk
                }
            }
        )

        # -------------------------------
        # 8. Build WhatsApp Reply
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

        print("🔥 WEBHOOK ERROR:", str(e))  # ADD THIS

        resp = MessagingResponse()

        resp.message(
            "⚠️ ScamShield Error\n\nUnable to analyze message right now. Please try again later."
        )

        return str(resp)
