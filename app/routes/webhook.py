from fastapi import APIRouter, Request, HTTPException
from fastapi.responses import Response
from twilio.twiml.messaging_response import MessagingResponse

from app.db.mongo import messages_collection
from app.models.message import create_message_doc
from app.services.ai_engine import analyze_with_ai
from app.services.url_engine import extract_urls
from app.services.url_reputation import scan_url
from app.services.url_ai import analyze_url_ai
from app.services.scoring import calculate_risk

router = APIRouter()


@router.post("/webhook/whatsapp")
async def whatsapp_webhook(request: Request):
    try:
        data = await request.form()

        message = data.get("Body")
        sender = data.get("From")

        if not message or not sender:
            raise HTTPException(status_code=400, detail="Missing fields")

        # 1. Store message
        doc = create_message_doc(sender, message)
        db_result = messages_collection.insert_one(doc)
        message_id = db_result.inserted_id

        # 2. AI analysis
        ai_text_result = await analyze_with_ai(message)

        # 3. URL extraction
        urls = extract_urls(message)

        vt_result = {"malicious": 0, "suspicious": 0, "harmless": 0}
        url_ai_result = {"is_scam": False, "risk": "low", "reason": "No URL found"}

        if urls:
            first_url = urls[0]

            try:
                vt_result = scan_url(first_url)
            except Exception as e:
                vt_result["error"] = str(e)

            try:
                url_ai_result = await analyze_url_ai(first_url)
            except Exception as e:
                url_ai_result = {"is_scam": False, "risk": "unknown", "reason": str(e)}

        # 4. Final risk
        final_risk = calculate_risk(
            ai_text=ai_text_result,
            vt=vt_result,
            url_ai=url_ai_result
        )

        # 5. Update DB
        messages_collection.update_one(
            {"_id": message_id},
            {"$set": {"analyzed": True, "risk": final_risk}}
        )

        # 6. Build reply
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

        resp = MessagingResponse()
        resp.message(reply_text)

        print("📤 TWILIO XML:", str(resp))

        return Response(
            content=str(resp),
            media_type="application/xml"
        )

    except Exception as e:
        print("🔥 WEBHOOK ERROR:", str(e))

        resp = MessagingResponse()
        resp.message(
            "⚠️ ScamShield Error\n\nUnable to analyze message right now. Please try again later."
        )

        return Response(
            content=str(resp),
            media_type="application/xml"
        )
