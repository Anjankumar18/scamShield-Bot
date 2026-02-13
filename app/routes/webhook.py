from fastapi import APIRouter, Request, HTTPException
from fastapi.responses import Response

from twilio.twiml.messaging_response import MessagingResponse

from app.db.mongo import messages_collection
from app.models.message import create_message_doc

# AI + Analysis
from app.services.ai_engine import analyze_with_ai
from app.services.hf_url_ai import analyze_url_hf

# URL Tools
from app.services.url_engine import extract_urls
from app.services.url_redirect import resolve_final_url
from app.services.domain_age import get_domain_age
from app.services.virus_total import scan_url_vt

# Rules + Scoring
from app.services.rules import rule_check
from app.services.scoring import calculate_risk


router = APIRouter()


# ------------------------------------  -------------
# WhatsApp Webhook
# -------------------------------------------------

@router.post("/webhook/whatsapp")
async def whatsapp_webhook(request: Request):

    try:

        # -------------------------------------------------
        # Read Twilio Form Data
        # -------------------------------------------------

        data = await request.form()

        message = data.get("Body")
        sender = data.get("From")

        if not message or not sender:
            raise HTTPException(status_code=400, detail="Missing fields")


        print("📩 Message:", message)
        print("👤 From:", sender)


        # -------------------------------------------------
        # 1. Save Raw Message
        # -------------------------------------------------

        doc = create_message_doc(sender, message)

        db_result = messages_collection.insert_one(doc)

        message_id = db_result.inserted_id


        # -------------------------------------------------
        # 2. AI Text Analysis
        # -------------------------------------------------

        ai_text_result = await analyze_with_ai(message)


        # -------------------------------------------------
        # 3. Extract URLs
        # -------------------------------------------------

        urls = extract_urls(message)

        final_url = None
        vt_result = None
        domain_age = None
        url_ai_result = None
        known_scam = False


        # -------------------------------------------------
        # 4. Rule Engine
        # -------------------------------------------------

        rule_hits = rule_check(message)


        # -------------------------------------------------
        # 5. URL Processing (If Exists)
        # -------------------------------------------------

        if urls:

            first_url = urls[0]

            print("🔗 Original URL:", first_url)

            # Resolve redirect
            final_url = resolve_final_url(first_url)

            print("➡️ Final URL:", final_url)


            # -------- History Check --------

            prev = messages_collection.find_one(
                {
                    "urls.final": final_url,
                    "risk.risk": "HIGH"
                }
            )

            if prev:
                known_scam = True
                print("⚠️ Known scam URL found in DB")


            # -------- VirusTotal --------

            try:
                vt_result = scan_url_vt(final_url)
            except Exception as e:
                print("VT ERROR:", e)

                vt_result = {
                    "malicious": 0,
                    "suspicious": 0,
                    "harmless": 0,
                    "undetected": 0
                }


            # -------- Domain Age --------

            domain_age = get_domain_age(final_url)


            # -------- HuggingFace AI --------

            url_ai_result = analyze_url_hf(final_url)


        else:

            url_ai_result = {
                "is_scam": False,
                "risk": "low",
                "reason": "No URL found"
            }


        # -------------------------------------------------
        # 6. Risk Calculation
        # -------------------------------------------------

        final_risk = calculate_risk(
            ai_text=ai_text_result,
            vt=vt_result,
            url_ai=url_ai_result,
            domain_age=domain_age,
            rules=rule_hits,
            known_scam=known_scam
        )


        # -------------------------------------------------
        # 7. Update Database
        # -------------------------------------------------

        messages_collection.update_one(
            {"_id": message_id},
            {
                "$set": {
                    "analyzed": True,

                    "ai_text": ai_text_result,

                    "urls": {
                        "original": urls[0] if urls else None,
                        "final": final_url
                    },

                    "virustotal": vt_result,
                    "domain_age": domain_age,
                    "url_ai": url_ai_result,
                    "rules": rule_hits,
                    "known_scam": known_scam,

                    "risk": final_risk
                }
            }
        )


        # -------------------------------------------------
        # 8. Build WhatsApp Reply
        # -------------------------------------------------

        resp = MessagingResponse()

        reasons_text = ""
        reasons_block = ""
        print(final_risk,"----")
        
        if final_risk.get("reasons"):

            if len(final_risk["reasons"]) > 0:

                reasons_list = "\n- " + "\n- ".join(final_risk["reasons"])

                reasons_block = f"""

🔍 Reasons:{reasons_list}
"""

        reply_text = f"""
🛡️ ScamShield AI

📊 Risk Level: {final_risk['risk']}
📈 Score: {final_risk['score']}{reasons_block}

⚠️ Always verify before clicking links.
Stay safe!
""".strip()


        resp.message(reply_text)


        return Response(
            content=str(resp),
            media_type="text/xml"
        )


    # -------------------------------------------------
    # Error Handler
    # -------------------------------------------------

    except Exception as e:

        print("🔥 WEBHOOK ERROR:", str(e))


        resp = MessagingResponse()

        resp.message(
            "⚠️ ScamShield Error\n\nUnable to analyze message right now. Please try again later."
        )


        return Response(
            content=str(resp),
            media_type="text/xml"
        )
