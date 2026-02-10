from datetime import datetime


def create_message_doc(sender, text, result="pending"):

    return {
        "sender": sender,
        "text": text,
        "result": result,
        "created_at": datetime.utcnow(),
        "analyzed": False
    }
