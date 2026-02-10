# from dotenv import load_dotenv
# load_dotenv()
from fastapi import FastAPI
from app.routes.webhook import router as webhook_router

app = FastAPI(
    title="ScamShield AI",
    version="1.0.0"
)

app.include_router(webhook_router)

@app.get("/")
def health():
    return {"status": "ok"}
