import os
from pymongo import MongoClient
from dotenv import load_dotenv

load_dotenv()

MONGO_URI = os.getenv("MONGO_URI")

if not MONGO_URI:
    raise Exception("MONGO_URI not set in .env")

client = MongoClient(
    MONGO_URI,
    serverSelectionTimeoutMS=5000
)

# Test connection
client.admin.command("ping")

db = client["scamshield"]

messages_collection = db["messages"]
reports_collection = db["reports"]
