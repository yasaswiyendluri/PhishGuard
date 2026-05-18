# app/db/mongo.py
# MongoDB connection and all database functions

import motor.motor_asyncio
from app.core.config import MONGO_URI, DB_NAME

client = motor.motor_asyncio.AsyncIOMotorClient(MONGO_URI)
db = client[DB_NAME]
scans_collection = db["scans"]
users_collection = db["users"]


async def save_scan(scan_data: dict):
    """Save a scan result to MongoDB."""
    await scans_collection.insert_one(scan_data)


async def get_recent_scans(limit: int = 20, user_id=None):
    """Get the most recent scans, optionally filtered by user."""
    query = {"user_id": user_id} if user_id else {}
    cursor = scans_collection.find(query, {"_id": 0}).sort("timestamp", -1).limit(limit)
    return await cursor.to_list(length=limit)


async def get_scan_by_id(scan_id: str):
    """Get one specific scan by its ID."""
    return await scans_collection.find_one({"scan_id": scan_id}, {"_id": 0})


async def get_user_stats(user_id: str):
    """Aggregate scan counts by risk level for dashboard stats."""
    pipeline = [
        {"$match": {"user_id": user_id}},
        {
            "$group": {
                "_id": "$risk_level",
                "count": {"$sum": 1},
            }
        },
    ]
    rows = await scans_collection.aggregate(pipeline).to_list(length=20)
    return {row["_id"]: row["count"] for row in rows}


async def create_user(user_doc: dict) -> dict:
    await users_collection.insert_one(user_doc)
    user_doc.pop("password_hash", None)
    user_doc.pop("_id", None)
    return user_doc


async def get_user_by_email(email: str):
    return await users_collection.find_one({"email": email.lower()})


async def get_user_by_username(username: str):
    return await users_collection.find_one({"username": username.lower()})


async def get_user_by_id(user_id: str):
    return await users_collection.find_one(
        {"user_id": user_id},
        {"_id": 0, "password_hash": 0},
    )
