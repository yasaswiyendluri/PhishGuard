# app/db/mongo.py
# MongoDB connection and all database functions
# motor = async version of pymongo (like mongoose but async)

import motor.motor_asyncio
from app.core.config import MONGO_URI, DB_NAME

# Create connection — like mongoose.connect() in Node
client = motor.motor_asyncio.AsyncIOMotorClient(MONGO_URI)
db = client[DB_NAME]
scans_collection = db["scans"]  # like a table/collection called "scans"


async def save_scan(scan_data: dict):
    """Save a scan result to MongoDB."""
    await scans_collection.insert_one(scan_data)


async def get_recent_scans(limit: int = 20):
    """Get the most recent scans, newest first."""
    cursor = scans_collection.find(
        {},                              # no filter = all records
        {"_id": 0}                       # exclude MongoDB's internal _id field
    ).sort("timestamp", -1).limit(limit)  # sort newest first
    return await cursor.to_list(length=limit)


async def get_scan_by_id(scan_id: str):
    """Get one specific scan by its ID."""
    return await scans_collection.find_one(
        {"scan_id": scan_id},
        {"_id": 0}
    )
