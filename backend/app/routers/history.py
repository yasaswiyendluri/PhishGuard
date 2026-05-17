# app/routers/history.py
# GET /api/history — returns recent scans from MongoDB
# Powers the scan history table in your React dashboard

from fastapi import APIRouter
from app.db.mongo import get_recent_scans

router = APIRouter()


@router.get("/history")
async def get_history(limit: int = 20):
    """Returns the last N scans. Default 20."""
    scans = await get_recent_scans(limit)
    return {"scans": scans, "count": len(scans)}
