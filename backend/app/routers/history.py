from fastapi import APIRouter, Depends

from app.db.mongo import get_recent_scans, get_user_stats
from app.core.security import get_current_user

router = APIRouter()


@router.get("/history")
async def get_history(
    limit: int = 20,
    current_user: dict = Depends(get_current_user),
):
    """Returns the last N scans for the authenticated analyst."""
    user_id = current_user["user_id"]
    scans = await get_recent_scans(limit, user_id=user_id)
    return {"scans": scans, "count": len(scans)}


@router.get("/stats")
async def get_stats(current_user: dict = Depends(get_current_user)):
    """Dashboard aggregate stats for the current user."""
    user_id = current_user["user_id"]
    scans = await get_recent_scans(limit=500, user_id=user_id)
    by_level = await get_user_stats(user_id)

    total = len(scans)
    threats = sum(1 for s in scans if s.get("prediction") == "phishing")
    safe = total - threats

    return {
        "total_scans": total,
        "threats_detected": threats,
        "safe_urls": safe,
        "by_risk_level": by_level,
        "last_scan": scans[0]["timestamp"] if scans else None,
    }
