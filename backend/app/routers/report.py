# app/routers/report.py
# GET /api/report/{scan_id} — returns full report for one scan
# Powers the detailed threat report page in your dashboard

from fastapi import APIRouter, HTTPException
from app.db.mongo import get_scan_by_id
from app.db.scan_serialize import enrich_scan_ml_fields

router = APIRouter()


@router.get("/report/{scan_id}")
async def get_report(scan_id: str):
    """Returns full scan report by ID."""
    report = await get_scan_by_id(scan_id)
    if not report:
        raise HTTPException(status_code=404, detail="Report not found")
    return enrich_scan_ml_fields(dict(report))
