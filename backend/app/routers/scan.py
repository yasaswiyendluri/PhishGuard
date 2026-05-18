# app/routers/scan.py
# Handles POST /api/scan
# This is like a route file in Express — router.post('/scan', handler)


# SANJANA DUMMY SERVICES ARE USED,REPLACE LATER

import asyncio

from fastapi import APIRouter, Request, Depends, HTTPException
from app.ml.predictor import predict as ml_predict
from slowapi.util import get_remote_address
from slowapi import Limiter
import uuid

from datetime import datetime, timezone
from app.models.schemas import ScanRequest, ScanResponse
from app.core.risk_engine import calculate_risk
from app.services.virustotal import check_virustotal
from app.services.urlhaus import check_urlhaus
from app.services.whois_dns import get_whois_dns
from app.services.deobfuscator import deobfuscate_url
from app.services.typosquatch import check_typosquatting
from app.db.mongo import save_scan
from app.core.security import get_current_user

router = APIRouter()
limiter = Limiter(key_func=get_remote_address)


@router.post("/scan", response_model=ScanResponse)
@limiter.limit("10/minute")  # max 10 scans per minute per IP
async def scan_url(
    request: Request,
    body: ScanRequest,
    current_user: dict = Depends(get_current_user),
):
    """
    Main scan endpoint.
    Takes a URL, runs all analysis, returns a full threat report.
    """

    # Step 1 — clean/decode the URL first
    # e.g. bit.ly/xyz → actual URL, hex encoded → readable
    clean_url = await deobfuscate_url(body.url)

    # Step 2 — run all threat intelligence checks concurrently
    # asyncio.gather runs all these AT THE SAME TIME (not one by one)
    # This keeps response time under 500ms — a stated project goal

    vt_result, urlhaus_result, whois_result, typo_result = await asyncio.gather(
        check_virustotal(clean_url),
        check_urlhaus(clean_url),
        get_whois_dns(body.url),
        check_typosquatting(body.url),
    )

    # ML prediction runs separately (it's CPU-bound, not async)
    # run_in_executor runs it in a thread so it doesn't block the server
    loop = asyncio.get_event_loop()
    ml_result = await loop.run_in_executor(None, ml_predict, body.url)

    # Step 3 — pass all results into your risk engine
    risk_data = calculate_risk(
        vt=vt_result,
        urlhaus=urlhaus_result,
        whois=whois_result,
        typo=typo_result,
        ml=ml_result
    )

    # Step 4 — build the final response
    scan_id = str(uuid.uuid4())  # unique ID like crypto.randomUUID() in JS
    response = ScanResponse(
        scan_id=scan_id,
        user_id=current_user["user_id"],
        url=body.url,
        risk_score=risk_data["score"],
        risk_level=risk_data["level"],
        prediction=risk_data["prediction"],
        explanation=risk_data["explanation"],
        features=whois_result,
        threat_intel={"virustotal": vt_result,
                      "urlhaus": urlhaus_result, "typosquatting": typo_result, "ml": ml_result},
        timestamp=datetime.now(timezone.utc),
    )

    # Step 5 — save to MongoDB for history/analytics
    await save_scan(response.model_dump())

    return response
