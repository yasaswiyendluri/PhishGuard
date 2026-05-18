# app/routers/scan.py
# Handles POST /api/scan

from fastapi import APIRouter, Request, Depends
from slowapi.util import get_remote_address
from slowapi import Limiter
from datetime import datetime, timezone
import uuid
import asyncio

from app.models.schemas import ScanRequest, ScanResponse
from app.core.risk_engine import calculate_risk
from app.services.virustotal import check_virustotal
from app.services.urlhaus import check_urlhaus
from app.services.whois_dns import get_whois_dns
from app.services.deobfuscator import deobfuscate_url
from app.services.typosquatch import check_typosquatting
from app.db.mongo import save_scan
from app.core.security import get_current_user
from app.ml.predictor import predict

router = APIRouter()
limiter = Limiter(key_func=get_remote_address)


@router.post("/scan", response_model=ScanResponse)
@limiter.limit("10/minute")
async def scan_url(
    request: Request,
    body: ScanRequest,
    current_user: dict = Depends(get_current_user),
):
    """Main scan endpoint — ML + CTI pipeline."""
    clean_url = await deobfuscate_url(body.url)

    ml_result = predict(clean_url)

    vt_result, urlhaus_result, whois_result, typo_result = await asyncio.gather(
        check_virustotal(clean_url),
        check_urlhaus(clean_url),
        get_whois_dns(body.url),
        check_typosquatting(body.url),
    )

    risk_data = calculate_risk(
        vt=vt_result,
        urlhaus=urlhaus_result,
        whois=whois_result,
        typo=typo_result,
        ml=ml_result,
    )

    scan_id = str(uuid.uuid4())
    response = ScanResponse(
        scan_id=scan_id,
        user_id=current_user["user_id"],
        url=body.url,
        risk_score=risk_data["score"],
        risk_level=risk_data["level"],
        prediction=risk_data["prediction"],
        explanation=risk_data["explanation"],
        ml_confidence=ml_result.get("ml_confidence") if ml_result.get("ml_ready") else None,
        ml_prediction=ml_result.get("ml_prediction") if ml_result.get("ml_ready") else None,
        ml_ready=bool(ml_result.get("ml_ready")),
        features=whois_result,
        threat_intel={
            "ml": ml_result,
            "virustotal": vt_result,
            "urlhaus": urlhaus_result,
            "typosquatting": typo_result,
        },
        timestamp=datetime.now(timezone.utc),
    )

    await save_scan(response.model_dump(mode="json"))

    return response
