# app/services/virustotal.py
# Calls VirusTotal API v3 to check URL reputation
# VirusTotal checks your URL against 90+ security vendors simultaneously

import httpx
import base64
from app.core.config import VIRUSTOTAL_API_KEY


async def check_virustotal(url: str) -> dict:
    """
    VirusTotal API works in 2 steps:
    Step 1 — Submit URL for analysis (POST) → get analysis ID
    Step 2 — Fetch results using that ID (GET) → get vendor verdicts

    URL must be base64 encoded (VT requirement) for the GET request
    """

    if not VIRUSTOTAL_API_KEY:
        # No key configured — return empty result, don't crash
        return _empty_result()

    headers = {"x-apikey": VIRUSTOTAL_API_KEY}

    try:
        async with httpx.AsyncClient(timeout=15) as client:

            # ── Step 1: Submit URL ─────────────────────────────
            submit_response = await client.post(
                "https://www.virustotal.com/api/v3/urls",
                headers=headers,
                data={"url": url}  # sent as form data, not JSON
            )
            submit_response.raise_for_status()
            analysis_id = submit_response.json()["data"]["id"]

            # ── Step 2: Fetch analysis results ────────────────
            # URL id for GET = base64 encode of the url (no padding)
            url_id = base64.urlsafe_b64encode(
                url.encode()).decode().rstrip("=")

            result_response = await client.get(
                f"https://www.virustotal.com/api/v3/urls/{url_id}",
                headers=headers,
            )
            result_response.raise_for_status()
            data = result_response.json()

            # ── Extract what we need ───────────────────────────
            stats = data["data"]["attributes"]["last_analysis_stats"]
            # stats looks like: {"malicious": 5, "suspicious": 2, "harmless": 80, "undetected": 3}

            malicious = stats.get("malicious", 0)
            suspicious = stats.get("suspicious", 0)
            harmless = stats.get("harmless", 0)
            undetected = stats.get("undetected", 0)
            total = malicious + suspicious + harmless + undetected

            return {
                "malicious_count": malicious,
                "suspicious_count": suspicious,
                "total_vendors": total,
                "reputation_score": data["data"]["attributes"].get("reputation", 0),
                "raw": stats
            }

    except httpx.HTTPStatusError as e:
        # API returned an error (wrong key, rate limit, etc.)
        return {**_empty_result(), "error": f"VT API error: {e.response.status_code}"}
    except Exception as e:
        return {**_empty_result(), "error": str(e)}


def _empty_result() -> dict:
    """Returns a safe empty result when VT can't be reached."""
    return {
        "malicious_count": 0,
        "suspicious_count": 0,
        "total_vendors": 0,
        "reputation_score": 0,
        "raw": {}
    }
