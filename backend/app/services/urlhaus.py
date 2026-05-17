# app/services/urlhaus.py
# Checks URL against URLHaus — abuse.ch's database of malicious URLs
# Free, no API key required
# Docs: https://urlhaus-api.abuse.ch/

# app/services/urlhaus.py

import httpx
from app.core.config import URLHAUS_API_KEY


async def check_urlhaus(url: str) -> dict:
    try:
        headers = {}
        if URLHAUS_API_KEY:
            headers["Auth-Key"] = URLHAUS_API_KEY

        async with httpx.AsyncClient(timeout=10) as client:
            response = await client.post(
                "https://urlhaus-api.abuse.ch/v1/url/",
                headers=headers,
                data={"url": url}
            )
            response.raise_for_status()
            data = response.json()

            if data.get("query_status") == "blacklisted":
                return {
                    "is_blacklisted": True,
                    "threat_type": data.get("threat", "unknown"),
                    "tags": data.get("tags") or [],
                    "date_added": data.get("date_added", ""),
                }

            return {"is_blacklisted": False, "threat_type": None, "tags": []}

    except Exception as e:
        return {"is_blacklisted": False, "threat_type": None, "tags": [], "error": str(e)}
