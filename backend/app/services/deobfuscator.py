# Expands shortened URLs (bit.ly etc) and decodes obfuscated URLs
# e.g. http://bit.ly/abc123 → https://actual-phishing-site.com

import httpx
import urllib.parse


async def deobfuscate_url(url: str) -> str:
    try:
        # Follow redirects to get the final destination URL
        async with httpx.AsyncClient(follow_redirects=True, timeout=5) as client:
            response = await client.head(url)
            return str(response.url)  # the final resolved URL
    except Exception:
        return url  # if it fails, just use original
