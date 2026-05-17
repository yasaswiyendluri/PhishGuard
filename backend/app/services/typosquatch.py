# Checks if URL looks like a typo of a famous domain
# e.g. paypa1.com vs paypal.com

import Levenshtein
import tldextract

# Top domains to compare against
TOP_DOMAINS = [
    "google.com", "facebook.com", "amazon.com", "paypal.com",
    "microsoft.com", "apple.com", "netflix.com", "instagram.com",
    "twitter.com", "linkedin.com", "github.com", "youtube.com",
    "whatsapp.com", "gmail.com", "yahoo.com", "bankofamerica.com",
]


async def check_typosquatting(url: str) -> dict:
    extracted = tldextract.extract(url)
    scanned_domain = f"{extracted.domain}.{extracted.suffix}"

    closest = None
    min_distance = 99

    for legit_domain in TOP_DOMAINS:
        distance = Levenshtein.distance(scanned_domain, legit_domain)
        if distance < min_distance:
            min_distance = distance
            closest = legit_domain

    return {
        "scanned_domain": scanned_domain,
        "closest_domain": closest,
        "distance": min_distance,
        "is_typosquat": min_distance <= 2 and scanned_domain != closest
    }
