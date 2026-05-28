# backend/app/core/risk_engine.py
# PhishGuard Risk Engine v3.0
# Multi-signal weighted threat scoring — no hardcoded keywords
# Works on structural URL analysis + live threat intelligence + ML probability

def calculate_risk(vt: dict, urlhaus: dict, whois: dict, typo: dict, ml: dict = None) -> dict:
    """
    Produces a 0-100 risk score combining all threat intelligence signals.

    Signal contributions (approximate):
        ML Model probability     : 0-35 pts
        VirusTotal vendors       : 0-25 pts
        Domain age (WHOIS)       : 0-20 pts
        Typosquatting            : 0-25 pts (major brands get higher weight)
        Brand embedded in domain : 0-18 pts
        Structural URL analysis  : 0-22 pts (hyphens, length, subdomains)
        URLHaus blacklist        : 0-15 pts
        Suspicious TLD           : 0-10 pts
        DNS anomalies            : 0-10 pts
        Max before cap           : ~180 pts → capped at 100
    """

    domain = whois.get("domain", "")
    domain_lower = domain.lower().strip()

    WHITELIST = [
        "google.com", "youtube.com", "facebook.com", "amazon.com",
        "microsoft.com", "apple.com", "twitter.com", "instagram.com",
        "linkedin.com", "github.com", "wikipedia.org", "reddit.com",
        "netflix.com", "whatsapp.com", "yahoo.com", "bing.com",
        "stackoverflow.com", "cloudflare.com", "openai.com",
        "anthropic.com", "notion.so", "figma.com", "canva.com",
        "dropbox.com", "zoom.us", "slack.com", "discord.com",
        "twitch.tv", "spotify.com", "adobe.com", "salesforce.com",
    ]
    if any(domain_lower == w or domain_lower.endswith(f".{w}") for w in WHITELIST):
        return {
            "score": 0,
            "level": "LOW",
            "prediction": "safe",
            "explanation": "No major threats detected",
            "ml_used": False
        }

    score = 0.0
    reasons = []
    ml = ml or {}

    # SIGNAL 1 — ML Model Probability (0-35 pts)
    # Uses predict_proba continuous score, not binary 0/1
    # Scale: 0.50→0pts, 0.65→10pts, 0.80→21pts, 0.90→28pts, 1.0→35pts

    ml_ready = ml.get("ml_ready", False)
    ml_score = ml.get("ml_score", 0.0)
    ml_confidence = ml.get("ml_confidence", 0)

    if ml_ready and ml_score >= 0.5:
        ml_points = (ml_score - 0.5) * 70  # maps 0.5–1.0 → 0–35
        score += ml_points
        if ml_score >= 0.7:
            reasons.append(
                f"ML model flagged as phishing ({ml_confidence}% confidence)"
            )

    # SIGNAL 2 — VirusTotal Reputation (0-25 pts)
    vt_malicious = vt.get("malicious_count", 0)
    vt_suspicious = vt.get("suspicious_count", 0)
    vt_total = max(vt.get("total_vendors", 1), 1)

    vt_effective = vt_malicious + (vt_suspicious * 0.5)
    vt_ratio = vt_effective / vt_total
    vt_points = min(vt_ratio * 150, 25)
    score += vt_points

    if vt_malicious >= 10:
        reasons.append(f"Flagged by {vt_malicious} VirusTotal vendors")
    elif vt_malicious >= 3:
        reasons.append(f"Flagged by {vt_malicious} VirusTotal vendors")
    elif vt_malicious > 0:
        reasons.append(f"Flagged by {vt_malicious} VirusTotal vendor(s)")
    elif vt_suspicious > 0:
        reasons.append(
            f"Marked suspicious by {vt_suspicious} VirusTotal vendors")

    # SIGNAL 3 — Domain Age via WHOIS (0-20 pts)
    domain_age_days = whois.get("domain_age_days", 365)

    if domain_age_days != 365:
        if domain_age_days < 7:
            score += 20
            reasons.append(f"Domain is only {domain_age_days} days old")
        elif domain_age_days < 30:
            score += 15
            reasons.append(
                f"Domain is {domain_age_days} days old (recently registered)"
            )
        elif domain_age_days < 90:
            score += 8
            reasons.append(
                f"Domain is {domain_age_days} days old (relatively new)")
        elif domain_age_days < 180:
            score += 3

    # SIGNAL 4 — Typosquatting Detection (0-25 pts)
    # Levenshtein distance check against known legitimate domains
    MAJOR_BRANDS = [
        "google.com", "amazon.com", "paypal.com", "apple.com",
        "microsoft.com", "facebook.com", "netflix.com", "instagram.com",
        "twitter.com", "linkedin.com", "ebay.com", "bankofamerica.com",
        "wellsfargo.com", "chase.com", "citibank.com", "youtube.com",
        "whatsapp.com", "dropbox.com", "adobe.com", "icloud.com",
    ]

    typo_is_squat = typo.get("is_typosquat", False)
    typo_distance = typo.get("distance", 99)
    typo_match = typo.get("closest_domain", None)

    if typo_is_squat:
        is_major = typo_match in MAJOR_BRANDS
        if typo_distance <= 2:
            pts = 25 if is_major else 12
            score += pts
            reasons.append(
                f"URL closely mimics {'major brand' if is_major else 'known domain'} "
                f"'{typo_match}' (typosquatting)"
            )
        elif typo_distance <= 4:
            pts = 12 if is_major else 6
            score += pts
            reasons.append(f"URL loosely resembles '{typo_match}'")

    # SIGNAL 5 — Brand Embedded in Domain Structure (0-18 pts)
    KNOWN_BRANDS = [
        "paypal", "amazon", "google", "apple", "microsoft",
        "facebook", "netflix", "instagram", "twitter", "ebay",
        "linkedin", "chase", "wellsfargo", "jetblue", "fedex",
        "dhl", "ups", "usps", "irs", "bankofamerica", "citibank",
        "dropbox", "adobe", "yahoo", "outlook", "office365",
        "coinbase", "binance", "kraken", "blockchain", "metamask",
        "steam", "playstation", "xbox", "nintendo", "roblox",
    ]

    # Only fire if this domain is NOT the real brand domain
    is_real_brand = any(
        domain_lower == f"{b}.com" or
        domain_lower == f"www.{b}.com" or
        domain_lower == f"{b}.net" or
        domain_lower == f"{b}.org"
        for b in KNOWN_BRANDS
    )

    if not is_real_brand:
        brand_hits = [b for b in KNOWN_BRANDS if b in domain_lower]
        if brand_hits:
            score += 18
            reasons.append(
                f"Brand name '{brand_hits[0]}' embedded in non-official domain"
            )

    # SIGNAL 6 — Structural URL Analysis (0-22 pts)
    # 6a — Hyphen count in domain (0-12 pts)
    hyphen_count = domain_lower.count("-")
    if hyphen_count >= 3:
        score += 12
        reasons.append(
            f"Domain has {hyphen_count} hyphens (highly suspicious structure)")
    elif hyphen_count == 2:
        score += 8
        reasons.append(
            f"Domain has {hyphen_count} hyphens (suspicious structure)")
    elif hyphen_count == 1:
        score += 4
        # Don't add to reasons for single hyphen — too common to be alarming

    # 6b — Domain length (0-6 pts)
    domain_name_only = domain_lower.split(".")[0]
    if len(domain_name_only) > 25:
        score += 6
        reasons.append(
            f"Unusually long domain name ({len(domain_name_only)} chars)")
    elif len(domain_name_only) > 18:
        score += 4
        reasons.append(f"Long domain name ({len(domain_name_only)} chars)")
    elif len(domain_name_only) > 13:
        score += 2

    # 6c — Excessive subdomain depth (0-4 pts)
    dot_count = domain_lower.count(".")
    if dot_count >= 3:
        score += 4
        reasons.append(f"Excessive subdomain depth ({dot_count} levels)")
    # SIGNAL 7 — URLHaus Blacklist (0-15 pts)
    if urlhaus.get("is_blacklisted", False):
        score += 15
        threat = urlhaus.get("threat_type", "malicious")
        reasons.append(f"URL found in URLHaus blacklist (threat: {threat})")

    # SIGNAL 8 — Suspicious TLD (0-10 pts)
    SUSPICIOUS_TLDS = {
        "xyz", "tk", "ml", "ga", "cf", "gq", "pw",  # free TLDs
        "top", "click", "su", "zip", "fit", "cam",    # abused cheap TLDs
        "loan", "work", "party", "racing",             # spam TLDs
        "stream", "download", "review", "win",         # scam TLDs
    }
    tld = domain_lower.split(".")[-1] if "." in domain_lower else ""
    if tld in SUSPICIOUS_TLDS:
        score += 10
        reasons.append(f"High-risk TLD detected (.{tld})")
    # SIGNAL 9 — DNS Anomalies (0-10 pts)
    dns_flags = whois.get("dns_flags", [])
    dns_suspicious = whois.get("dns_suspicious", False)

    if dns_flags or dns_suspicious:
        dns_points = min(len(dns_flags) * 4, 10)
        score += dns_points
        for flag in dns_flags:
            reasons.append(f"DNS: {flag}")

    # FINAL SCORING
    final_score = min(int(score), 100)
    ml_very_high = ml_ready and ml_score >= 0.88
    vt_confirmed = vt_malicious >= 8

    if final_score >= 75 or (final_score >= 55 and ml_very_high):
        level = "CRITICAL"
    elif final_score >= 45 or ml_very_high or vt_confirmed:
        level = "HIGH"
    elif final_score >= 22:
        level = "MEDIUM"
    else:
        level = "LOW"

    # Phishing verdict logic:
    # Any of these alone is enough to call it phishing:
    # 1. Composite score >= 45
    # 2. ML is 88%+ confident
    # 3. 8+ VirusTotal vendors flagged it
    # 4. URLHaus blacklisted it
    is_phishing = (
        final_score >= 45
        or (ml_ready and ml_score >= 0.88)
        or vt_malicious >= 8
        or urlhaus.get("is_blacklisted", False)
    )

    explanation = ". ".join(
        reasons) if reasons else "No major threats detected"

    return {
        "score": final_score,
        "level": level,
        "prediction": "phishing" if is_phishing else "safe",
        "explanation": explanation,
        "ml_used": ml_ready
    }
