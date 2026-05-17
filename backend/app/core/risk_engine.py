# app/core/risk_engine.py
# YOUR custom risk scoring logic — this is what makes PhishGuard unique
# Combines ML + VirusTotal + WHOIS + Typosquatting into one score

def calculate_risk(vt: dict, urlhaus: dict, whois: dict, typo: dict) -> dict:
    """
    Combines all intelligence sources into a single risk score (0–100).

    Weights:
    - VirusTotal detections : 40%
    - Domain age (WHOIS)    : 25%
    - URLHaus blacklist     : 20%
    - Typosquatting         : 15%
    -DNS flags              :10%
    Total max               :110 capped at 100
    ML model score will be added here once teammate delivers model.pkl
    At that point weights will shift:
    - ML score              : 30%
    - VirusTotal            : 30%
    - Domain age            : 20%
    - URLHaus               : 10%
    - Typosquatting         : 10%
    """

    score = 0
    reasons = []

    # ── VirusTotal score (0–40 points) ────────────────────────
    vt_malicious = vt.get("malicious_count", 0)
    vt_total = vt.get("total_vendors", 1)
    vt_ratio = vt_malicious / vt_total  # what fraction of vendors flagged it
    vt_score = min(vt_ratio * 40, 40)   # cap at 40
    score += vt_score
    if vt_malicious > 0:
        reasons.append(f"Flagged by {vt_malicious} VirusTotal vendors")

    # ── Domain age score (0–25 points) ────────────────────────
    # Very new domains are suspicious — phishers register fresh domains
    domain_age_days = whois.get("domain_age_days", 365)
    if domain_age_days < 7:
        score += 25
        reasons.append(f"Domain is only {domain_age_days} days old")
    elif domain_age_days < 30:
        score += 15
        reasons.append(
            f"Domain is {domain_age_days} days old (recently registered)")
    elif domain_age_days < 90:
        score += 5

    # ── URLHaus blacklist (0–20 points) ───────────────────────
    if urlhaus.get("is_blacklisted", False):
        score += 20
        reasons.append("URL found in URLHaus malicious database")

    # ── Typosquatting (0–15 points) ───────────────────────────
    typo_match = typo.get("closest_domain", None)
    typo_distance = typo.get("distance", 99)

    typo_is_squat = typo.get("is_typosquat", False)
    if typo_is_squat and typo_distance <= 2:
        score += 15
        reasons.append(
            f"URL resembles '{typo_match}' (possible typosquatting)")
    elif typo_is_squat and typo_distance <= 4:
        score += 7

     # ── DNS anomalies (bonus points, up to 10) ────────────────
# Shifts weight when ML model is added later
    dns_suspicious = whois.get("dns_suspicious", False)
    dns_flags = whois.get("dns_flags", [])

    if dns_suspicious:
        score += 10
    for flag in dns_flags:
        reasons.append(f"DNS: {flag}")

    # ── Final score capped at 100 ─────────────────────────────
    final_score = min(int(score), 100)

    # ── Risk level label ──────────────────────────────────────
    if final_score >= 75:
        level = "CRITICAL"
    elif final_score >= 50:
        level = "HIGH"
    elif final_score >= 25:
        level = "MEDIUM"
    else:
        level = "LOW"

    # ── Human-readable explanation ────────────────────────────
    explanation = ". ".join(
        reasons) if reasons else "No major threats detected"

    return {
        "score": final_score,
        "level": level,
        "prediction": "phishing" if final_score >= 50 else "safe",
        "explanation": explanation,
    }
