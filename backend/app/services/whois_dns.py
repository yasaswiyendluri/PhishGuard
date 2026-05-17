# app/services/whois_dns.py
# Two jobs:
# 1. WHOIS — gets domain registration info (age, registrar)
# 2. DNS   — checks DNS records for suspicious patterns

import asyncio

import whois
import dns.resolver
import tldextract
from datetime import datetime, timezone


async def get_whois_dns(url: str) -> dict:
    extracted = tldextract.extract(url)

    if not extracted.domain or not extracted.suffix:
        return _empty_result(url)

    domain = f"{extracted.domain}.{extracted.suffix}"

    whois_data = await _get_whois(domain)
    dns_data = await _get_dns(domain)

    return {**whois_data, **dns_data}


async def _get_whois(domain: str) -> dict:
    try:
        loop = asyncio.get_event_loop()
        w = await asyncio.wait_for(
            loop.run_in_executor(None, whois.whois, domain),
            timeout=5.0  # give up after 5 seconds
        )

        creation_date = w.creation_date
        if isinstance(creation_date, list):
            creation_date = creation_date[0]

        if creation_date:
            if creation_date.tzinfo is not None:
                creation_date = creation_date.replace(tzinfo=None)

            age_days = (
                datetime.now(timezone.utc) - creation_date
            ).days
        else:
            age_days = 365

        return {
            "domain": domain,
            "domain_age_days": age_days,
            "registrar": str(w.registrar) if w.registrar else "unknown",
            "creation_date": str(creation_date),
        }
    except asyncio.TimeoutError:
        # WHOIS timed out — return safe default, don't block the scan
        return {
            "domain": domain,
            "domain_age_days": 365,
            "registrar": "unknown",
            "creation_date": "unknown",
            "whois_error": "timeout"
        }
    except Exception as e:
        return {
            "domain": domain,
            "domain_age_days": 365,
            "registrar": "unknown",
            "creation_date": "unknown",
            "whois_error": str(e)
        }


async def _get_dns(domain: str) -> dict:
    """
    Checks DNS records for suspicious patterns.

    Phishing sites often:
    - Have no MX records (not a real email domain)
    - Use suspicious nameservers
    - Have very few A records
    """
    result = {
        "dns_a_records": [],
        "dns_mx_records": [],
        "dns_ns_records": [],
        "dns_suspicious": False,
        "dns_flags": []
    }

    # Check A records (IP addresses the domain points to)
    try:
        a_records = dns.resolver.resolve(domain, 'A')
        result["dns_a_records"] = [str(r) for r in a_records]
    except Exception:
        result["dns_flags"].append("No A records found")
        result["dns_suspicious"] = True

    # Check MX records (mail servers — real orgs always have these)
    try:
        mx_records = dns.resolver.resolve(domain, 'MX')
        result["dns_mx_records"] = [str(r.exchange) for r in mx_records]
    except Exception:
        result["dns_flags"].append("No MX records (not a real mail domain)")
        # Not always suspicious alone, but combined with other signals it is

    # Check NS records (nameservers)
    try:
        ns_records = dns.resolver.resolve(domain, 'NS')
        result["dns_ns_records"] = [str(r) for r in ns_records]

        # Flag cheap/suspicious nameserver providers commonly used by phishers
        suspicious_ns = ["freenom", "000webhost", "hostinger"]
        for ns in result["dns_ns_records"]:
            if any(s in ns.lower() for s in suspicious_ns):
                result["dns_flags"].append(f"Suspicious nameserver: {ns}")
                result["dns_suspicious"] = True
    except Exception:
        result["dns_flags"].append("No NS records found")

    return result


def _empty_result(url: str) -> dict:
    return {
        "domain": url,
        "domain_age_days": 365,
        "registrar": "unknown",
        "creation_date": "unknown",
        "dns_a_records": [],
        "dns_mx_records": [],
        "dns_ns_records": [],
        "dns_suspicious": False,
        "dns_flags": []
    }
