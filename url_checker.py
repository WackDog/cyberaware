import ipaddress
from urllib.parse import urlparse


SUSPICIOUS_TERMS = {
    "login",
    "verify",
    "verification",
    "secure",
    "account",
    "update",
    "password",
    "payment",
    "billing",
}


def _normalise_url(raw_url):
    """Return a parseable URL while preserving whether the user supplied a scheme."""
    cleaned = (raw_url or "").strip()
    if not cleaned:
        raise ValueError("Enter a URL to analyse.")

    supplied_scheme = "://" in cleaned
    candidate = cleaned if supplied_scheme else "https://" + cleaned
    parsed = urlparse(candidate)

    if parsed.scheme not in {"http", "https"}:
        raise ValueError("Only http:// and https:// URLs can be analysed.")

    if not parsed.hostname:
        raise ValueError("Enter a valid URL containing a hostname.")

    return cleaned, parsed, supplied_scheme


def _is_ip_address(hostname):
    try:
        ipaddress.ip_address(hostname)
        return True
    except ValueError:
        return False


def analyse_url(raw_url):
    """
    Analyse a URL using transparent educational heuristics.

    The result is deliberately not a malware verdict. Each rule highlights a
    characteristic that can deserve extra scrutiny and explains why.
    """
    original, parsed, supplied_scheme = _normalise_url(raw_url)
    hostname = parsed.hostname.lower()
    warnings = []
    score = 0

    def add_warning(code, points, title, explanation):
        nonlocal score
        warnings.append(
            {
                "code": code,
                "points": points,
                "title": title,
                "explanation": explanation,
            }
        )
        score += points

    if _is_ip_address(hostname):
        add_warning(
            "ip-host",
            3,
            "IP address used as the hostname",
            "Most public services use a recognisable domain name. An IP-address link can make it harder to judge who operates the site.",
        )

    if "@" in parsed.netloc:
        add_warning(
            "at-symbol",
            3,
            "The URL contains an @ symbol before the hostname",
            "Text before an @ symbol can be misleading because browsers treat the part after @ as the actual host.",
        )

    if supplied_scheme and parsed.scheme == "http":
        add_warning(
            "http",
            1,
            "The URL uses HTTP rather than HTTPS",
            "HTTP does not provide the encrypted connection normally expected for logins, payments or other sensitive activity.",
        )

    labels = [label for label in hostname.split(".") if label]
    if not _is_ip_address(hostname) and len(labels) >= 5:
        add_warning(
            "subdomains",
            1,
            "The hostname contains many subdomains",
            "Long chains of subdomains can make the important registered-domain portion harder to notice at a glance.",
        )

    if "xn--" in hostname:
        add_warning(
            "punycode",
            2,
            "The hostname contains an internationalised-domain encoding",
            "Punycode is legitimate, but it can also be used in lookalike domains, so the address deserves careful checking.",
        )

    if hostname.count("-") >= 4:
        add_warning(
            "hyphens",
            1,
            "The hostname contains an unusually high number of hyphens",
            "Heavy use of separators can make a hostname harder to read and can be a sign that a domain is imitating another service.",
        )

    if len(original) >= 120:
        add_warning(
            "length",
            1,
            "The URL is unusually long",
            "Very long links can hide important parts of the destination among tracking parameters or misleading text.",
        )

    searchable_text = (hostname + " " + parsed.path.lower()).replace("-", " ").replace("_", " ")
    matched_terms = sorted(term for term in SUSPICIOUS_TERMS if term in searchable_text)
    if matched_terms:
        add_warning(
            "sensitive-terms",
            1,
            "The URL contains account or security-related wording",
            "Words such as login, verify or payment are common on legitimate sites too, but attackers also use them to make links appear convincing.",
        )

    if score >= 5:
        risk_level = "High"
    elif score >= 2:
        risk_level = "Medium"
    else:
        risk_level = "Low"

    return {
        "original": original,
        "hostname": hostname,
        "scheme": parsed.scheme if supplied_scheme else "not supplied",
        "warnings": warnings,
        "score": score,
        "risk_level": risk_level,
    }
