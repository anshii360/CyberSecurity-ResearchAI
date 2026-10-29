
"""
query_parser.py
Parse user research queries into structured search filters.
"""

import re


SEVERITIES = {
    "CRITICAL": ["critical", "crit"],
    "HIGH": ["high", "severe"],
    "MEDIUM": ["medium", "moderate", "med"],
    "LOW": ["low", "minor"],
}

PRODUCT_KEYWORDS = {
    "wordpress": ["wordpress", "wp plugin", "wp plugins"],
    "apache": ["apache", "apache http server"],
    "linux": ["linux", "ubuntu", "debian", "red hat", "rhel"],
    "windows": ["windows", "microsoft windows"],
    "chrome": ["chrome", "google chrome", "chromium"],
    "log4j": ["log4j", "apache log4j"],
    "openssh": ["openssh", "open ssh"],
    "nginx": ["nginx"],
    "mysql": ["mysql"],
    "postgresql": ["postgresql", "postgres"],
}


def _clean_query(query):
    """Normalize and validate a user query."""
    if query is None:
        return ""

    if not isinstance(query, str):
        raise TypeError("Query must be a string.")

    return re.sub(r"\s+", " ", query).strip()


def _find_severity(query):
    """Identify an explicitly requested severity."""
    words = set(re.findall(r"[a-zA-Z]+", query.lower()))

    for severity, aliases in SEVERITIES.items():
        if any(alias in words for alias in aliases):
            return severity

    return None


def _find_days(query, default_days=30):
    """Extract a time window in days, weeks or months."""
    text = query.lower()

    match = re.search(
        r"\b(?:last|past|within|in the last)?\s*"
        r"(\d{1,3})\s*(days?|weeks?|months?)\b",
        text,
    )

    if not match:
        return default_days

    amount = int(match.group(1))
    unit = match.group(2)

    if unit.startswith("week"):
        days = amount * 7
    elif unit.startswith("month"):
        days = amount * 30
    else:
        days = amount

    # NVD date-range requests are limited to 120 days.
    return max(1, min(days, 120))


def _find_limit(query, default_limit=100):
    """Extract a requested result count."""
    match = re.search(
        r"\b(?:top|limit|first|show|fetch|get)\s+(\d{1,4})\b",
        query.lower(),
    )

    if not match:
        return default_limit

    return max(1, min(int(match.group(1)), 2000))


def _find_product(query):
    """Detect a known product or technology mentioned in the query."""
    text = query.lower()

    # Prefer longer phrases to avoid matching a shorter alias first.
    candidates = []

    for canonical, aliases in PRODUCT_KEYWORDS.items():
        for alias in aliases:
            candidates.append((alias, canonical))

    candidates.sort(key=lambda item: len(item[0]), reverse=True)

    for alias, canonical in candidates:
        if re.search(r"(?<!\w)" + re.escape(alias) + r"(?!\w)", text):
            return canonical

    return None


def _find_cve_id(query):
    """Extract a CVE identifier if the user supplied one."""
    match = re.search(
        r"\bCVE-\d{4}-\d{4,}\b",
        query,
        re.IGNORECASE,
    )

    return match.group(0).upper() if match else None


def parse_query(query, default_days=30, default_limit=100):
    """
    Convert natural-language text into structured research parameters.

    Returns a dictionary with:
      original_query, search_keyword, severity, days, limit,
      known_exploited_only, cve_id, and intent.
    """
    cleaned = _clean_query(query)

    if not isinstance(default_days, int) or not 1 <= default_days <= 120:
        raise ValueError("default_days must be between 1 and 120.")

    if not isinstance(default_limit, int) or default_limit < 1:
        raise ValueError("default_limit must be positive.")

    lowered = cleaned.lower()

    severity = _find_severity(lowered)
    days = _find_days(cleaned, default_days)
    limit = _find_limit(cleaned, default_limit)
    product = _find_product(cleaned)
    cve_id = _find_cve_id(cleaned)

    exploited_phrases = (
        "known exploited",
        "actively exploited",
        "exploited vulnerabilities",
        "cisa kev",
        "kev catalog",
        "kev catalogue",
        "ransomware exploited",
    )

    known_exploited_only = any(
        phrase in lowered for phrase in exploited_phrases
    )

    if cve_id:
        intent = "single_cve"
        search_keyword = cve_id
    elif known_exploited_only:
        intent = "known_exploited"
        search_keyword = product
    elif product:
        intent = "product_search"
        search_keyword = product
    else:
        intent = "general_search"
        search_keyword = None

    return {
        "original_query": cleaned,
        "search_keyword": search_keyword,
        "product": product,
        "severity": severity,
        "days": days,
        "limit": limit,
        "known_exploited_only": known_exploited_only,
        "cve_id": cve_id,
        "intent": intent,
    }


def parse_query_string(query):
    """Compatibility alias for callers expecting a string parser."""
    return parse_query(query)


if __name__ == "__main__":
    examples = [
        "Show high severity Apache vulnerabilities from last 7 days",
        "Find the top 20 WordPress CVEs from last 2 weeks",
        "Show known exploited vulnerabilities",
        "Research CVE-2021-44228",
        "Find critical Linux vulnerabilities from last 30 days",
    ]

    for example in examples:
        print(f"\nQuery: {example}")
        print(parse_query(example))
