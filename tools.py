
"""
tools.py
Reusable utility functions for CyberSecurity-ResearchAI.
"""

import re
from datetime import datetime, timezone


VALID_SEVERITIES = {"CRITICAL", "HIGH", "MEDIUM", "LOW", "NONE", "UNKNOWN"}


def normalize_text(value, default=""):
    """Convert a value into clean, trimmed text."""
    if value is None:
        return default

    if isinstance(value, str):
        return " ".join(value.split()) or default

    return str(value)


def normalize_severity(severity=None, cvss_score=None):
    """Normalize severity or infer it from a CVSS base score."""
    if severity:
        value = normalize_text(severity).upper()

        aliases = {
            "MODERATE": "MEDIUM",
            "INFORMATIONAL": "NONE",
            "INFO": "NONE",
        }

        value = aliases.get(value, value)

        if value in VALID_SEVERITIES:
            return value

    try:
        score = float(cvss_score)
    except (TypeError, ValueError):
        return "UNKNOWN"

    if score < 0 or score > 10:
        return "UNKNOWN"
    if score == 0:
        return "NONE"
    if score < 4:
        return "LOW"
    if score < 7:
        return "MEDIUM"
    if score < 9:
        return "HIGH"

    return "CRITICAL"


def get_cvss_score(record):
    """Safely retrieve a CVSS score from a vulnerability record."""
    if not isinstance(record, dict):
        return None

    score = record.get("cvss_score")

    if score is None:
        score = record.get("baseScore")

    try:
        score = float(score)
    except (TypeError, ValueError):
        return None

    if not 0 <= score <= 10:
        return None

    return score


def validate_cve_id(cve_id):
    """Return True if the value resembles a valid CVE identifier."""
    if not isinstance(cve_id, str):
        return False

    return bool(
        re.fullmatch(r"CVE-\d{4}-\d{4,}", cve_id.strip(), re.IGNORECASE)
    )


def normalize_cve_id(cve_id):
    """Validate and return an uppercase CVE identifier."""
    if not validate_cve_id(cve_id):
        raise ValueError(
            "Invalid CVE ID. Expected a format like CVE-2021-44228."
        )

    return cve_id.strip().upper()


def is_known_exploited(record):
    """Read a known-exploited flag already supplied by another module."""
    if not isinstance(record, dict):
        return False

    value = record.get(
        "known_exploited",
        record.get("is_known_exploited", False),
    )

    if isinstance(value, str):
        return value.strip().lower() in {
            "true", "yes", "1", "known", "exploited"
        }

    return bool(value)


def calculate_risk_score(record):
    """
    Calculate a simple prioritization score.

    This is a heuristic, not a probability or calibrated security rating.
    """
    score = get_cvss_score(record)

    if score is None:
        return None

    risk_score = score

    if is_known_exploited(record):
        risk_score += 1.0

    return round(min(risk_score, 10.0), 2)


def filter_by_severity(records, severity):
    """Return records matching the requested severity."""
    if not isinstance(records, (list, tuple)):
        raise TypeError("records must be a list or tuple.")

    target = normalize_severity(severity)

    return [
        record
        for record in records
        if isinstance(record, dict)
        and normalize_severity(
            record.get("severity"),
            record.get("cvss_score"),
        ) == target
    ]


def filter_known_exploited(records):
    """Return records flagged as known exploited by the data source."""
    if not isinstance(records, (list, tuple)):
        raise TypeError("records must be a list or tuple.")

    return [
        record for record in records
        if isinstance(record, dict) and is_known_exploited(record)
    ]


def search_records(records, keyword):
    """Search CVE IDs, descriptions, vendors and products."""
    if not isinstance(records, (list, tuple)):
        raise TypeError("records must be a list or tuple.")

    keyword = normalize_text(keyword).lower()

    if not keyword:
        return list(records)

    searchable_fields = (
        "cve_id",
        "id",
        "description",
        "vendor",
        "product",
        "attack_type",
    )

    matches = []

    for record in records:
        if not isinstance(record, dict):
            continue

        searchable_text = " ".join(
            normalize_text(record.get(field))
            for field in searchable_fields
        ).lower()

        if keyword in searchable_text:
            matches.append(record)

    return matches


def sort_by_cvss(records, descending=True):
    """Sort records by CVSS score, placing unknown scores last."""
    if not isinstance(records, (list, tuple)):
        raise TypeError("records must be a list or tuple.")

    known = []
    unknown = []

    for record in records:
        if not isinstance(record, dict):
            continue

        score = get_cvss_score(record)

        if score is None:
            unknown.append(record)
        else:
            known.append((score, record))

    known.sort(key=lambda item: item[0], reverse=descending)

    return [record for _, record in known] + unknown


def get_utc_timestamp():
    """Return the current UTC timestamp in ISO 8601 format."""
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def summarize_records(records):
    """Create a compact summary of CVE records."""
    if not isinstance(records, (list, tuple)):
        raise TypeError("records must be a list or tuple.")

    valid_records = [
        record for record in records if isinstance(record, dict)
    ]

    severity_counts = {}
    score_values = []

    for record in valid_records:
        severity = normalize_severity(
            record.get("severity"),
            record.get("cvss_score"),
        )

        severity_counts[severity] = severity_counts.get(severity, 0) + 1

        score = get_cvss_score(record)
        if score is not None:
            score_values.append(score)

    return {
        "total": len(valid_records),
        "severity_distribution": severity_counts,
        "known_exploited": sum(
            is_known_exploited(record) for record in valid_records
        ),
        "average_cvss": (
            round(sum(score_values) / len(score_values), 2)
            if score_values else None
        ),
        "highest_cvss": max(score_values) if score_values else None,
        "generated_at": get_utc_timestamp(),
    }


if __name__ == "__main__":
    sample_records = [
        {
            "cve_id": "CVE-2021-44228",
            "severity": "CRITICAL",
            "cvss_score": 10.0,
            "known_exploited": True,
            "description": "Example remote code execution vulnerability",
            "vendor": "Apache",
            "product": "Log4j",
        },
        {
            "cve_id": "CVE-2023-0001",
            "severity": "HIGH",
            "cvss_score": 8.1,
            "known_exploited": False,
            "description": "Example vulnerability",
            "vendor": "Example",
            "product": "Application",
        },
    ]

    print("CVE ID validation:", validate_cve_id("CVE-2021-44228"))
    print("Severity:", normalize_severity(cvss_score=8.1))
    print("Risk score:", calculate_risk_score(sample_records[0]))
    print("Summary:", summarize_records(sample_records))
    print(
        "Critical records:",
        len(filter_by_severity(sample_records, "CRITICAL")),
    )
    print(
        "Search results for Apache:",
        len(search_records(sample_records, "Apache")),
    )
