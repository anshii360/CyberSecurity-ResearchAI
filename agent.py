
"""
CyberSecurity-ResearchAI
Rule-based CVE analysis engine.
"""

import re


# --------------------------------------------------
# HELPER FUNCTIONS
# --------------------------------------------------

def _get_value(data, *keys, default=None):
    """Safely get the first available value from a dictionary."""
    if not isinstance(data, dict):
        return default

    for key in keys:
        value = data.get(key)
        if value is not None and value != "":
            return value

    return default


def _normalize_text(value):
    """Convert text or lists into lowercase searchable text."""
    if value is None:
        return ""

    if isinstance(value, (list, tuple, set)):
        return " ".join(str(item) for item in value).lower()

    return str(value).lower()


def _get_description(cve):
    return str(_get_value(
        cve, "description", "details", default=""
    ))


def _get_cve_id(cve):
    return str(_get_value(
        cve, "cve_id", "cveId", "id", default="UNKNOWN"
    )).upper()


def _get_cvss_score(cve):
    """Return a valid CVSS score between 0 and 10."""
    try:
        score = float(_get_value(
            cve, "cvss_score", "cvss", "score", default=0
        ))
        return max(0.0, min(10.0, score))
    except (TypeError, ValueError):
        return 0.0


def _get_severity(cve):
    """Use the provided severity, or infer it from CVSS."""
    severity = _get_value(cve, "severity", default="")

    if severity:
        severity = str(severity).upper()
        if severity in {"CRITICAL", "HIGH", "MEDIUM", "LOW", "NONE"}:
            return severity

    score = _get_cvss_score(cve)

    if score >= 9.0:
        return "CRITICAL"
    if score >= 7.0:
        return "HIGH"
    if score >= 4.0:
        return "MEDIUM"
    if score > 0:
        return "LOW"

    return "UNKNOWN"


def _get_searchable_text(cve):
    description = _get_description(cve)
    affected = _get_value(
        cve, "affected_systems", "affected_products", default=[]
    )
    vendor = _get_value(cve, "vendor", default="")
    product = _get_value(cve, "product", default="")

    return " ".join([
        _normalize_text(description),
        _normalize_text(affected),
        _normalize_text(vendor),
        _normalize_text(product),
    ])


# --------------------------------------------------
# ATTACK CLASSIFICATION
# --------------------------------------------------

def classify_attack(cve):
    """Identify a likely vulnerability category from its description."""
    text = _get_searchable_text(cve)

    patterns = [
        (["remote code execution", "arbitrary code execution"],
         "Remote Code Execution"),
        (["sql injection"], "SQL Injection"),
        (["cross-site scripting", "cross site scripting"],
         "Cross-Site Scripting"),
        (["command injection"], "Command Injection"),
        (["path traversal", "directory traversal"], "Path Traversal"),
        (["privilege escalation", "elevation of privilege"],
         "Privilege Escalation"),
        (["authentication bypass", "bypass authentication"],
         "Authentication Bypass"),
        (["denial of service"], "Denial of Service"),
        (["buffer overflow", "out-of-bounds write", "use after free"],
         "Memory Corruption"),
        (["server-side request forgery", "ssrf"],
         "Server-Side Request Forgery"),
        (["cross-site request forgery", "csrf"],
         "Cross-Site Request Forgery"),
        (["insecure deserialization"], "Insecure Deserialization"),
        (["information disclosure", "sensitive information exposure"],
         "Information Disclosure"),
        (["race condition"], "Race Condition"),
        (["file upload"], "File Upload Vulnerability"),
    ]

    for keywords, category in patterns:
        if any(keyword in text for keyword in keywords):
            return category

    return "Other / Needs Review"


# --------------------------------------------------
# AUTHENTICATION ANALYSIS
# --------------------------------------------------

def analyze_authentication(cve):
    """Estimate authentication requirements from available text."""
    text = _get_searchable_text(cve)

    if any(term in text for term in [
        "unauthenticated",
        "without authentication",
        "pre-authentication",
        "no authentication required",
    ]):
        return "No authentication required (reported)"

    if any(term in text for term in [
        "authenticated attacker",
        "requires authentication",
        "privileged user",
    ]):
        return "Authentication or privileges may be required"

    return "Unknown - verify vendor advisory"


# --------------------------------------------------
# IMPACT ANALYSIS
# --------------------------------------------------

def analyze_impact(cve):
    """Identify potential impacts mentioned in the CVE record."""
    text = _get_searchable_text(cve)
    impacts = []

    impact_patterns = [
        (
            ["remote code execution", "arbitrary code execution"],
            "Code Execution",
        ),
        (
            ["privilege escalation", "elevation of privilege"],
            "Privilege Escalation",
        ),
        (
            ["information disclosure", "sensitive information"],
            "Information Disclosure",
        ),
        (
            ["denial of service", "system crash"],
            "Availability Disruption",
        ),
        (
            ["modify data", "arbitrary file write", "data manipulation"],
            "Data Modification",
        ),
        (
            ["account takeover", "account compromise"],
            "Account Compromise",
        ),
    ]

    for keywords, label in impact_patterns:
        if any(keyword in text for keyword in keywords):
            impacts.append(label)

    if not impacts:
        return "Impact requires verification"

    return ", ".join(dict.fromkeys(impacts))


# --------------------------------------------------
# AFFECTED SYSTEM IDENTIFICATION
# --------------------------------------------------

def identify_affected_system(cve):
    """Extract affected-system information when available."""
    systems = _get_value(
        cve, "affected_systems", "affected_products", default=[]
    )

    if isinstance(systems, list):
        systems = ", ".join(str(item) for item in systems)

    if systems:
        return str(systems)

    vendor = _get_value(cve, "vendor", default="")
    product = _get_value(cve, "product", default="")

    if vendor or product:
        return f"{vendor} {product}".strip()

    return "Check the vendor advisory for affected versions"


# --------------------------------------------------
# KNOWN-EXPLOITED STATUS
# --------------------------------------------------

def _kev_status(cve):
    """Read known-exploited status already attached to the record."""
    value = _get_value(
        cve,
        "known_exploited",
        "is_known_exploited",
        default=False,
    )

    if isinstance(value, str):
        return value.strip().lower() in {
            "true", "yes", "1", "known exploited"
        }

    return bool(value)


# --------------------------------------------------
# REMEDIATION RECOMMENDATIONS
# --------------------------------------------------

def generate_recommendation(cve):
    """Generate a practical remediation recommendation."""
    score = _get_cvss_score(cve)

    if _kev_status(cve):
        return (
            "Prioritize immediate investigation. Confirm affected versions, "
            "apply the vendor security fix or mitigation, and review logs "
            "for signs of exploitation."
        )

    if score >= 9.0:
        return (
            "Urgently verify exposure and apply the vendor's security fix "
            "or mitigation. Review affected assets and monitor relevant logs."
        )

    if score >= 7.0:
        return (
            "Prioritize remediation. Verify affected versions, apply the "
            "vendor patch, and restrict exposure where appropriate."
        )

    if score >= 4.0:
        return (
            "Review the vendor advisory, confirm whether your systems are "
            "affected, and schedule remediation according to your risk."
        )

    return (
        "Verify the affected versions and review the vendor advisory "
        "for appropriate updates or mitigations."
    )


# --------------------------------------------------
# RISK SCORING
# --------------------------------------------------

def calculate_risk_score(cve):
    """
    Calculate a heuristic risk score.

    This is a prioritization aid, not an official CVSS score.
    """
    score = _get_cvss_score(cve)

    if _kev_status(cve):
        score += 1.0

    return round(min(10.0, score), 1)


# --------------------------------------------------
# ANALYZE ONE CVE
# --------------------------------------------------

def analyze_cve(cve):
    """Analyze a single CVE and return structured findings."""
    if not isinstance(cve, dict):
        raise TypeError("cve must be a dictionary")

    return {
        "cve_id": _get_cve_id(cve),
        "severity": _get_severity(cve),
        "attack_type": classify_attack(cve),
        "authentication": analyze_authentication(cve),
        "impact": analyze_impact(cve),
        "affected_system": identify_affected_system(cve),
        "known_exploited": _kev_status(cve),
        "risk_score": calculate_risk_score(cve),
        "recommendation": generate_recommendation(cve),
        "analysis_method": "Rule-based",
        "analysis_note": (
            "Automated heuristic analysis. Verify findings against "
            "the official CVE record and vendor advisory."
        ),
    }


# --------------------------------------------------
# ANALYZE MULTIPLE CVEs
# --------------------------------------------------

def analyze_vulnerabilities(vulnerabilities):
    """Analyze multiple CVEs and preserve their original fields."""
    results = []

    for cve in vulnerabilities:
        if not isinstance(cve, dict):
            continue

        result = dict(cve)
        result.update(analyze_cve(cve))
        results.append(result)

    return results


# --------------------------------------------------
# COMPATIBILITY ALIAS
# --------------------------------------------------

def generate_llm_analysis(cve):
    """Keep compatibility with code using this function name."""
    return analyze_cve(cve)


# --------------------------------------------------
# DIRECT TEST
# --------------------------------------------------

if __name__ == "__main__":
    sample_cve = {
        "cve_id": "CVE-2021-40539",
        "description": (
            "An example description mentioning remote code execution."
        ),
        "cvss_score": 9.8,
        "severity": "CRITICAL",
        "affected_systems": ["Example Product"],
        "known_exploited": True,
    }

    print("CyberSecurity-ResearchAI - Agent Test")
    print("-" * 45)

    result = analyze_cve(sample_cve)

    for key, value in result.items():
        print(f"{key}: {value}")
