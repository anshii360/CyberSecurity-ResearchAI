
import requests
from datetime import datetime, timedelta, timezone


NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
REQUEST_TIMEOUT = 30


def _parse_date(value):
    """Convert an ISO date string into a timezone-aware datetime."""
    if not value:
        return None

    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except (ValueError, TypeError):
        return None


def _get_cvss(metrics):
    """Extract the best available CVSS score, severity and version."""
    for metric_name in (
        "cvssMetricV40",
        "cvssMetricV31",
        "cvssMetricV30",
        "cvssMetricV2",
    ):
        metric_list = metrics.get(metric_name, [])

        if not metric_list:
            continue

        metric = metric_list[0]
        cvss_data = metric.get("cvssData", {})

        score = cvss_data.get("baseScore")
        severity = (
            cvss_data.get("baseSeverity")
            or metric.get("baseSeverity")
            or "UNKNOWN"
        )
        version = cvss_data.get("version", "")

        if score is not None:
            return score, str(severity).upper(), version

    return None, "UNKNOWN", ""


def _get_description(descriptions):
    """Return the English CVE description when available."""
    for item in descriptions or []:
        if item.get("lang") == "en":
            return item.get("value", "No description available.")

    if descriptions:
        return descriptions[0].get("value", "No description available.")

    return "No description available."


def _get_weaknesses(weaknesses):
    """Extract CWE identifiers from NVD weakness data."""
    cwe_ids = []

    for weakness in weaknesses or []:
        for description in weakness.get("description", []):
            value = description.get("value", "")

            if value.startswith("CWE-"):
                cwe_ids.append(value)

    return ", ".join(sorted(set(cwe_ids))) or "Unknown"


def _get_affected_systems(configurations):
    """Extract vendor, product and version information."""
    affected = []

    def inspect_nodes(nodes):
        for node in nodes or []:
            for match in node.get("cpeMatch", []):
                if not match.get("vulnerable", False):
                    continue

                criteria = match.get("criteria", "")
                parts = criteria.split(":")

                if len(parts) >= 6:
                    vendor = parts[3]
                    product = parts[4]
                    version = parts[5]

                    affected.append({
                        "vendor": vendor,
                        "product": product,
                        "version": version,
                        "cpe": criteria,
                    })

            inspect_nodes(node.get("children", []))

    for configuration in configurations or []:
        inspect_nodes(configuration.get("nodes", []))

    # Remove duplicate affected-system entries.
    unique = {}
    for item in affected:
        unique[item["cpe"]] = item

    return list(unique.values())


def normalize_cve(item):
    """Convert an NVD API CVE item into a consistent Python dictionary."""
    cve = item.get("cve", item)
    metrics = cve.get("metrics", {})

    score, severity, cvss_version = _get_cvss(metrics)

    published = _parse_date(cve.get("published"))
    last_modified = _parse_date(cve.get("lastModified"))

    affected_systems = _get_affected_systems(
        cve.get("configurations", [])
    )

    return {
        "cve_id": cve.get("id", "UNKNOWN"),
        "description": _get_description(cve.get("descriptions", [])),
        "published": published.isoformat() if published else None,
        "last_modified": (
            last_modified.isoformat() if last_modified else None
        ),
        "cvss_score": score,
        "severity": severity,
        "cvss_version": cvss_version,
        "cwe": _get_weaknesses(cve.get("weaknesses", [])),
        "affected_systems": affected_systems,
        "vendor": ", ".join(sorted({
            system["vendor"] for system in affected_systems
        })) or "Unknown",
        "product": ", ".join(sorted({
            system["product"] for system in affected_systems
        })) or "Unknown",
        "source": "NVD",
        "known_exploited": False,
    }


def fetch_cves(
    days=30,
    limit=100,
    keyword=None,
    severity=None,
    api_key=None,
):
    """
    Fetch recent CVEs from NVD.

    Args:
        days: Number of days to search, maximum 120.
        limit: Maximum number of records to return.
        keyword: Optional keyword, e.g. Apache or WordPress.
        severity: Optional CRITICAL, HIGH, MEDIUM or LOW filter.
        api_key: Optional NVD API key.

    Returns:
        A list of normalized CVE dictionaries.
    """
    if not isinstance(days, int) or not 1 <= days <= 120:
        raise ValueError("days must be an integer between 1 and 120.")

    if not isinstance(limit, int) or limit < 1:
        raise ValueError("limit must be a positive integer.")

    if severity:
        severity = severity.strip().upper()
        allowed = {"CRITICAL", "HIGH", "MEDIUM", "LOW"}

        if severity not in allowed:
            raise ValueError(
                "severity must be CRITICAL, HIGH, MEDIUM or LOW."
            )

    now = datetime.now(timezone.utc)
    start_date = now - timedelta(days=days)

    params = {
        "pubStartDate": start_date.strftime("%Y-%m-%dT%H:%M:%S.000"),
        "pubEndDate": now.strftime("%Y-%m-%dT%H:%M:%S.000"),
        "resultsPerPage": min(limit, 2000),
        "startIndex": 0,
    }

    if keyword and keyword.strip():
        params["keywordSearch"] = keyword.strip()

    if severity:
        params["cvssV3Severity"] = severity

    headers = {
        "User-Agent": "CyberSecurity-ResearchAI/1.0"
    }

    if api_key:
        headers["apiKey"] = api_key

    results = []
    session = requests.Session()

    try:
        while len(results) < limit:
            params["resultsPerPage"] = min(2000, limit - len(results))

            response = session.get(
                NVD_API_URL,
                params=params,
                headers=headers,
                timeout=REQUEST_TIMEOUT,
            )

            response.raise_for_status()

            try:
                payload = response.json()
            except ValueError as exc:
                raise RuntimeError(
                    "NVD returned an invalid JSON response."
                ) from exc

            vulnerabilities = payload.get("vulnerabilities", [])

            if not vulnerabilities:
                break

            for item in vulnerabilities:
                results.append(normalize_cve(item))

                if len(results) >= limit:
                    break

            total_results = payload.get("totalResults", 0)
            params["startIndex"] += len(vulnerabilities)

            if params["startIndex"] >= total_results:
                break

    except requests.exceptions.Timeout as exc:
        raise RuntimeError(
            "NVD API request timed out. Please try again."
        ) from exc

    except requests.exceptions.HTTPError as exc:
        status = (
            exc.response.status_code
            if exc.response is not None
            else "unknown"
        )

        if status == 403:
            message = "NVD access was denied. Check your API key or retry later."
        elif status == 429:
            message = "NVD rate limit reached. Wait before retrying."
        else:
            message = f"NVD API returned HTTP error {status}."

        raise RuntimeError(message) from exc

    except requests.exceptions.RequestException as exc:
        raise RuntimeError(
            f"Could not connect to NVD: {exc}"
        ) from exc

    finally:
        session.close()

    return results


def search_cves(query, days=30, limit=100, api_key=None):
    """Search NVD using a keyword or product name."""
    if not query or not query.strip():
        raise ValueError("Please provide a search keyword.")

    return fetch_cves(
        days=days,
        limit=limit,
        keyword=query,
        api_key=api_key,
    )


def get_cve_by_id(cve_id, api_key=None):
    """Fetch one specific CVE using its CVE identifier."""
    if not cve_id or not cve_id.strip().upper().startswith("CVE-"):
        raise ValueError("Provide a valid CVE ID, e.g. CVE-2021-44228.")

    headers = {
        "User-Agent": "CyberSecurity-ResearchAI/1.0"
    }

    if api_key:
        headers["apiKey"] = api_key

    try:
        response = requests.get(
            NVD_API_URL,
            params={"cveId": cve_id.strip().upper()},
            headers=headers,
            timeout=REQUEST_TIMEOUT,
        )
        response.raise_for_status()
        payload = response.json()

    except requests.exceptions.RequestException as exc:
        raise RuntimeError(f"Could not fetch CVE details: {exc}") from exc

    except ValueError as exc:
        raise RuntimeError("NVD returned invalid JSON.") from exc

    vulnerabilities = payload.get("vulnerabilities", [])

    if not vulnerabilities:
        return None

    return normalize_cve(vulnerabilities[0])


if __name__ == "__main__":
    print("CyberSecurity-ResearchAI | NVD Data Collector")
    print("-" * 50)

    try:
        cves = fetch_cves(days=7, limit=10)

        print(f"Fetched {len(cves)} CVEs.\n")

        for cve in cves:
            print(
                f"{cve['cve_id']} | "
                f"{cve['severity']} | "
                f"CVSS: {cve['cvss_score']}"
            )
            print(cve["description"][:180])
            print("-" * 50)

    except (RuntimeError, ValueError) as error:
        print(f"Error: {error}")
