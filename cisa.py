
"""
CyberSecurity-ResearchAI
CISA Known Exploited Vulnerabilities (KEV) Integration

Fetches the official CISA KEV catalog and checks whether CVEs
are listed as known exploited vulnerabilities.
"""

import requests
from datetime import datetime, timezone


# ---------------- CONFIGURATION ----------------

CISA_KEV_URL = (
    "https://www.cisa.gov/sites/default/files/feeds/"
    "known_exploited_vulnerabilities.json"
)

REQUEST_TIMEOUT = 20

# In-memory cache to avoid repeatedly downloading the same catalog.
_kev_cache = None
_kev_cache_time = None


# ---------------- FETCH CISA CATALOG ----------------

def fetch_kev_catalog(force_refresh=False):
    """
    Fetch the official CISA KEV catalog.

    Args:
        force_refresh: Download a fresh copy even if cached data exists.

    Returns:
        Dictionary containing the catalog metadata and vulnerabilities.

    Raises:
        RuntimeError: If the catalog cannot be fetched or validated.
    """

    global _kev_cache, _kev_cache_time

    if _kev_cache is not None and not force_refresh:
        return _kev_cache

    try:
        response = requests.get(
            CISA_KEV_URL,
            timeout=REQUEST_TIMEOUT,
            headers={
                "Accept": "application/json",
                "User-Agent": "CyberSecurity-ResearchAI/1.0"
            }
        )

        response.raise_for_status()

        try:
            data = response.json()
        except ValueError as error:
            raise RuntimeError(
                "CISA returned invalid JSON. Please try again later."
            ) from error

        if not isinstance(data, dict):
            raise RuntimeError(
                "Unexpected CISA response: expected a JSON object."
            )

        vulnerabilities = data.get("vulnerabilities")

        if not isinstance(vulnerabilities, list):
            raise RuntimeError(
                "CISA response does not contain a valid vulnerabilities list."
            )

        # Validate the essential structure before caching.
        for item in vulnerabilities:
            if not isinstance(item, dict) or not item.get("cveID"):
                raise RuntimeError(
                    "CISA catalog contains an invalid vulnerability entry."
                )

        _kev_cache = data
        _kev_cache_time = datetime.now(timezone.utc).isoformat()

        return _kev_cache

    except requests.exceptions.Timeout as error:
        raise RuntimeError(
            "Connection to CISA timed out. Check your internet connection "
            "and try again."
        ) from error

    except requests.exceptions.ConnectionError as error:
        raise RuntimeError(
            "Could not connect to CISA. Check your internet connection."
        ) from error

    except requests.exceptions.HTTPError as error:
        status_code = (
            error.response.status_code
            if error.response is not None
            else "unknown"
        )

        raise RuntimeError(
            f"CISA returned HTTP status {status_code}."
        ) from error

    except requests.exceptions.RequestException as error:
        raise RuntimeError(
            f"Unable to retrieve the CISA KEV catalog: {error}"
        ) from error


# ---------------- GET CATALOG ENTRIES ----------------

def get_kev_vulnerabilities(force_refresh=False):
    """
    Return the catalog's vulnerability entries as a list.
    """

    catalog = fetch_kev_catalog(force_refresh=force_refresh)
    return catalog["vulnerabilities"]


def get_kev_index(force_refresh=False):
    """
    Return a dictionary indexed by uppercase CVE ID.

    Example:
        {
            "CVE-2021-40539": {
                "cveID": "CVE-2021-40539",
                ...
            }
        }
    """

    vulnerabilities = get_kev_vulnerabilities(
        force_refresh=force_refresh
    )

    index = {}

    for item in vulnerabilities:
        cve_id = str(item.get("cveID", "")).strip().upper()

        if cve_id:
            index[cve_id] = item

    return index


# ---------------- FIND A CVE ----------------

def find_cve(cve_id, force_refresh=False):
    """
    Find a CVE in the official CISA KEV catalog.

    Args:
        cve_id: CVE identifier, such as CVE-2021-40539.
        force_refresh: Refresh the catalog before searching.

    Returns:
        Matching catalog entry dictionary if found; otherwise None.

    Raises:
        RuntimeError: If the catalog cannot be retrieved.
    """

    if not cve_id or not isinstance(cve_id, str):
        return None

    normalized_id = cve_id.strip().upper()

    if not normalized_id.startswith("CVE-"):
        return None

    index = get_kev_index(force_refresh=force_refresh)

    return index.get(normalized_id)


# ---------------- EXPLOITATION STATUS ----------------

def is_known_exploited(cve_id, force_refresh=False):
    """
    Return True if the CVE is listed in CISA KEV.

    Return False if it is not listed.

    A catalog retrieval error raises RuntimeError rather than silently
    claiming the vulnerability is not exploited.
    """

    return find_cve(
        cve_id,
        force_refresh=force_refresh
    ) is not None


# ---------------- GET CVE DETAILS ----------------

def get_cve_details(cve_id, force_refresh=False):
    """
    Return normalized details for a CVE in the KEV catalog.

    Returns None when the CVE is not listed.
    """

    entry = find_cve(
        cve_id,
        force_refresh=force_refresh
    )

    if entry is None:
        return None

    return {
        "cve_id": entry.get("cveID"),
        "known_exploited": True,
        "vendor_project": entry.get("vendorProject"),
        "product": entry.get("product"),
        "vulnerability_name": entry.get("vulnerabilityName"),
        "date_added": entry.get("dateAdded"),
        "short_description": entry.get("shortDescription"),
        "required_action": entry.get("requiredAction"),
        "due_date": entry.get("dueDate"),
        "known_ransomware_campaign_use": entry.get(
            "knownRansomwareCampaignUse"
        ),
        "notes": entry.get("notes"),
        "cwes": entry.get("cwes", [])
    }


# ---------------- CHECK MANY CVEs ----------------

def check_cves(cve_ids, force_refresh=False):
    """
    Check multiple CVE IDs against one downloaded catalog.

    Returns:
        List of dictionaries containing each CVE's KEV status.
    """

    if not isinstance(cve_ids, (list, tuple, set)):
        raise TypeError("cve_ids must be a list, tuple, or set.")

    index = get_kev_index(force_refresh=force_refresh)
    results = []

    for raw_id in cve_ids:
        if not isinstance(raw_id, str) or not raw_id.strip():
            results.append({
                "cve_id": raw_id,
                "known_exploited": False,
                "details": None
            })
            continue

        normalized_id = raw_id.strip().upper()
        entry = index.get(normalized_id)

        results.append({
            "cve_id": normalized_id,
            "known_exploited": entry is not None,
            "details": entry
        })

    return results


# ---------------- CATALOG INFORMATION ----------------

def get_catalog_summary(force_refresh=False):
    """
    Return basic metadata about the downloaded CISA KEV catalog.
    """

    catalog = fetch_kev_catalog(force_refresh=force_refresh)
    vulnerabilities = catalog["vulnerabilities"]

    return {
        "title": catalog.get("title"),
        "catalog_version": catalog.get("catalogVersion"),
        "date_released": catalog.get("dateReleased"),
        "total_vulnerabilities": len(vulnerabilities),
        "retrieved_at": _kev_cache_time,
        "source": CISA_KEV_URL
    }


# ---------------- CACHE MANAGEMENT ----------------

def clear_cache():
    """Clear the locally cached CISA catalog."""

    global _kev_cache, _kev_cache_time

    _kev_cache = None
    _kev_cache_time = None


# ---------------- QUICK TEST ----------------

if __name__ == "__main__":
    print("\n" + "=" * 55)
    print("       CISA KNOWN EXPLOITED VULNERABILITIES")
    print("=" * 55)

    try:
        summary = get_catalog_summary()

        print(f"Catalog title   : {summary['title']}")
        print(f"Catalog version : {summary['catalog_version']}")
        print(f"Release date    : {summary['date_released']}")
        print(f"Total CVEs      : {summary['total_vulnerabilities']}")

        test_cve = "CVE-2021-40539"

        print(f"\nChecking {test_cve}...")

        details = get_cve_details(test_cve)

        if details:
            print("KEV status      : YES")
            print(f"Vendor          : {details['vendor_project']}")
            print(f"Product         : {details['product']}")
            print(f"Date added      : {details['date_added']}")
            print(f"Required action : {details['required_action']}")
        else:
            print("KEV status      : NOT LISTED")

        print("\nCISA catalog check completed.")

    except RuntimeError as error:
        print(f"\nCISA catalog error: {error}")
        print("Check your internet connection and try again.")

    print("=" * 55)
