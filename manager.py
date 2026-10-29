
"""
CyberSecurity-ResearchAI
Research manager: fetch, analyze, enrich and save CVE records.
"""

from datetime import datetime, timezone

import data
import database
import cisa
import llm


def _now():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _get_cve_id(record):
    """Extract a CVE ID from common record formats."""
    if not isinstance(record, dict):
        return ""

    cve_id = (
        record.get("cve_id")
        or record.get("cveId")
        or record.get("id")
    )

    if not cve_id and isinstance(record.get("cve"), dict):
        cve_id = (
            record["cve"].get("id")
            or record["cve"].get("cveId")
        )

    return str(cve_id or "").strip().upper()


def _get_severity(record):
    """Normalize severity to CRITICAL, HIGH, MEDIUM, LOW or UNKNOWN."""
    severity = str(record.get("severity") or "").upper().strip()

    if severity in {"CRITICAL", "HIGH", "MEDIUM", "LOW"}:
        return severity

    score = record.get("cvss_score", record.get("cvss"))

    try:
        score = float(score)
    except (TypeError, ValueError):
        return "UNKNOWN"

    if score >= 9.0:
        return "CRITICAL"
    if score >= 7.0:
        return "HIGH"
    if score >= 4.0:
        return "MEDIUM"
    if score > 0:
        return "LOW"

    return "UNKNOWN"


def _get_kev_entry(cve_id):
    """Try common CISA module functions without assuming one API name."""
    possible_functions = (
        "get_kev_details",
        "get_cve_details",
        "lookup_cve",
        "get_cve",
        "is_known_exploited",
        "check_cve",
    )

    for function_name in possible_functions:
        function = getattr(cisa, function_name, None)

        if not callable(function):
            continue

        try:
            result = function(cve_id)

            if isinstance(result, dict):
                return result

            if isinstance(result, bool):
                return {"known_exploited": result}

        except Exception:
            # Continue to other supported lookup methods.
            continue

    return {}


def _apply_kev_data(record):
    """Add known-exploited information when CISA data is available."""
    enriched = dict(record)
    cve_id = _get_cve_id(enriched)

    if not cve_id:
        return enriched

    kev = _get_kev_entry(cve_id)

    known_exploited = (
        kev.get("known_exploited")
        if "known_exploited" in kev
        else kev.get("is_known_exploited")
    )

    if known_exploited is None:
        known_exploited = kev.get("knownExploited")

    if known_exploited is not None:
        if isinstance(known_exploited, str):
            known_exploited = known_exploited.strip().lower() in {
                "true", "yes", "1", "exploited"
            }

        enriched["known_exploited"] = bool(known_exploited)

    if kev.get("date_added"):
        enriched["kev_date_added"] = kev["date_added"]

    if kev.get("required_action"):
        enriched["kev_required_action"] = kev["required_action"]

    if kev.get("due_date"):
        enriched["kev_due_date"] = kev["due_date"]

    return enriched


def _analyze_one(record):
    """Analyze one CVE while retaining all original fields."""
    original = dict(record)
    cve_id = _get_cve_id(original)

    if cve_id:
        original["cve_id"] = cve_id

    analysis = {}

    try:
        # The project's llm.analyze_cve may accept a dict or CVE ID.
        analysis_function = getattr(llm, "analyze_cve", None)

        if callable(analysis_function):
            analysis = analysis_function(original)

        if not isinstance(analysis, dict):
            analysis = {}

    except Exception as exc:
        analysis = {
            "analysis_method": "Rule-based",
            "analysis_note": (
                "Analysis function failed; verify the CVE manually. "
                f"Details: {type(exc).__name__}"
            ),
        }

    # Preserve the original NVD record and add analysis fields.
    combined = dict(original)
    combined.update(analysis)

    # Keep identifiers and source data from the original record.
    combined["cve_id"] = cve_id or _get_cve_id(combined)
    combined.setdefault("description", original.get("description", ""))
    combined.setdefault("published", original.get("published"))
    combined.setdefault("last_modified", original.get("last_modified"))

    combined = _apply_kev_data(combined)

    # Normalize the display severity without overwriting the CVSS score.
    combined["severity"] = _get_severity(combined)

    score = combined.get("cvss_score", combined.get("cvss"))

    try:
        score = float(score) if score is not None else None
    except (TypeError, ValueError):
        score = None

    if score is not None:
        combined["cvss_score"] = score

    combined.setdefault("risk_score", score)
    combined.setdefault("analysis_method", "Rule-based")
    combined.setdefault("analysis_note", "")
    combined.setdefault("root_cause", "Not established; verify vendor advisory.")
    combined.setdefault(
        "attack_mechanism",
        "Review the source description and vendor advisory for attack details."
    )
    combined.setdefault(
        "impact_explanation",
        "Actual impact depends on the affected product, version and configuration."
    )
    combined.setdefault(
        "severity_reasoning",
        "Severity is based on the supplied CVE record; verify the official advisory."
    )
    combined.setdefault(
        "remediation_steps",
        "Verify affected versions and apply the vendor-recommended fix."
    )
    combined.setdefault("confidence", "Low")

    return combined


def _save_one(record):
    """Save a record using the available database save function."""
    possible_functions = (
        "save_vulnerability",
        "save_cve",
        "save_to_database",
    )

    for function_name in possible_functions:
        function = getattr(database, function_name, None)

        if callable(function):
            result = function(record)

            # These functions typically return True, None or an ID.
            return result

    raise AttributeError(
        "database.py must provide save_vulnerability(), "
        "save_cve() or save_to_database()."
    )


def _fetch_records(query, days, limit, api_key=None):
    """Fetch records through the project's data.py functions."""
    if query:
        search_function = getattr(data, "search_cves", None)

        if not callable(search_function):
            raise AttributeError(
                "data.py is missing the search_cves() function."
            )

        try:
            return search_function(
                query=query,
                days=days,
                limit=limit,
                api_key=api_key,
            )
        except TypeError:
            return search_function(
                query=query,
                days=days,
                limit=limit,
            )

    fetch_function = getattr(data, "fetch_cves", None)

    if not callable(fetch_function):
        raise AttributeError(
            "data.py is missing the fetch_cves() function."
        )

    try:
        return fetch_function(
            days=days,
            limit=limit,
            api_key=api_key,
        )
    except TypeError:
        return fetch_function(days=days, limit=limit)


def run_research(
    query="",
    days=30,
    limit=100,
    severity=None,
    save_to_database=True,
    api_key=None,
):
    """
    Run vulnerability research.

    Returns a dictionary containing:
    query, days, requested_limit, total_fetched, total_analyzed,
    saved_count, known_exploited_count, severity_distribution,
    vulnerabilities and errors.
    """
    query = (query or "").strip()
    days = int(days)
    limit = int(limit)

    if not 1 <= days <= 120:
        raise ValueError("days must be between 1 and 120.")

    if limit < 1:
        raise ValueError("limit must be at least 1.")

    result = {
        "query": query,
        "days": days,
        "requested_limit": limit,
        "total_fetched": 0,
        "total_analyzed": 0,
        "saved_count": 0,
        "known_exploited_count": 0,
        "severity_distribution": {},
        "vulnerabilities": [],
        "errors": [],
        "started_at": _now(),
    }

    # Step 1: Fetch from NVD.
    try:
        fetched = _fetch_records(
            query=query,
            days=days,
            limit=limit,
            api_key=api_key,
        )

        if isinstance(fetched, dict):
            fetched = (
                fetched.get("vulnerabilities")
                or fetched.get("results")
                or fetched.get("data")
                or []
            )

        if not isinstance(fetched, list):
            fetched = list(fetched or [])

        fetched = fetched[:limit]
        result["total_fetched"] = len(fetched)

    except Exception as exc:
        result["errors"].append({
            "stage": "fetch",
            "error": str(exc),
        })
        result["finished_at"] = _now()
        return result

    # Step 2: Analyze each record and optionally save it.
    analyzed_records = []

    for record in fetched:
        if not isinstance(record, dict):
            result["errors"].append({
                "stage": "analysis",
                "error": "Skipped a record that was not a dictionary.",
            })
            continue

        cve_id = _get_cve_id(record)

        try:
            analyzed = _analyze_one(record)

            if not analyzed.get("cve_id"):
                raise ValueError("Record has no CVE ID.")

            analyzed_records.append(analyzed)

            if save_to_database:
                try:
                    _save_one(analyzed)
                    result["saved_count"] += 1
                except Exception as exc:
                    result["errors"].append({
                        "stage": "database",
                        "cve_id": cve_id,
                        "error": str(exc),
                    })

        except Exception as exc:
            result["errors"].append({
                "stage": "analysis",
                "cve_id": cve_id,
                "error": str(exc),
            })

    # Apply severity filtering to the displayed results.
    if severity and str(severity).upper() != "ALL":
        requested_severity = str(severity).upper()
        analyzed_records = [
            record for record in analyzed_records
            if str(record.get("severity", "")).upper()
            == requested_severity
        ]

    result["vulnerabilities"] = analyzed_records
    result["total_analyzed"] = len(analyzed_records)
    result["known_exploited_count"] = sum(
        1 for record in analyzed_records
        if record.get("known_exploited") is True
        or str(record.get("known_exploited", "")).lower()
        in {"1", "true", "yes"}
    )

    severity_distribution = {}

    for record in analyzed_records:
        level = _get_severity(record)
        severity_distribution[level] = (
            severity_distribution.get(level, 0) + 1
        )

    result["severity_distribution"] = severity_distribution
    result["finished_at"] = _now()

    return result


def research_single_cve(cve_id, save_to_database=True, api_key=None):
    """Fetch and analyze one CVE by its identifier."""
    cve_id = (cve_id or "").strip().upper()

    if not cve_id:
        return {
            "success": False,
            "error": "Please provide a CVE ID.",
            "vulnerability": None,
        }

    get_function = getattr(data, "get_cve_by_id", None)

    if not callable(get_function):
        return {
            "success": False,
            "error": "data.py is missing get_cve_by_id().",
            "vulnerability": None,
        }

    try:
        try:
            record = get_function(cve_id, api_key=api_key)
        except TypeError:
            record = get_function(cve_id)

        if not record:
            return {
                "success": False,
                "error": f"No record found for {cve_id}.",
                "vulnerability": None,
            }

        # Some API helpers return a wrapper object.
        if isinstance(record, dict):
            record = (
                record.get("vulnerability")
                or record.get("data")
                or record
            )

        analyzed = _analyze_one(record)

        if save_to_database:
            try:
                _save_one(analyzed)
            except Exception as exc:
                return {
                    "success": True,
                    "vulnerability": analyzed,
                    "saved": False,
                    "warning": str(exc),
                }

        return {
            "success": True,
            "vulnerability": analyzed,
            "saved": bool(save_to_database),
        }

    except Exception as exc:
        return {
            "success": False,
            "error": str(exc),
            "vulnerability": None,
        }


def get_saved_research(limit=None):
    """Read saved CVEs from the database."""
    possible_functions = (
        "get_all_vulnerabilities",
        "get_saved_vulnerabilities",
    )

    for function_name in possible_functions:
        function = getattr(database, function_name, None)

        if callable(function):
            return function(limit=limit)

    raise AttributeError(
        "database.py must provide get_all_vulnerabilities() "
        "or get_saved_vulnerabilities()."
    )


def print_research_summary(result):
    """Print a compact research summary in the terminal."""
    print("\n=== CyberSecurity-ResearchAI Summary ===")
    print("Query:", result.get("query", ""))
    print("Fetched:", result.get("total_fetched", 0))
    print("Analyzed:", result.get("total_analyzed", 0))
    print("Saved:", result.get("saved_count", 0))
    print("Known exploited:", result.get("known_exploited_count", 0))
    print("Severity:", result.get("severity_distribution", {}))

    errors = result.get("errors", [])

    if errors:
        print("Warnings/errors:")
        for error in errors[:10]:
            print("-", error)

    print("========================================\n")


if __name__ == "__main__":
    print("Starting a small research test...")

    try:
        research_result = run_research(
            days=7,
            limit=5,
            save_to_database=False,
        )
        print_research_summary(research_result)

    except Exception as exc:
        print("Research test failed:", repr(exc))
