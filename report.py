
"""
report.py
Generate console, CSV, and JSON reports for CVE research.
"""

import csv
import json
from datetime import datetime
from pathlib import Path


BASE_DIR = Path(__file__).resolve().parent
REPORTS_DIR = BASE_DIR / "reports"


def _get_value(record, *keys, default="N/A"):
    """Return the first non-empty value for the given keys."""
    for key in keys:
        value = record.get(key)

        if value is not None and value != "":
            return value

    return default


def _format_bool(value):
    """Convert common boolean values into readable text."""
    if isinstance(value, str):
        return "Yes" if value.strip().lower() in {
            "true", "yes", "1", "known", "exploited"
        } else "No"

    return "Yes" if value else "No"


def _prepare_record(cve):
    """Convert a CVE dictionary into report-friendly fields."""
    affected = _get_value(
        cve, "affected_system", "affected_systems",
        "product", default="Unknown"
    )

    if isinstance(affected, (dict, list)):
        affected = json.dumps(affected, ensure_ascii=False)

    return {
        "CVE ID": _get_value(cve, "cve_id", "id"),
        "Severity": str(_get_value(cve, "severity", default="UNKNOWN")).upper(),
        "CVSS Score": _get_value(cve, "cvss_score", "baseScore"),
        "Attack Type": _get_value(cve, "attack_type"),
        "Known Exploited (CISA KEV)": _format_bool(
            cve.get("known_exploited", False)
        ),
        "KEV Check Status": _get_value(
            cve, "kev_check_status", default="Unknown"
        ),
        "Vendor": _get_value(cve, "vendor"),
        "Product": _get_value(cve, "product"),
        "Affected System": affected,
        "Published": _get_value(cve, "published"),
        "Description": _get_value(cve, "description"),
        "Authentication": _get_value(cve, "authentication"),
        "Impact": _get_value(cve, "impact"),
        "Risk Score": _get_value(cve, "risk_score"),
        "Recommendation": _get_value(cve, "recommendation"),
        "Analysis Method": _get_value(
            cve, "analysis_method", default="Not specified"
        ),
    }


def _normalize_records(vulnerabilities):
    """Validate and prepare a list of CVE records."""
    if vulnerabilities is None:
        return []

    if isinstance(vulnerabilities, dict):
        vulnerabilities = [vulnerabilities]

    if not isinstance(vulnerabilities, (list, tuple)):
        raise TypeError("vulnerabilities must be a list of dictionaries.")

    return [
        _prepare_record(item)
        for item in vulnerabilities
        if isinstance(item, dict)
    ]


def generate_report(vulnerabilities, title="CyberSecurity Research Report"):
    """Print a readable summary of vulnerability findings."""
    records = _normalize_records(vulnerabilities)

    severity_counts = {}
    for record in records:
        severity = record["Severity"]
        severity_counts[severity] = severity_counts.get(severity, 0) + 1

    kev_count = sum(
        record["Known Exploited (CISA KEV)"] == "Yes"
        for record in records
    )

    print("\n" + "=" * 65)
    print(title)
    print("=" * 65)
    print(f"Generated: {datetime.now().astimezone().isoformat(timespec='seconds')}")
    print(f"Total vulnerabilities: {len(records)}")
    print(f"Known exploited according to supplied KEV flag: {kev_count}")

    print("\nSeverity distribution:")
    if severity_counts:
        for severity, count in sorted(severity_counts.items()):
            print(f"  {severity}: {count}")
    else:
        print("  No vulnerability records found.")

    for record in records:
        print("\n" + "-" * 65)
        print(f"CVE: {record['CVE ID']}")
        print(f"Severity: {record['Severity']}")
        print(f"CVSS Score: {record['CVSS Score']}")
        print(f"Attack Type: {record['Attack Type']}")
        print(f"Known Exploited: {record['Known Exploited (CISA KEV)']}")
        print(f"KEV Check Status: {record['KEV Check Status']}")
        print(f"Affected System: {record['Affected System']}")
        print(f"Published: {record['Published']}")
        print(f"Description: {record['Description']}")
        print(f"Impact: {record['Impact']}")
        print(f"Recommendation: {record['Recommendation']}")

    print("\n" + "=" * 65)

    return {
        "title": title,
        "generated_at": datetime.now().astimezone().isoformat(),
        "total_vulnerabilities": len(records),
        "known_exploited_count": kev_count,
        "severity_distribution": severity_counts,
        "vulnerabilities": records,
    }


def export_csv(vulnerabilities, filename=None):
    """Export vulnerability records to a CSV file."""
    records = _normalize_records(vulnerabilities)
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)

    if filename is None:
        filename = (
            "cve_report_"
            + datetime.now().strftime("%Y%m%d_%H%M%S")
            + ".csv"
        )

    path = Path(filename)
    if not path.is_absolute():
        path = REPORTS_DIR / path

    path.parent.mkdir(parents=True, exist_ok=True)

    fieldnames = list(records[0].keys()) if records else [
        "CVE ID",
        "Severity",
        "CVSS Score",
        "Attack Type",
        "Known Exploited (CISA KEV)",
        "KEV Check Status",
        "Vendor",
        "Product",
        "Affected System",
        "Published",
        "Description",
        "Authentication",
        "Impact",
        "Risk Score",
        "Recommendation",
        "Analysis Method",
    ]

    with path.open("w", newline="", encoding="utf-8-sig") as file:
        writer = csv.DictWriter(file, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(records)

    print(f"CSV report saved: {path}")
    return str(path)


def export_json(vulnerabilities, filename=None):
    """Export vulnerability records to a JSON file."""
    records = _normalize_records(vulnerabilities)
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)

    if filename is None:
        filename = (
            "cve_report_"
            + datetime.now().strftime("%Y%m%d_%H%M%S")
            + ".json"
        )

    path = Path(filename)
    if not path.is_absolute():
        path = REPORTS_DIR / path

    path.parent.mkdir(parents=True, exist_ok=True)

    payload = {
        "report_title": "CyberSecurity Research Report",
        "generated_at": datetime.now().astimezone().isoformat(),
        "total_vulnerabilities": len(records),
        "vulnerabilities": records,
    }

    with path.open("w", encoding="utf-8") as file:
        json.dump(payload, file, indent=4, ensure_ascii=False, default=str)

    print(f"JSON report saved: {path}")
    return str(path)


def generate_all_reports(vulnerabilities):
    """Print findings and export both CSV and JSON reports."""
    summary = generate_report(vulnerabilities)
    csv_path = export_csv(vulnerabilities)
    json_path = export_json(vulnerabilities)

    return {
        "summary": summary,
        "csv_path": csv_path,
        "json_path": json_path,
    }


if __name__ == "__main__":
    sample_data = [
        {
            "cve_id": "CVE-2021-44228",
            "description": "Example Log4j remote code execution vulnerability.",
            "published": "2021-12-10",
            "cvss_score": 10.0,
            "severity": "CRITICAL",
            "vendor": "apache",
            "product": "log4j",
            "attack_type": "Remote Code Execution",
            "known_exploited": True,
            "kev_check_status": "checked",
            "authentication": "May not require authentication",
            "impact": "Potential code execution",
            "recommendation": "Upgrade to a vendor-fixed version.",
            "analysis_method": "Local rule-based analysis",
        }
    ]

    generate_all_reports(sample_data)
