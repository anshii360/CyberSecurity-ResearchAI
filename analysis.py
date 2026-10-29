
import pandas as pd


# ---------------- DATA NORMALIZATION ----------------

def _get_dataframe(vulnerabilities):
    """
    Convert vulnerability data into a pandas DataFrame.

    Accepts:
    - List of dictionaries
    - Pandas DataFrame
    - A single vulnerability dictionary
    - None or empty input
    """

    if vulnerabilities is None:
        return pd.DataFrame()

    if isinstance(vulnerabilities, pd.DataFrame):
        return vulnerabilities.copy()

    if isinstance(vulnerabilities, dict):
        vulnerabilities = [vulnerabilities]

    if isinstance(vulnerabilities, list):
        records = []

        for item in vulnerabilities:
            if isinstance(item, dict):
                records.append(item)
            elif hasattr(item, "__dict__"):
                records.append(vars(item))

        return pd.DataFrame(records)

    return pd.DataFrame()


def _find_column(df, possible_names):
    """Find a column without depending on capitalization."""

    lookup = {str(col).lower(): col for col in df.columns}

    for name in possible_names:
        if name.lower() in lookup:
            return lookup[name.lower()]

    return None


def _numeric_scores(df):
    """Extract numeric CVSS scores when a score column exists."""

    score_column = _find_column(
        df,
        ["cvss_score", "baseScore", "score", "cvss"]
    )

    if score_column is None:
        return None, None

    scores = pd.to_numeric(df[score_column], errors="coerce")
    return score_column, scores


def _normalize_severity(value):
    """Normalize severity labels to a consistent format."""

    if value is None or pd.isna(value):
        return "UNKNOWN"

    value = str(value).strip().upper()

    allowed = {"CRITICAL", "HIGH", "MEDIUM", "LOW", "NONE"}

    if value in allowed:
        return value

    return "UNKNOWN"


# ---------------- SEVERITY ANALYSIS ----------------

def severity_distribution(vulnerabilities):
    """Count vulnerabilities by severity."""

    df = _get_dataframe(vulnerabilities)

    if df.empty:
        return {
            "CRITICAL": 0,
            "HIGH": 0,
            "MEDIUM": 0,
            "LOW": 0,
            "NONE": 0,
            "UNKNOWN": 0
        }

    severity_column = _find_column(
        df,
        ["severity", "baseSeverity", "cvss_severity"]
    )

    if severity_column is None:
        return {
            "CRITICAL": 0,
            "HIGH": 0,
            "MEDIUM": 0,
            "LOW": 0,
            "NONE": 0,
            "UNKNOWN": len(df)
        }

    severities = df[severity_column].apply(_normalize_severity)
    counts = severities.value_counts().to_dict()

    return {
        severity: int(counts.get(severity, 0))
        for severity in [
            "CRITICAL",
            "HIGH",
            "MEDIUM",
            "LOW",
            "NONE",
            "UNKNOWN"
        ]
    }


# ---------------- CVSS ANALYSIS ----------------

def average_cvss_score(vulnerabilities):
    """Calculate the average available CVSS score."""

    df = _get_dataframe(vulnerabilities)

    if df.empty:
        return None

    _, scores = _numeric_scores(df)

    if scores is None:
        return None

    valid_scores = scores.dropna()

    if valid_scores.empty:
        return None

    return round(float(valid_scores.mean()), 2)


def highest_cvss_score(vulnerabilities):
    """Return the highest available CVSS score."""

    df = _get_dataframe(vulnerabilities)

    if df.empty:
        return None

    _, scores = _numeric_scores(df)

    if scores is None:
        return None

    valid_scores = scores.dropna()

    if valid_scores.empty:
        return None

    return round(float(valid_scores.max()), 2)


def highest_risk_vulnerabilities(vulnerabilities, limit=10):
    """Return vulnerabilities with the highest numeric CVSS scores."""

    df = _get_dataframe(vulnerabilities)

    if df.empty or limit <= 0:
        return []

    score_column, scores = _numeric_scores(df)

    if scores is None:
        return []

    df[score_column] = scores
    df = df.dropna(subset=[score_column])

    if df.empty:
        return []

    df = df.sort_values(
        by=score_column,
        ascending=False
    ).head(limit)

    return df.to_dict(orient="records")


# ---------------- CISA KEV ANALYSIS ----------------

def _is_true(value):
    """Interpret common boolean representations safely."""

    if isinstance(value, bool):
        return value

    if isinstance(value, (int, float)):
        return value == 1

    if value is None:
        return False

    return str(value).strip().lower() in {
        "true", "1", "yes", "y"
    }


def known_exploited_vulnerabilities(vulnerabilities):
    """
    Return vulnerabilities marked as present in CISA KEV.

    The input must already contain a KEV field.
    This function does not query the CISA website.
    """

    df = _get_dataframe(vulnerabilities)

    if df.empty:
        return []

    kev_column = _find_column(
        df,
        [
            "known_exploited",
            "is_kev",
            "kev",
            "cisa_kev",
            "in_cisa_kev"
        ]
    )

    if kev_column is None:
        return []

    matches = df[df[kev_column].apply(_is_true)]

    return matches.to_dict(orient="records")


# ---------------- HIGH-RISK FILTER ----------------

def filter_high_risk(vulnerabilities):
    """Return vulnerabilities with HIGH or CRITICAL severity."""

    df = _get_dataframe(vulnerabilities)

    if df.empty:
        return []

    severity_column = _find_column(
        df,
        ["severity", "baseSeverity", "cvss_severity"]
    )

    if severity_column is not None:
        severities = df[severity_column].apply(_normalize_severity)

        return df[
            severities.isin(["HIGH", "CRITICAL"])
        ].to_dict(orient="records")

    score_column, scores = _numeric_scores(df)

    if score_column is None:
        return []

    df[score_column] = scores

    return df[
        df[score_column] >= 7.0
    ].to_dict(orient="records")


# ---------------- FULL ANALYTICS SUMMARY ----------------

def generate_analytics(vulnerabilities):
    """Generate a complete analytics summary."""

    df = _get_dataframe(vulnerabilities)

    if df.empty:
        return {
            "total_vulnerabilities": 0,
            "severity_distribution": severity_distribution([]),
            "average_cvss_score": None,
            "highest_cvss_score": None,
            "high_risk_count": 0,
            "known_exploited_count": 0,
            "top_risk_vulnerabilities": []
        }

    return {
        "total_vulnerabilities": len(df),
        "severity_distribution": severity_distribution(df),
        "average_cvss_score": average_cvss_score(df),
        "highest_cvss_score": highest_cvss_score(df),
        "high_risk_count": len(filter_high_risk(df)),
        "known_exploited_count": len(
            known_exploited_vulnerabilities(df)
        ),
        "top_risk_vulnerabilities": highest_risk_vulnerabilities(
            df,
            limit=10
        )
    }


# ---------------- CONSOLE REPORT ----------------

def print_analytics(vulnerabilities):
    """Print an analytics summary in the terminal."""

    summary = generate_analytics(vulnerabilities)

    print("\n" + "=" * 48)
    print("       CYBERSECURITY RESEARCH ANALYTICS")
    print("=" * 48)

    print(
        f"Total vulnerabilities : "
        f"{summary['total_vulnerabilities']}"
    )

    print("\nSeverity Distribution:")

    for severity, count in summary["severity_distribution"].items():
        print(f"  {severity:<10}: {count}")

    average = summary["average_cvss_score"]
    highest = summary["highest_cvss_score"]

    print(
        "\nAverage CVSS Score   : "
        + (str(average) if average is not None else "N/A")
    )

    print(
        "Highest CVSS Score   : "
        + (str(highest) if highest is not None else "N/A")
    )

    print(f"High-risk CVEs       : {summary['high_risk_count']}")
    print(f"CISA KEV matches     : {summary['known_exploited_count']}")

    print("\nTop Risk Vulnerabilities:")

    top_vulnerabilities = summary["top_risk_vulnerabilities"]

    if not top_vulnerabilities:
        print("  No scored vulnerabilities available.")
    else:
        for item in top_vulnerabilities:
            cve_id = (
                item.get("cve_id")
                or item.get("cveId")
                or item.get("id")
                or "Unknown CVE"
            )

            score_column = _find_column(
                pd.DataFrame([item]),
                ["cvss_score", "baseScore", "score", "cvss"]
            )

            score = item.get(score_column) if score_column else "N/A"

            print(f"  {cve_id} | CVSS: {score}")

    print("=" * 48 + "\n")


# ---------------- OPTIONAL CLI TEST ----------------

if __name__ == "__main__":
    sample_data = [
        {
            "cve_id": "CVE-2024-0001",
            "severity": "CRITICAL",
            "cvss_score": 9.8,
            "known_exploited": True
        },
        {
            "cve_id": "CVE-2024-0002",
            "severity": "HIGH",
            "cvss_score": 7.5,
            "known_exploited": False
        },
        {
            "cve_id": "CVE-2024-0003",
            "severity": "MEDIUM",
            "cvss_score": 5.4,
            "known_exploited": False
        }
    ]

    print_analytics(sample_data)
