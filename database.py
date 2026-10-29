
"""
CyberSecurity-ResearchAI
Database management with automatic SQLite schema migration.
Preserves existing saved CVE records.
"""

import json
import sqlite3
from pathlib import Path
from datetime import datetime, timezone


BASE_DIR = Path(__file__).resolve().parent
DB_PATH = BASE_DIR / "cve_database.db"


# --------------------------------------------------
# CONNECTION
# --------------------------------------------------

def get_connection():
    conn = sqlite3.connect(str(DB_PATH), timeout=30)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA busy_timeout = 30000")
    return conn


def _now():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


# --------------------------------------------------
# COMPLETE SCHEMA
# --------------------------------------------------

COLUMN_DEFINITIONS = {
    "cve_id": "TEXT",
    "description": "TEXT",
    "cvss": "REAL",
    "cvss_score": "REAL",
    "cvss_version": "TEXT",
    "severity": "TEXT",
    "published": "TEXT",
    "published_date": "TEXT",
    "source_url": "TEXT",
    "source": "TEXT",
    "known_exploited": "INTEGER DEFAULT 0",
    "cisa_vendor": "TEXT",
    "cisa_product": "TEXT",
    "cisa_due_date": "TEXT",
    "vendor": "TEXT",
    "product": "TEXT",
    "affected_system": "TEXT",
    "affected_systems": "TEXT",
    "attack_type": "TEXT",
    "authentication": "TEXT",
    "impact": "TEXT",
    "root_cause": "TEXT",
    "attack_mechanism": "TEXT",
    "impact_explanation": "TEXT",
    "severity_reasoning": "TEXT",
    "recommendation": "TEXT",
    "remediation_steps": "TEXT",
    "risk_score": "REAL",
    "analysis_method": "TEXT",
    "analysis_note": "TEXT",
    "confidence": "TEXT",
    "last_modified": "TEXT",
    "last_modified_date": "TEXT",
    "references": "TEXT",
    "raw_json": "TEXT",
    "created_at": "TEXT",
    "updated_at": "TEXT",
}


def init_db():
    """Create the table and safely add missing columns."""
    with get_connection() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS vulnerabilities (
                cve_id TEXT PRIMARY KEY,
                description TEXT,
                severity TEXT,
                cvss_score REAL,
                published TEXT,
                last_modified TEXT,
                created_at TEXT,
                updated_at TEXT
            )
        """)

        existing = {
            row["name"]
            for row in conn.execute(
                "PRAGMA table_info(vulnerabilities)"
            ).fetchall()
        }

        for name, sql_type in COLUMN_DEFINITIONS.items():
            if name not in existing:
                conn.execute(
                    f'ALTER TABLE vulnerabilities ADD COLUMN "{name}" {sql_type}'
                )

        conn.execute("""
            CREATE INDEX IF NOT EXISTS idx_vulnerabilities_severity
            ON vulnerabilities(severity)
        """)
        conn.execute("""
            CREATE INDEX IF NOT EXISTS idx_vulnerabilities_cvss
            ON vulnerabilities(cvss_score)
        """)
        conn.execute("""
            CREATE INDEX IF NOT EXISTS idx_vulnerabilities_modified
            ON vulnerabilities(last_modified)
        """)


# --------------------------------------------------
# NORMALIZATION HELPERS
# --------------------------------------------------

def _first(record, *keys, default=None):
    for key in keys:
        value = record.get(key)
        if value is not None and value != "":
            return value
    return default


def _json_value(value):
    if value is None:
        return None
    if isinstance(value, (dict, list, tuple, set)):
        return json.dumps(value, ensure_ascii=False, default=str)
    return value


def _as_bool_int(value):
    if isinstance(value, str):
        return int(value.strip().lower() in {
            "true", "yes", "1", "known exploited"
        })
    return int(bool(value))


def _normalize_record(record):
    if not isinstance(record, dict):
        raise TypeError("CVE record must be a dictionary")

    cve_id = str(
        _first(record, "cve_id", "cveId", "id", default="")
    ).strip().upper()

    if not cve_id:
        raise ValueError("CVE record is missing its CVE ID")

    now = _now()
    affected = _first(
        record, "affected_systems", "affected_system",
        "affected_products", default=None
    )

    refs = _first(record, "references", "reference_urls", default=None)

    values = {
        "cve_id": cve_id,
        "description": _first(record, "description", "details"),
        "cvss": _first(record, "cvss", "cvss_score", "score"),
        "cvss_score": _first(record, "cvss_score", "cvss", "score"),
        "cvss_version": _first(record, "cvss_version", "cvssVersion"),
        "severity": _first(record, "severity", default="UNKNOWN"),
        "published": _first(record, "published", "published_date"),
        "published_date": _first(record, "published_date", "published"),
        "source_url": _first(record, "source_url", "url"),
        "source": _first(record, "source", default="NVD"),
        "known_exploited": _as_bool_int(
            _first(record, "known_exploited", default=False)
        ),
        "cisa_vendor": _first(record, "cisa_vendor"),
        "cisa_product": _first(record, "cisa_product"),
        "cisa_due_date": _first(record, "cisa_due_date"),
        "vendor": _first(record, "vendor"),
        "product": _first(record, "product"),
        "affected_system": _first(
            record, "affected_system", default=affected
        ),
        "affected_systems": affected,
        "attack_type": _first(record, "attack_type"),
        "authentication": _first(record, "authentication"),
        "impact": _first(record, "impact"),
        "root_cause": _first(record, "root_cause"),
        "attack_mechanism": _first(record, "attack_mechanism"),
        "impact_explanation": _first(record, "impact_explanation"),
        "severity_reasoning": _first(record, "severity_reasoning"),
        "recommendation": _first(record, "recommendation"),
        "remediation_steps": _first(record, "remediation_steps"),
        "risk_score": _first(record, "risk_score"),
        "analysis_method": _first(record, "analysis_method"),
        "analysis_note": _first(record, "analysis_note"),
        "confidence": _first(record, "confidence"),
        "last_modified": _first(
            record, "last_modified", "last_modified_date",
            "lastModified", "lastModifiedDate"
        ),
        "last_modified_date": _first(
            record, "last_modified_date", "last_modified",
            "lastModifiedDate", "lastModified"
        ),
        "references": refs,
        "raw_json": json.dumps(
            record, ensure_ascii=False, default=str
        ),
        "created_at": _first(record, "created_at", default=now),
        "updated_at": now,
    }

    return {
        key: _json_value(value)
        for key, value in values.items()
    }


# --------------------------------------------------
# SAVE RECORDS
# --------------------------------------------------

def save_vulnerability(record):
    """Insert a CVE or update the existing record with the same ID."""
    init_db()
    values = _normalize_record(record)

    columns = list(values.keys())
    column_sql = ", ".join(f'"{c}"' for c in columns)
    placeholders = ", ".join("?" for _ in columns)

    updates = ", ".join(
        f'"{c}" = excluded."{c}"'
        for c in columns
        if c not in {"cve_id", "created_at"}
    )

    sql = f"""
        INSERT INTO vulnerabilities ({column_sql})
        VALUES ({placeholders})
        ON CONFLICT(cve_id) DO UPDATE SET {updates}
    """

    with get_connection() as conn:
        conn.execute(sql, [values[c] for c in columns])

    return True


def save_cve(record):
    return save_vulnerability(record)


def save_to_database(record):
    return save_vulnerability(record)


def save_vulnerabilities(records):
    count = 0
    for record in records:
        save_vulnerability(record)
        count += 1
    return count


# --------------------------------------------------
# READ AND SEARCH
# --------------------------------------------------

def get_all_vulnerabilities(limit=None):
    init_db()

    sql = """
        SELECT * FROM vulnerabilities
        ORDER BY updated_at DESC, cve_id ASC
    """
    params = ()

    if limit is not None:
        sql += " LIMIT ?"
        params = (max(1, int(limit)),)

    with get_connection() as conn:
        rows = conn.execute(sql, params).fetchall()

    return [dict(row) for row in rows]


def get_saved_vulnerabilities(limit=None):
    return get_all_vulnerabilities(limit)


def get_saved_cves(limit=None):
    return get_all_vulnerabilities(limit)


def get_vulnerability(cve_id):
    init_db()

    with get_connection() as conn:
        row = conn.execute(
            """
            SELECT * FROM vulnerabilities
            WHERE UPPER(cve_id) = ?
            LIMIT 1
            """,
            (str(cve_id).strip().upper(),),
        ).fetchone()

    return dict(row) if row else None


def get_cve_by_id(cve_id):
    return get_vulnerability(cve_id)


def search_vulnerabilities(query="", severity=None, limit=500):
    init_db()

    sql = "SELECT * FROM vulnerabilities WHERE 1=1"
    params = []

    query = str(query or "").strip()
    if query:
        sql += " AND (cve_id LIKE ? OR description LIKE ?)"
        params.extend([f"%{query}%", f"%{query}%"])

    if severity and str(severity).upper() not in {"ALL", "ANY"}:
        sql += " AND UPPER(severity) = ?"
        params.append(str(severity).upper())

    sql += " ORDER BY updated_at DESC, cve_id ASC LIMIT ?"
    params.append(max(1, int(limit)))

    with get_connection() as conn:
        rows = conn.execute(sql, params).fetchall()

    return [dict(row) for row in rows]


def search_cves(query="", severity=None, limit=500):
    return search_vulnerabilities(query, severity, limit)


# --------------------------------------------------
# STATISTICS
# --------------------------------------------------

def get_stats():
    init_db()

    with get_connection() as conn:
        total = conn.execute(
            "SELECT COUNT(*) FROM vulnerabilities"
        ).fetchone()[0]

        exploited = conn.execute("""
            SELECT COUNT(*) FROM vulnerabilities
            WHERE known_exploited = 1
        """).fetchone()[0]

        severity_rows = conn.execute("""
            SELECT UPPER(COALESCE(severity, 'UNKNOWN')) AS severity,
                   COUNT(*) AS total
            FROM vulnerabilities
            GROUP BY UPPER(COALESCE(severity, 'UNKNOWN'))
        """).fetchall()

    distribution = {
        row["severity"]: row["total"] for row in severity_rows
    }

    return {
        "total": total,
        "total_vulnerabilities": total,
        "known_exploited": exploited,
        "severity_distribution": distribution,
    }


def get_database_stats():
    return get_stats()


# --------------------------------------------------
# DELETE
# --------------------------------------------------

def delete_vulnerability(cve_id):
    init_db()

    with get_connection() as conn:
        cursor = conn.execute(
            "DELETE FROM vulnerabilities WHERE UPPER(cve_id) = ?",
            (str(cve_id).strip().upper(),),
        )

    return cursor.rowcount > 0


def clear_database():
    """Explicitly delete all saved records. Not called automatically."""
    init_db()
    with get_connection() as conn:
        conn.execute("DELETE FROM vulnerabilities")


# --------------------------------------------------
# STARTUP / MIGRATION
# --------------------------------------------------

if __name__ == "__main__":
    init_db()
    print("Database initialized and schema checked.")
    print(f"Database path: {DB_PATH}")
    print(f"Statistics: {get_stats()}")
