
"""
CyberSecurity-ResearchAI
Streamlit dashboard for CVE research, AI explanations and remediation.
"""

import json
import threading
import queue
import time
import traceback
from datetime import datetime

import pandas as pd
import plotly.express as px
import streamlit as st

try:
    from manager import run_research
    BACKEND_AVAILABLE = True
    BACKEND_ERROR = None
except Exception as exc:
    run_research = None
    BACKEND_AVAILABLE = False
    BACKEND_ERROR = f"{type(exc).__name__}: {exc}"


# --------------------------------------------------
# PAGE CONFIGURATION
# --------------------------------------------------

st.set_page_config(
    page_title="CyberSecurity ResearchAI",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)


# --------------------------------------------------
# CUSTOM STYLING — PRESERVED
# --------------------------------------------------

st.markdown(
    """
    <style>
    .stApp {
        background-color: #0b1020;
        color: #e8edf7;
    }

    [data-testid="stSidebar"] {
        background-color: #11182a;
    }

    [data-testid="stMetric"] {
        background-color: #151e33;
        border: 1px solid #263653;
        padding: 16px;
        border-radius: 12px;
    }

    .hero {
        padding: 26px;
        border-radius: 16px;
        background: linear-gradient(120deg, #16284b, #111827);
        border: 1px solid #2a416b;
        margin-bottom: 20px;
    }

    .hero h1 {
        margin: 0;
        color: #f2f6ff;
        font-size: 32px;
    }

    .hero p {
        color: #b8c7e5;
        margin-top: 10px;
        margin-bottom: 0;
    }

    .section-card {
        background-color: #121b2e;
        border: 1px solid #263653;
        padding: 18px;
        border-radius: 12px;
        margin-bottom: 12px;
    }

    .muted {
        color: #a9b8d1;
        font-size: 13px;
    }

    div[data-testid="stExpander"] {
        border: 1px solid #263653;
        border-radius: 10px;
    }
    </style>
    """,
    unsafe_allow_html=True,
)


# --------------------------------------------------
# HELPER FUNCTIONS
# --------------------------------------------------

def safe_text(value, default="Not available"):
    if value is None:
        return default

    if isinstance(value, str):
        return value.strip() or default

    if isinstance(value, (list, tuple, set)):
        return ", ".join(str(item) for item in value) or default

    return str(value)


def get_score(record):
    value = record.get(
        "cvss_score",
        record.get("cvss", record.get("score", 0)),
    )

    try:
        return float(value or 0)
    except (ValueError, TypeError):
        return 0.0


def get_severity(record):
    severity = str(record.get("severity", "")).upper().strip()

    if severity in {"CRITICAL", "HIGH", "MEDIUM", "LOW", "NONE"}:
        return severity

    score = get_score(record)

    if score >= 9:
        return "CRITICAL"
    if score >= 7:
        return "HIGH"
    if score >= 4:
        return "MEDIUM"
    if score > 0:
        return "LOW"

    return "UNKNOWN"


def get_cve_id(record):
    return safe_text(
        record.get("cve_id", record.get("cveId", record.get("id"))),
        "Unknown CVE",
    )


def is_known_exploited(record):
    value = record.get(
        "known_exploited",
        record.get("is_known_exploited", False),
    )

    if isinstance(value, str):
        return value.strip().lower() in {
            "true", "yes", "1", "known exploited"
        }

    return bool(value)


def get_analysis_method(record):
    return safe_text(record.get("analysis_method"), "Unknown")


def extract_records(result):
    if isinstance(result, list):
        raw_records = result
    elif isinstance(result, dict):
        raw_records = result.get(
            "vulnerabilities",
            result.get("results", result.get("data", [])),
        )
    else:
        raw_records = []

    if not isinstance(raw_records, list):
        return []

    return [
        dict(item)
        for item in raw_records
        if isinstance(item, dict)
    ]


def prepare_query(query):
    cleaned = query.strip()

    replacements = [
        "find high severity vulnerabilities in",
        "find critical vulnerabilities in",
        "find medium severity vulnerabilities in",
        "find low severity vulnerabilities in",
        "search for vulnerabilities in",
        "search vulnerabilities in",
        "show vulnerabilities in",
        "find vulnerabilities in",
        "vulnerabilities in",
        "vulnerabilities for",
        "security vulnerabilities in",
        "security issues in",
        "find",
        "search",
        "show",
    ]

    lowered = cleaned.lower()

    for phrase in replacements:
        if lowered.startswith(phrase):
            cleaned = cleaned[len(phrase):].strip()
            break

    return cleaned or query.strip()


def render_steps(value):
    if isinstance(value, list) and value:
        for step in value:
            st.markdown(f"- {step}")
    elif isinstance(value, str) and value.strip():
        st.write(value)
    else:
        st.write(
            "No structured remediation steps were returned. "
            "Check the official vendor advisory for the recommended fix."
        )


def download_json(records):
    return json.dumps(
        records,
        indent=2,
        ensure_ascii=False,
        default=str,
    )


# --------------------------------------------------
# SESSION STATE
# --------------------------------------------------

if "research_result" not in st.session_state:
    st.session_state.research_result = None

if "research_error" not in st.session_state:
    st.session_state.research_error = None

if "last_query" not in st.session_state:
    st.session_state.last_query = ""

if "diagnostic_history" not in st.session_state:
    st.session_state.diagnostic_history = []

if "research_status" not in st.session_state:
    st.session_state.research_status = "Not started"


def record_error(message):
    st.session_state.research_error = str(message)

    st.session_state.diagnostic_history.append({
        "time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "message": str(message),
    })

    st.session_state.diagnostic_history = (
        st.session_state.diagnostic_history[-20:]
    )


# --------------------------------------------------
# SIDEBAR — PRESERVED
# --------------------------------------------------

with st.sidebar:
    st.title("🛡️ Research Controls")
    st.caption("CVE intelligence and security analysis")

    query = st.text_input(
        "Product or keyword",
        value="WordPress",
        placeholder="e.g. WordPress, Apache, OpenSSL",
        help=(
            "Enter a product name or keyword. Use the severity selector "
            "below for severity filtering."
        ),
    )

    days = st.slider(
        "Published/updated within (days)",
        min_value=1,
        max_value=120,
        value=30,
    )

    limit = st.number_input(
        "Maximum CVEs to fetch",
        min_value=1,
        max_value=2000,
        value=100,
        step=10,
    )

    severity_filter = st.selectbox(
        "Severity filter",
        options=["All", "CRITICAL", "HIGH", "MEDIUM", "LOW"],
    )

    run_button = st.button(
        "🔍 Run Security Research",
        use_container_width=True,
        type="primary",
    )

    st.divider()

    st.markdown("**Analysis pipeline**")
    st.markdown(
        """
        1. Retrieve CVE records
        2. Analyze vulnerability details
        3. Check exploitation metadata
        4. Explain impact and severity
        5. Recommend defensive actions
        """
    )

    st.caption(
        "AI-generated explanations are estimates. Verify technical "
        "details and affected versions with the official advisory."
    )


# --------------------------------------------------
# HEADER — PRESERVED
# --------------------------------------------------

st.markdown(
    """
    <div class="hero">
        <h1>🛡️ CyberSecurity ResearchAI</h1>
        <p>
            CVE intelligence, root-cause explanations, risk insights,
            and practical remediation guidance.
        </p>
    </div>
    """,
    unsafe_allow_html=True,
)


# Keep backend import errors for the bottom diagnostics section.
if not BACKEND_AVAILABLE:
    record_error(
        "Backend import failed: "
        + (BACKEND_ERROR or "Unknown import error")
    )


# --------------------------------------------------
# RUN RESEARCH — TIMEOUT HANDLING
# --------------------------------------------------

if run_button:
    if not BACKEND_AVAILABLE:
        record_error(
            "The backend is unavailable. Check manager.py and its dependencies."
        )
        st.session_state.research_status = "Failed"

    elif not query.strip():
        record_error("Please enter a product name or search keyword.")
        st.session_state.research_status = "Failed"

    else:
        st.session_state.research_error = None
        st.session_state.research_status = "Running"
        st.session_state.research_result = None

        result_queue = queue.Queue()

        def run_research_task():
            try:
                result = run_research(
                    query=prepare_query(query),
                    days=int(days),
                    limit=int(limit),
                    severity=(
                        None if severity_filter == "All"
                        else severity_filter
                    ),
                )

                result_queue.put(("success", result))

            except Exception as exc:
                result_queue.put((
                    "error",
                    f"{type(exc).__name__}: {exc}",
                    traceback.format_exc(),
                ))

        try:
            with st.status(
                "Connecting to vulnerability sources...",
                expanded=True,
            ) as status:

                st.write(
                    "Starting CVE collection and vulnerability analysis..."
                )

                worker = threading.Thread(
                    target=run_research_task,
                    daemon=True,
                )
                worker.start()

                timeout_seconds = 90
                deadline = time.monotonic() + timeout_seconds

                while (
                    worker.is_alive()
                    and time.monotonic() < deadline
                ):
                    time.sleep(0.25)

                if worker.is_alive():
                    message = (
                        f"Research timed out after {timeout_seconds} seconds. "
                        "The backend thread may still be running. Check "
                        "API timeout settings in data.py and llm.py."
                    )

                    record_error(message)
                    st.session_state.research_status = "Timed out"

                    status.update(
                        label="Research timed out",
                        state="error",
                        expanded=True,
                    )

                else:
                    try:
                        outcome = result_queue.get_nowait()

                        if outcome[0] == "success":
                            payload = outcome[1]

                            if not isinstance(payload, (dict, list)):
                                raise ValueError(
                                    "The backend returned an unexpected "
                                    "result format."
                                )

                            st.session_state.research_result = payload
                            st.session_state.research_error = None
                            st.session_state.last_query = query.strip()
                            st.session_state.research_status = "Completed"

                            status.update(
                                label="Research completed",
                                state="complete",
                                expanded=False,
                            )

                        else:
                            _, message, details = outcome

                            record_error(message)
                            st.session_state.research_status = "Failed"

                            status.update(
                                label="Research failed",
                                state="error",
                                expanded=True,
                            )

                            # Save technical details for bottom diagnostics.
                            st.session_state.diagnostic_history.append({
                                "time": datetime.now().strftime(
                                    "%Y-%m-%d %H:%M:%S"
                                ),
                                "message": details,
                            })

                    except queue.Empty:
                        record_error(
                            "Research ended without returning a result."
                        )
                        st.session_state.research_status = "Failed"

                        status.update(
                            label="No result returned",
                            state="error",
                            expanded=True,
                        )

        except Exception as exc:
            record_error(f"{type(exc).__name__}: {exc}")
            st.session_state.research_status = "Failed"


# --------------------------------------------------
# LOAD RESULTS
# --------------------------------------------------

result = st.session_state.research_result
records = extract_records(result) if result is not None else []

backend_errors = []

if isinstance(result, dict):
    errors = result.get("errors", [])
    if isinstance(errors, list):
        backend_errors = errors

display_records = records[:]

if severity_filter != "All":
    display_records = [
        record
        for record in display_records
        if get_severity(record) == severity_filter
    ]


# --------------------------------------------------
# DASHBOARD METRICS
# --------------------------------------------------

if display_records:
    for record in display_records:
        record["severity_display"] = get_severity(record)
        record["score_display"] = get_score(record)
        record["cve_id_display"] = get_cve_id(record)
        record["known_exploited_display"] = is_known_exploited(record)

    total = len(display_records)

    critical_count = sum(
        get_severity(record) == "CRITICAL"
        for record in display_records
    )
    high_count = sum(
        get_severity(record) == "HIGH"
        for record in display_records
    )
    exploited_count = sum(
        is_known_exploited(record)
        for record in display_records
    )

    st.subheader("Research Overview")

    m1, m2, m3, m4 = st.columns(4)

    m1.metric("CVEs displayed", total)
    m2.metric("Critical", critical_count)
    m3.metric("High", high_count)
    m4.metric("Marked as exploited", exploited_count)

    if st.session_state.last_query:
        st.caption(
            f"Search: {st.session_state.last_query} · "
            f"Showing {total} record(s)"
        )

    if isinstance(result, dict):
        fetched = result.get("total_fetched")
        analyzed = result.get("total_analyzed")
        saved = result.get("saved_count")

        extra_metrics = st.columns(3)

        if fetched is not None:
            extra_metrics[0].metric("Fetched by backend", fetched)

        if analyzed is not None:
            extra_metrics[1].metric("Analyzed by backend", analyzed)

        if saved is not None:
            extra_metrics[2].metric("Saved to database", saved)

    # --------------------------------------------------
    # CHARTS
    # --------------------------------------------------

    st.subheader("Vulnerability Analytics")

    chart_left, chart_right = st.columns(2)

    severity_counts = (
        pd.Series([get_severity(record) for record in display_records])
        .value_counts()
        .rename_axis("Severity")
        .reset_index(name="Count")
    )

    with chart_left:
        st.markdown("**Severity distribution**")

        fig_severity = px.pie(
            severity_counts,
            names="Severity",
            values="Count",
            hole=0.48,
            title="CVE Severity",
        )

        fig_severity.update_layout(
            template="plotly_dark",
            paper_bgcolor="rgba(0,0,0,0)",
            plot_bgcolor="rgba(0,0,0,0)",
        )

        st.plotly_chart(fig_severity, use_container_width=True)

    with chart_right:
        st.markdown("**CVSS score distribution**")

        score_df = pd.DataFrame({
            "CVE ID": [get_cve_id(r) for r in display_records],
            "CVSS Score": [get_score(r) for r in display_records],
            "Severity": [get_severity(r) for r in display_records],
        })

        fig_score = px.histogram(
            score_df,
            x="CVSS Score",
            color="Severity",
            nbins=10,
            title="CVSS Scores",
        )

        fig_score.update_layout(
            template="plotly_dark",
            paper_bgcolor="rgba(0,0,0,0)",
            plot_bgcolor="rgba(0,0,0,0)",
        )

        st.plotly_chart(fig_score, use_container_width=True)

    # --------------------------------------------------
    # CVE TABLE
    # --------------------------------------------------

    st.subheader("CVE Results")

    table_data = []

    for record in display_records:
        table_data.append({
            "CVE ID": get_cve_id(record),
            "Severity": get_severity(record),
            "CVSS": get_score(record),
            "Attack Type": safe_text(
                record.get("attack_type"), "Not classified"
            ),
            "Known Exploited": (
                "Yes" if is_known_exploited(record) else "Not marked"
            ),
            "Analysis Method": get_analysis_method(record),
        })

    table_df = pd.DataFrame(table_data)

    st.dataframe(
        table_df,
        use_container_width=True,
        hide_index=True,
    )

    # --------------------------------------------------
    # DETAILED CVE VIEW
    # --------------------------------------------------

    st.subheader("Vulnerability Investigation")

    options = [
        f"{get_cve_id(record)} | {get_severity(record)} | "
        f"CVSS {get_score(record):.1f}"
        for record in display_records
    ]

    selected_option = st.selectbox(
        "Choose a CVE to inspect",
        options=options,
    )

    record = display_records[options.index(selected_option)]

    st.markdown(f"### {get_cve_id(record)}")

    severity = get_severity(record)
    score = get_score(record)

    d1, d2, d3 = st.columns(3)

    d1.metric("Severity", severity)
    d2.metric("CVSS Score", f"{score:.1f}")
    d3.metric(
        "Known Exploited",
        "Yes" if is_known_exploited(record) else "Not marked",
    )

    st.markdown("**Description from the CVE record**")

    st.write(
        safe_text(
            record.get("description", record.get("details")),
            "No description was supplied.",
        )
    )

    # --------------------------------------------------
    # ROOT CAUSE AND AI REASONING
    # --------------------------------------------------

    st.markdown("---")
    st.subheader("🧠 Why did this vulnerability occur?")

    with st.container(border=True):
        st.markdown("#### Root Cause")

        st.write(
            safe_text(
                record.get("root_cause"),
                "A root-cause explanation was not returned. "
                "Review the official vendor advisory for technical details.",
            )
        )

        st.markdown("#### How could it be triggered?")

        st.write(
            safe_text(
                record.get("attack_mechanism"),
                "The attack mechanism could not be established from the "
                "available analysis.",
            )
        )

        st.markdown("#### Potential Impact")

        st.write(
            safe_text(
                record.get("impact_explanation", record.get("impact")),
                "The potential impact requires verification.",
            )
        )

        st.markdown("#### Why was this severity assigned?")

        st.write(
            safe_text(
                record.get("severity_reasoning"),
                (
                    f"The source record reports severity {severity} and "
                    f"CVSS {score:.1f}. Verify the score and rationale "
                    "against the original CVE record."
                ),
            )
        )

    # --------------------------------------------------
    # TECHNICAL CLASSIFICATION
    # --------------------------------------------------

    st.subheader("Technical Classification")

    t1, t2 = st.columns(2)

    with t1:
        st.markdown("**Attack Type**")
        st.write(safe_text(record.get("attack_type")))

        st.markdown("**Authentication Requirements**")
        st.write(safe_text(record.get("authentication")))

        st.markdown("**Affected System**")
        st.write(safe_text(record.get("affected_system")))

    with t2:
        st.markdown("**Impact Labels**")
        st.write(safe_text(record.get("impact")))

        st.markdown("**Risk Score**")
        risk_score = record.get("risk_score", score)

        try:
            st.write(f"{float(risk_score):.1f} / 10")
        except (ValueError, TypeError):
            st.write(safe_text(risk_score))

        st.markdown("**Analysis Method**")
        st.write(get_analysis_method(record))

    # --------------------------------------------------
    # REMEDIATION
    # --------------------------------------------------

    st.markdown("---")
    st.subheader("🛠️ How to Fix It")

    st.info(
        safe_text(
            record.get("recommendation"),
            "Review the official vendor advisory and identify the "
            "recommended patch or mitigation.",
        )
    )

    remediation = record.get("remediation_steps")

    if remediation:
        render_steps(remediation)
    else:
        st.markdown(
            "- Confirm whether the product and version are affected.\n"
            "- Review the official vendor security advisory.\n"
            "- Apply the vendor-approved patch or mitigation.\n"
            "- Review logs if exploitation is suspected."
        )

    # --------------------------------------------------
    # CONFIDENCE AND EVIDENCE
    # --------------------------------------------------

    st.markdown("---")
    st.subheader("Evidence and Confidence")

    confidence_col, method_col = st.columns(2)

    confidence_col.metric(
        "Analysis Confidence",
        safe_text(record.get("confidence"), "Unknown"),
    )

    method_col.metric(
        "Analysis Method",
        get_analysis_method(record),
    )

    st.caption(
        "Confidence describes the analysis output; it is not a guarantee "
        "that the vulnerability affects your own systems."
    )

    analysis_note = record.get("analysis_note")

    if analysis_note:
        st.warning(str(analysis_note))

    with st.expander("View complete CVE record"):
        st.json(record)

    # --------------------------------------------------
    # EXPORTS
    # --------------------------------------------------

    st.markdown("---")
    st.subheader("Export Research")

    export_col1, export_col2 = st.columns(2)

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

    csv_data = pd.DataFrame([
        {
            **record,
            "severity": get_severity(record),
            "cvss_score": get_score(record),
            "cve_id": get_cve_id(record),
        }
        for record in display_records
    ]).to_csv(index=False).encode("utf-8-sig")

    json_data = download_json(display_records)

    with export_col1:
        st.download_button(
            label="⬇️ Download CSV",
            data=csv_data,
            file_name=f"cve_research_{timestamp}.csv",
            mime="text/csv",
            use_container_width=True,
        )

    with export_col2:
        st.download_button(
            label="⬇️ Download JSON",
            data=json_data,
            file_name=f"cve_research_{timestamp}.json",
            mime="application/json",
            use_container_width=True,
        )

    if backend_errors:
        with st.expander("Research warnings and errors"):
            for error in backend_errors:
                st.warning(str(error))

elif result is not None:
    st.warning(
        "The research completed, but no records match the current filters. "
        "Try another keyword, increase the date range, or select All severities."
    )

else:
    # --------------------------------------------------
    # EMPTY STATE — PRESERVED
    # --------------------------------------------------

    st.subheader("Start Your Security Research")

    st.write(
        "Enter a product or keyword in the sidebar and click "
        "**Run Security Research** to retrieve and analyze CVEs."
    )

    examples = st.columns(3)

    with examples[0]:
        st.markdown("**Product Research**")
        st.caption("WordPress, Apache, OpenSSL")

    with examples[1]:
        st.markdown("**Risk Assessment**")
        st.caption("CVSS scores, severity, known-exploited metadata")

    with examples[2]:
        st.markdown("**AI Explanations**")
        st.caption("Root cause, impact, reasoning, remediation")

    st.info(
        "Run a search to populate the dashboard. If the backend returns "
        "zero records, try a specific product name such as WordPress."
    )


# --------------------------------------------------
# FOOTER — PRESERVED
# --------------------------------------------------

st.markdown("---")

st.markdown(
    """
    <p class="muted">
        CyberSecurity-ResearchAI · Defensive security research dashboard.
        AI analysis is informational; validate affected versions, severity,
        exploitation status, and remediation against trusted primary sources.
    </p>
    """,
    unsafe_allow_html=True,
)


# --------------------------------------------------
# ERRORS & DIAGNOSTICS — BOTTOM OF DASHBOARD
# --------------------------------------------------

st.markdown("---")

with st.expander(
    "⚠️ Errors & Diagnostics",
    expanded=bool(st.session_state.research_error),
):
    st.markdown("**Current research status**")
    st.write(st.session_state.research_status)

    if not BACKEND_AVAILABLE:
        st.error("Backend import failed.")
        st.code(BACKEND_ERROR or "Unknown import error")

    if st.session_state.research_error:
        st.markdown("**Latest error**")
        st.error(st.session_state.research_error)
    elif not st.session_state.diagnostic_history:
        st.success("No research errors recorded.")

    if st.session_state.diagnostic_history:
        st.markdown("**Recent diagnostic history**")

        for item in reversed(st.session_state.diagnostic_history):
            st.caption(item["time"])
            st.code(item["message"])

        if st.button(
            "Clear diagnostic history",
            key="clear_diagnostics",
        ):
            st.session_state.diagnostic_history = []
            st.session_state.research_error = None
            st.rerun()

    st.caption(
        "A timeout does not forcibly stop the backend thread. "
        "If a task times out repeatedly, check API timeout settings "
        "in data.py and llm.py."
    )
