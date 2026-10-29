CyberSecurity-ResearchAI

AI-Assisted Vulnerability Research and Risk Analysis

A Python-based cybersecurity research dashboard for exploring CVEs, analyzing vulnerability severity, reviewing risk indicators, and examining remediation options.

Overview

CyberSecurity-ResearchAI combines vulnerability data, analytical tools, and AI-assisted insights in an interactive Streamlit dashboard.

Features

CVE Research — Explore vulnerability records from configured data sources.

Severity Analysis — Review severity classifications and vulnerability distributions.

CVSS Analysis — Examine available scores and identify higher-risk vulnerabilities.

Known Exploited Vulnerabilities — Review available exploitation metadata.

AI-Assisted Analysis — Explore vulnerability explanations using the configured language-model integration.

Remediation Insights — Review potential mitigation approaches.

Interactive Dashboard — Explore metrics, charts, filters, and vulnerability details.

Data Export — Export research results in CSV and JSON formats.

Diagnostics — Inspect application errors for troubleshooting.

Technology Stack

Technology

Purpose

Python

Application logic

Streamlit

Interactive dashboard

Pandas

Data analysis

SQLite

Local database

NVD CVE API

Vulnerability information

CISA KEV

Known-exploited vulnerability metadata

Language-model integration

AI-assisted analysis

Project Structure

CyberSecurity-ResearchAI/
├── app.py
├── agent.py
├── analysis.py
├── cisa.py
├── data.py
├── database.py
├── llm.py
├── manager.py
├── query_parser.py
├── report.py
├── tools.py
├── requirements.txt
└── README.md

Installation

1. Clone the Repository

git clone https://github.com/anshii360/CyberSecurity-ResearchAI.git
cd CyberSecurity-ResearchAI

2. Create a Virtual Environment

python -m venv venv

3. Activate the Environment

Windows PowerShell

.\venv\Scripts\Activate.ps1

4. Install Dependencies

python -m pip install -r requirements.txt

5. Configure Credentials

Configure any required API credentials according to the project's implementation. Never commit API keys, passwords, or private credentials to GitHub.

6. Run the Dashboard

streamlit run app.py

Open the local URL displayed in your terminal.

Workflow

Enter a vulnerability research query.

Retrieve relevant CVE information.

Review severity, CVSS scores, and available exploitation metadata.

Examine AI-assisted analysis when configured.

Review remediation considerations.

Export results for further analysis.

Security Notice

Verify vulnerability information and remediation recommendations against authoritative sources. AI-generated output may be incomplete or inaccurate. Keep credentials and sensitive local data out of version control.

Future Scope

Enhanced vulnerability filtering

Additional threat-intelligence integrations

Improved reporting and visualization

Expanded risk-prioritization capabilities

Disclaimer

This project is intended for educational, research, and defensive cybersecurity purposes. Findings should be validated before being used for operational security decisions.

Author

Anshii360

GitHub Profile

Cybersecurity research through data analysis and AI-assisted insights.
