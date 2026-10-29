CyberSecurity-ResearchAI

AI-Assisted Vulnerability Research and Risk Analysis

A Python-based cybersecurity research dashboard for exploring CVEs, analyzing vulnerability severity, reviewing risk indicators, and understanding remediation options through an interactive interface.

Repository

Overview

CyberSecurity-ResearchAI brings vulnerability research and security analysis together in a Streamlit dashboard. It combines structured vulnerability data, analytical tools, and AI-assisted explanations to support a clearer understanding of potential security risks.

The project focuses on making CVE research more accessible through data visualization, vulnerability details, and exportable research results.

Key Features

CVE Research: Retrieve and explore vulnerability records from configured data sources.

Severity Analysis: Review severity classifications and vulnerability distributions.

CVSS Assessment: Analyze available CVSS scores and identify higher-risk vulnerabilities.

Exploitation Indicators: Examine known-exploited vulnerability metadata when available.

AI-Assisted Insights: Generate additional explanations through the configured language-model integration.

Remediation Guidance: Review potential mitigation and remediation considerations.

Interactive Dashboard: Explore metrics, charts, filters, and individual vulnerability details.

Data Export: Download supported research results in CSV and JSON formats.

Diagnostics: Inspect application errors to help troubleshoot issues.

Technology Stack

Technology

Purpose

Python

Application logic

Streamlit

Interactive dashboard

Pandas

Data processing and analysis

SQLite

Local data storage

NVD CVE API

Vulnerability information

CISA KEV data

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

Getting Started

Prerequisites

Python 3.11 or a compatible version

pip

Git

API credentials if required by the configured language-model provider

1. Clone the Repository

git clone https://github.com/anshii360/CyberSecurity-ResearchAI.git
cd CyberSecurity-ResearchAI

2. Create a Virtual Environment

python -m venv venv

3. Activate the Environment

Windows PowerShell

.\venv\Scripts\Activate.ps1

Windows Command Prompt

venv\Scripts\activate.bat

4. Install Dependencies

python -m pip install -r requirements.txt

5. Configure Credentials

Configure any required API credentials according to the project's implementation. Store secrets in environment variables or an appropriate local secrets file.

Never commit API keys, passwords, or private credentials to the repository.

6. Launch the Dashboard

streamlit run app.py

Open the local URL displayed in the terminal to access the application.

Research Workflow

Enter a vulnerability research query.

Retrieve relevant CVE information from configured data sources.

Examine vulnerability details, severity classifications, and available CVSS scores.

Review available exploitation indicators and AI-assisted analysis.

Explore remediation considerations.

Export research results for further review.

The availability and completeness of results depend on the configured data sources and external service access.

Security Considerations

Verify vulnerability information against authoritative sources.

Treat AI-generated explanations as supporting analysis, not definitive security advice.

Review remediation recommendations before applying them to production systems.

Keep API credentials and sensitive local data out of version control.

Future Scope

Potential improvements include enhanced vulnerability filtering, additional threat-intelligence sources, richer reporting, and expanded risk-prioritization capabilities.

Disclaimer

This project is intended for educational, research, and defensive cybersecurity purposes. Vulnerability information may change over time, and AI-generated output may be incomplete or inaccurate. Validate findings against authoritative sources before making security decisions.

Author

Anshii360

GitHub Profile

Built to support more accessible cybersecurity research and vulnerability analysis.
