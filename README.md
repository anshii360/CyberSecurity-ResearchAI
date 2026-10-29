🛡️ CyberSecurity-ResearchAI

AI-Powered Vulnerability Research & Risk Analysis Dashboard

<p align="center">

Explore CVEs. Analyze Risks. Understand Vulnerabilities.

</p>

<p align="center">






</p>

📌 Overview

CyberSecurity-ResearchAI is an AI-assisted cybersecurity research project designed to simplify vulnerability research, CVE analysis, and risk assessment through an interactive dashboard.

The application combines vulnerability intelligence, analytical tools, and AI-assisted explanations to help users explore security vulnerabilities, understand their severity, and review potential remediation approaches.

Built with Python and Streamlit, the project provides a centralized interface for exploring vulnerability data and generating research insights.

✨ Key Features

🔎 CVE Research

Search and explore Common Vulnerabilities and Exposures (CVEs).

Retrieve vulnerability information from configured data sources.

Review individual vulnerability details.

📊 Vulnerability Analytics

Analyze vulnerability severity distributions.

Explore CVSS scores and risk levels.

Identify high-risk vulnerabilities.

Visualize research results through dashboard charts and metrics.

🤖 AI-Assisted Security Analysis

Generate explanations of vulnerability details.

Support understanding of potential causes and security impact.

Review AI-assisted technical analysis and remediation insights.

🚨 Known Exploited Vulnerability Analysis

Examine known-exploited vulnerability metadata when available.

Support vulnerability prioritization using available exploitation indicators.

🛠️ Remediation Insights

Review suggested approaches for addressing vulnerabilities.

Understand potential mitigation and remediation considerations.

📁 Data Export

Export research results in CSV format.

Download structured results in JSON format.

🖥️ Interactive Dashboard

Explore vulnerability records and analytical summaries.

Filter research results by severity.

Review detailed vulnerability information.

Access application diagnostics for troubleshooting.

🧰 Tech Stack

Technology

Purpose

Python

Core application logic

Streamlit

Interactive dashboard

Pandas

Data processing and analysis

SQLite

Local data storage

NVD CVE API

Vulnerability data source

CISA KEV data

Known-exploited vulnerability intelligence

Configured LLM provider

AI-assisted analysis

Git & GitHub

Version control and project hosting

🏗️ Project Architecture

The application is organized into separate Python modules to keep data retrieval, analysis, reporting, and dashboard functionality manageable.

app.py — Streamlit dashboard and user interface.

agent.py — Agent-related functionality.

analysis.py — Vulnerability analysis and risk metrics.

cisa.py — CISA-related vulnerability data handling.

data.py — Data retrieval and processing.

database.py — Database operations.

llm.py — Language-model integration.

manager.py — Research workflow management.

query_parser.py — Research query parsing.

report.py — Report generation.

tools.py — Supporting utilities and tools.

requirements.txt — Python dependencies.

📂 Project Structure

CyberSecurity-ResearchAI/
│
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

⚙️ Installation & Setup

Follow these steps to run the project locally.

1. Clone the Repository

git clone https://github.com/anshii360/CyberSecurity-ResearchAI.git

2. Navigate to the Project Directory

cd CyberSecurity-ResearchAI

3. Create a Virtual Environment

python -m venv venv

4. Activate the Virtual Environment

Windows PowerShell

.\venv\Scripts\Activate.ps1

Windows Command Prompt

venv\Scripts\activate.bat

5. Install Dependencies

python -m pip install -r requirements.txt

6. Configure API Credentials

If your configured language-model provider requires an API key, configure it according to the settings expected by the project.

Store credentials in environment variables or an appropriate secrets file.

Never commit API keys, passwords, or other secrets to GitHub.

Check the relevant configuration in llm.py before launching the application.

7. Launch the Dashboard

streamlit run app.py

Open the local URL shown in your terminal to access the dashboard.

🔄 How It Works

Enter a research query to begin exploring relevant vulnerabilities.

Retrieve vulnerability data from the configured sources.

Analyze security information, including severity and CVSS scores when available.

Review vulnerability details and relevant exploitation metadata.

Explore AI-assisted insights when the language-model integration is configured and available.

Review remediation guidance to support further investigation.

Export results in CSV or JSON format for additional analysis.

🎯 Project Objectives

Simplify cybersecurity vulnerability research.

Improve visibility into CVE severity and risk indicators.

Support risk-based vulnerability prioritization.

Make technical security information easier to explore.

Combine structured vulnerability data with AI-assisted analysis.

Present research findings through an interactive dashboard.

🔐 Security & Reliability

Keep API credentials outside source control.

Validate vulnerability details against authoritative sources.

Treat AI-generated explanations as assistance rather than definitive security advice.

Review application errors and data-source availability when troubleshooting.

Use current vulnerability intelligence when making remediation decisions.

🚀 Future Improvements

Potential future enhancements include:

Advanced vulnerability search and filtering.

Improved risk-prioritization workflows.

Additional threat-intelligence integrations.

Enhanced reporting and visualization.

More detailed vulnerability trend analysis.

Automated monitoring of newly published vulnerabilities.

⚠️ Disclaimer

This project is intended for educational, research, and defensive cybersecurity purposes.

AI-generated explanations and remediation recommendations may be incomplete or inaccurate. Vulnerability data and severity assessments should be verified using authoritative sources before being used for operational security decisions.

👩‍💻 Author

Anshii360

GitHub: @anshii360

⭐ Show Your Support

If you find this project useful, consider giving the repository a ⭐ on GitHub.

<p align="center">

Built with Python, Streamlit, and a passion for cybersecurity.

</p>
