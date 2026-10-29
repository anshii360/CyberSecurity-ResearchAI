🛡️ CyberSecurity-ResearchAI

An AI-powered cybersecurity research tool for CVE analysis, vulnerability risk assessment, severity classification, and remediation insights.

📌 Overview

CyberSecurity-ResearchAI is a Python-based cybersecurity research dashboard designed to help users explore Common Vulnerabilities and Exposures (CVEs), assess vulnerability severity, and understand potential security risks.

The project combines vulnerability data retrieval, analytical tools, and AI-assisted insights in a Streamlit dashboard.

✨ Features

CVE Research: Retrieve and explore vulnerability information.

Severity Analysis: Classify vulnerabilities by Critical, High, Medium, and Low severity.

CVSS Scoring: Analyze CVSS scores and identify high-risk vulnerabilities.

Known Exploited Vulnerabilities: Display available known-exploited vulnerability metadata.

AI-Assisted Analysis: Generate explanations of vulnerability causes, impact, and severity.

Remediation Insights: Provide guidance for understanding and addressing security risks.

Interactive Dashboard: Explore vulnerability metrics, charts, and individual CVE details.

Data Export: Export research results in CSV and JSON formats.

Diagnostics: Review application errors and troubleshooting information.

🧰 Tech Stack

Language: Python

Dashboard: Streamlit

Data Analysis: Pandas

Vulnerability Intelligence: NVD CVE API

Security Data: CISA Known Exploited Vulnerabilities metadata

AI Integration: Configured language-model integration

Database: SQLite

Data Visualization: Streamlit charts

📂 Project Structure

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

⚙️ Installation and Setup

1. Clone the repository

git clone https://github.com/anshii360/CyberSecurity-ResearchAI.git

2. Navigate to the project directory

cd CyberSecurity-ResearchAI

3. Create a virtual environment

python -m venv venv

4. Activate the environment

Windows PowerShell:

.\venv\Scripts\Activate.ps1

Windows Command Prompt:

venv\Scripts\activate.bat

5. Install dependencies

python -m pip install -r requirements.txt

6. Configure API credentials

If your configured AI provider requires an API key, set it according to the configuration expected by llm.py. Keep API keys in environment variables or an appropriate secrets file; never commit them to GitHub.

7. Run the application

streamlit run app.py

Open the local URL displayed in your terminal to access the dashboard.

🔍 How It Works

Enter a vulnerability research query.

Retrieve relevant CVE information from the configured data sources.

Explore severity classifications, CVSS scores, and available exploitation metadata.

Review AI-assisted explanations and remediation insights when the AI service is configured.

Export the research results for further analysis.

🎯 Project Goals

Make vulnerability research easier to explore.

Support risk-based prioritization of security issues.

Improve understanding of CVE severity and potential impact.

Present security research findings through an interactive dashboard.

⚠️ Disclaimer

This project is intended for educational, research, and defensive cybersecurity purposes. Vulnerability severity scores and AI-generated explanations should be validated against authoritative sources before making security decisions. AI-generated recommendations may be incomplete or inaccurate.

👩‍💻 Author

Anshii360

GitHub: @anshii360

⭐ Support

If you find this project useful, consider giving the repository a star on GitHub.
