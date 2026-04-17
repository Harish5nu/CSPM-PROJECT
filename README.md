
# 🔒 AI-Powered AWS Security Scanner (CSPM)

[![Python](https://img.shields.io/badge/Python-3.11-blue.svg)](https://python.org)
[![AWS](https://img.shields.io/badge/AWS-boto3-orange.svg)](https://aws.amazon.com)
[![Streamlit](https://img.shields.io/badge/Streamlit-Dashboard-red.svg)](https://streamlit.io)
[![Docker](https://img.shields.io/badge/Docker-Ready-blue.svg)](https://docker.com)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

## 📖 Overview

An **AI-powered Cloud Security Posture Management (CSPM)** tool that automatically scans AWS resources, detects security misconfigurations, generates AI-powered remediation, and provides a beautiful dashboard.

### 🎯 Why This Project?

| Problem | Solution |
|---------|----------|
| 80% of cloud breaches are due to misconfigurations | Automated scanning catches issues before attackers |
| Security teams spend hours writing remediation guides | AI generates fix commands instantly |
| Compliance audits are manual and painful | Automated compliance mapping to CIS, NIST, GDPR |
| No centralized security view | Dashboard shows security score and all findings |

### ✨ Features

| Feature | Description |
|---------|-------------|
| 🔍 **AWS Scanning** | S3, IAM, EC2, RDS security checks (20+ rules) |
| 🤖 **AI Remediation** | LLM-generated fix commands (CLI + Terraform) |
| 📊 **Risk Scoring** | 0-100 security score with letter grade (A+ to F) |
| 📜 **Compliance** | CIS, NIST, GDPR, HIPAA, PCI, SOX mapping |
| 📈 **Dashboard** | Interactive Streamlit web interface (5 pages) |
| 📧 **Alerts** | Email (SMTP) + Slack notifications |
| 📉 **History** | Track security score over time |
| 🐳 **Docker** | Ready-to-run container |

---

## 🚀 Quick Start

### Prerequisites

- AWS account (free tier works)
- Python 3.11 or higher
- Git (optional)
- Docker (optional)

### Installation

```bash
git clone https://github.com/YOUR_USERNAME/ai-aws-cspm.git
cd ai-aws-cspm

python -m venv venv

venv\Scripts\activate
# or
source venv/bin/activate

pip install -r requirements.txt

ollama pull llama3.2:1b

cp .env.example .env
```

### Configuration (.env file)

```env
AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
AWS_DEFAULT_REGION=us-east-1

SMTP_SERVER=smtp.gmail.com
SMTP_PORT=587
SENDER_EMAIL=your-email@gmail.com
SENDER_PASSWORD=your-app-password
RECIPIENT_EMAIL=alerts@example.com

SLACK_WEBHOOK_URL=https://hooks.slack.com/services/...
```

## 📊 Usage

### Run a Security Scan

```bash
python scripts/run_all_scanners.py
python scripts/run_with_ai.py
python scripts/run_with_scoring.py
python scripts/run_automated.py
```

### Launch Dashboard

```bash
streamlit run dashboard/app.py
```

Open http://localhost:8501

### Run with Docker

```bash
docker build -t ai-aws-cspm .
docker run --rm --env-file .env ai-aws-cspm
docker run --rm -p 8501:8501 --env-file .env ai-aws-cspm streamlit run dashboard/app.py --server.address=0.0.0.0
```

## 📁 Project Structure

```
ai-aws-cspm/
│
├── dashboard/
│   └── app.py                 # Streamlit web interface (5 pages)
│
├── src/
│   ├── collectors/            # AWS data collection
│   │   ├── base_collector.py  # Parent class for all collectors
│   │   ├── s3_collector.py    # S3 bucket scanner
│   │   ├── iam_collector.py   # IAM user/role scanner
│   │   ├── ec2_collector.py   # EC2 instance scanner
│   │   └── rds_collector.py   # RDS database scanner
│   │
│   ├── ai/                    # AI and analytics
│   │   ├── ai_client.py       # Ollama API wrapper
│   │   ├── remediation_gen.py # Generates fix suggestions
│   │   ├── risk_scorer.py     # Calculates security scores
│   │   ├── compliance_mapper.py # Maps to compliance frameworks
│   │   └── security_score.py  # Unified scoring engine
│   │
│   ├── alerts/                # Notification system
│   │   ├── email_alerter.py   # SMTP email alerts
│   │   └── slack_alerter.py   # Slack webhook alerts
│   │
│   └── utils/                 # Helper modules
│       ├── history_manager.py # Historical tracking
│       └── scheduler.py       # Automated scheduling
│
├── scripts/                   # Executable scripts
│   ├── run_all_scanners.py   # Run all collectors
│   ├── run_with_ai.py        # Add AI remediation
│   ├── run_with_scoring.py   # Full assessment
│   └── run_automated.py      # Automated with alerts
│
├── data/                      # Scan results (JSON)
│   ├── full_assessment.json   # Latest scan
│   ├── scan_history.json      # Historical trends
│   └── automation_log.json    # Automated run log
│
├── Dockerfile                 # Docker container recipe
├── docker-compose.yml         # Multi-container setup
├── requirements.txt           # Python dependencies
└── README.md                  # This file
```

## 📊 Sample Output

```
======================================================================
🔒 AI AWS CSPM - Complete Security Assessment
======================================================================

📊 Found 3 security issue(s)

🤖 Generating AI remediation...
✅ Remediation complete for 3 finding(s)

🎯 Security Score: 81.6%
📝 Grade: B
⚠️ Risk Score: 88.0%
📋 Compliance Score: 66.6%

🔴 CRITICAL: 0
🟠 HIGH: 2
🟡 MEDIUM: 1
🔵 LOW: 0

📜 Compliance Summary:
   CIS    [███░░░░░░░] 33.3%
   NIST   [███░░░░░░░] 33.3%
   GDPR   [███░░░░░░░] 33.3%
   HIPAA  [██████████] 100.0%
   PCI    [██████████] 100.0%
   SOX    [██████████] 100.0%
```

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                         USER INTERFACE                           │
│                      Streamlit Dashboard                         │
│                    (http://localhost:8501)                       │
└─────────────────────────────┬───────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                      APPLICATION LAYER                           │
├───────────────┬───────────────┬───────────────┬─────────────────┤
│   S3 Scanner  │  IAM Scanner  │  EC2 Scanner  │  RDS Scanner    │
│   (boto3)     │   (boto3)     │   (boto3)     │   (boto3)       │
└───────────────┴───────────────┴───────────────┴─────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                        AI & ANALYTICS                            │
├─────────────────┬─────────────────┬─────────────────────────────┤
│  AI Remediation │  Risk Scoring    │  Compliance Mapping         │
│    (Ollama)     │  (0-100 Scale)   │  (CIS/NIST/GDPR)            │
└─────────────────┴─────────────────┴─────────────────────────────┘
```

## 🔒 Security Checks Implemented

### S3 Scanner
| Check | Severity | Why Important |
| :---- | :----- | :---- |
| Public bucket access | CRITICAL |	Data exposure to anyone on internet |
|Encryption disabled | HIGH	| Data at risk if storage stolen |
|Versioning disabled | MEDIUM |	Accidental/permanent deletion risk |
|Logging disabled |	MEDIUM | No audit trail of access |
### IAM Scanner
| Check | Severity | Why Important |
| :---- | :------ | :---- |
|Root user MFA	|CRITICAL|	Root account takeover risk|
|No password policy	|HIGH	| Users can choose weak passwords|
|Users without MFA	|HIGH	|Account takeover risk|
|Admin policies	|MEDIUM	|Over-privileged accounts|
### EC2 Scanner
| Check | Severity | Why Important |
| :--- | :----| :--- |
|Open SSH/RDP ports	|CRITICAL	|Direct attacker access|
|Public IP addresses	|MEDIUM	|Increased attack surface|
|Unencrypted volumes	|HIGH	|Data at risk|
### RDS Scanner
| Check | Severity | Why Important |
| :--- | :---- | :--- |
|Public database access	|CRITICAL|	Direct database exposure|
|Encryption disabled	|HIGH	|Data stored unsecured|
|Short backup retention	|MEDIUM|	Data loss risk|
```

## 📈 Risk Scoring Formula

```python
finding_risk = severity_weight × service_multiplier × (exploitability/10)
security_score = max(0, 100 - sum(all_finding_risks))
```

## 📧 Alerts Configuration

### Email (Gmail)
Enable 2FA and generate App Password.

### Slack
Create webhook and add to .env.

## 🐳 Docker Deployment

```bash
docker-compose up
```

## 🛠️ Technologies Used

Python, boto3, Ollama, Streamlit, Plotly, Pandas, Docker, SMTP, Slack API

## 📝 Requirements.txt

```
boto3>=1.34.0
pandas>=2.2.0
streamlit>=1.29.0
plotly>=5.18.0
python-dotenv>=1.0.0
requests>=2.31.0
pydantic>=2.5.0
```


## 👨‍💻 Author

Harish Saud

## ⭐ Show Your Support

Give a ⭐ on GitHub.

