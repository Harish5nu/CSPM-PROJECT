
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
...
```

## 📊 Sample Output

```
🔒 AI AWS CSPM - Complete Security Assessment
...
```

## 🏗️ Architecture

```
(Streamlit → Scanners → AI → Output)
```

## 🔒 Security Checks Implemented

Includes checks across S3, IAM, EC2, and RDS with severity classification.

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

## 🤝 Contributing

PRs welcome.

## 📄 License

MIT License

## 👨‍💻 Author

Your Name

## ⭐ Show Your Support

Give a ⭐ on GitHub.

## 📞 Contact

Open an issue.

Built with 🔒
