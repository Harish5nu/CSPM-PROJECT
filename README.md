# 🔒 AI-Powered AWS Security Scanner (CSPM)

[![Python](https://img.shields.io/badge/Python-3.11-blue.svg)](https://python.org)
[![AWS](https://img.shields.io/badge/AWS-boto3-orange.svg)](https://aws.amazon.com)
[![Streamlit](https://img.shields.io/badge/Streamlit-Dashboard-red.svg)](https://streamlit.io)
[![Docker](https://img.shields.io/badge/Docker-Ready-blue.svg)](https://docker.com)

## 📖 Overview

An **AI-powered Cloud Security Posture Management (CSPM)** tool that automatically scans AWS resources, detects security misconfigurations, generates AI-powered remediation, and provides a beautiful dashboard.

### What It Does

| Feature | Description |
|---------|-------------|
| 🔍 **AWS Scanning** | S3, IAM, EC2, RDS security checks |
| 🤖 **AI Remediation** | LLM-generated fix commands (CLI + Terraform) |
| 📊 **Risk Scoring** | 0-100 security score with letter grade |
| 📜 **Compliance** | CIS, NIST, GDPR, HIPAA, PCI, SOX mapping |
| 📈 **Dashboard** | Interactive Streamlit web interface |
| 📧 **Alerts** | Email + Slack notifications |
| 🐳 **Docker** | Ready-to-run container |

## 🚀 Quick Start

### Prerequisites
- AWS account (free tier works)
- Python 3.11+
- Docker (optional)

### Installation

```bash
# Clone the repository
git clone https://github.com/YOUR_USERNAME/ai-aws-cspm
cd ai-aws-cspm

# Create virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Configure AWS credentials
cp .env.example .env
# Edit .env with your AWS credentials