# scripts/test_ai_remediation.py
"""
Test AI remediation with sample findings.
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.ai.remediation_gen import RemediationGenerator

# Sample findings for testing
sample_findings = [
    {
        "resource_id": "my-test-bucket",
        "service": "S3",
        "issue": "Bucket is publicly accessible",
        "severity": "CRITICAL",
        "details": {
            "check": "public_access",
            "recommendation": "Block all public access"
        }
    },
    {
        "resource_id": "database-01",
        "service": "RDS",
        "issue": "Database is publicly accessible",
        "severity": "CRITICAL",
        "details": {
            "endpoint": "database-01.xxxxxx.us-east-1.rds.amazonaws.com"
        }
    },
    {
        "resource_id": "web-sg",
        "service": "EC2",
        "issue": "Security group allows SSH from anywhere (0.0.0.0/0)",
        "severity": "CRITICAL",
        "details": {
            "group_id": "sg-12345678",
            "port": 22
        }
    },
    {
        "resource_id": "unencrypted-bucket",
        "service": "S3",
        "issue": "Default encryption not enabled",
        "severity": "HIGH",
        "details": {
            "check": "encryption"
        }
    }
]

print("=" * 60)
print("Testing AI Remediation Generator")
print("=" * 60)

remediator = RemediationGenerator(use_ai=True)

for finding in sample_findings:
    print(f"\n📝 Finding: {finding['severity']} - {finding['service']}")
    print(f"   Issue: {finding['issue']}")
    
    result = remediator.add_remediation_to_finding(finding)
    remediation = result.get('remediation', {})
    
    print(f"   🤖 AI Explanation: {remediation.get('explanation', 'N/A')[:100]}...")
    print(f"   🔧 CLI Fix: {remediation.get('cli_command', 'N/A')[:80]}...")
    print("-" * 40)

print("\n✅ Test complete!")