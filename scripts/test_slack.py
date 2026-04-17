# scripts/test_slack.py
import sys
import os
from dotenv import load_dotenv

# Load .env
env_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), '.env')
load_dotenv(env_path)

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.alerts.slack_alerter import SlackAlerter

# Create test data
test_scan = {
    'security_assessment': {
        'security_score': 75,
        'grade': 'C',
        'risk_assessment': {
            'risk_summary': {'CRITICAL': 0, 'HIGH': 2, 'MEDIUM': 1, 'LOW': 0}
        }
    },
    'total_findings': 3
}

test_comparison = {
    'new_findings': [
        {
            'severity': 'HIGH',
            'service': 'IAM',
            'issue': 'No password policy configured',
            'resource_id': 'account-password-policy',
            'remediation': {'cli_command': 'aws iam update-account-password-policy'}
        }
    ],
    'score_change': -5.2,
    'old_score': 80.2,
    'new_score': 75.0
}

print("=" * 50)
print("Testing Slack Alerts")
print("=" * 50)

slack = SlackAlerter()

if slack.enabled:
    print("\nSending test message...")
    result = slack.send_test_message()
    if result:
        print("✅ Test message sent! Check your Slack channel.")
    else:
        print("❌ Failed to send test message")
    
    print("\nSending alert simulation...")
    result2 = slack.send_alert(test_scan, test_comparison)
    if result2:
        print("✅ Alert simulation sent!")
    else:
        print("❌ Alert simulation failed")
else:
    print("\n⚠️ Slack not configured. Add SLACK_WEBHOOK_URL to .env file")