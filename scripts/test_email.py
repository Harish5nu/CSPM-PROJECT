# scripts/test_email.py
import sys
import os
from dotenv import load_dotenv

# IMPORTANT: Explicitly load .env file from the correct location
env_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), '.env')
load_dotenv(env_path)

# Print debug info
print("=" * 50)
print("DEBUG: Checking .env file")
print("=" * 50)
print(f".env path: {env_path}")
print(f"File exists: {os.path.exists(env_path)}")
print(f"SENDER_EMAIL from env: {os.getenv('SENDER_EMAIL')}")
print(f"SMTP_SERVER from env: {os.getenv('SMTP_SERVER')}")
print("=" * 50)

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.alerts.email_alerter import EmailAlerter

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
            'remediation': {'cli_command': 'aws iam update-account-password-policy --minimum-password-length 14'}
        }
    ],
    'score_change': -5.2,
    'old_score': 80.2,
    'new_score': 75.0
}

# Initialize email alerter
print("\nInitializing EmailAlerter...")
emailer = EmailAlerter()

print(f"\nEmail enabled status: {emailer.enabled}")

if emailer.enabled:
    print("\nSending test email...")
    result = emailer.send_alert(test_scan, test_comparison)
    if result:
        print("\n✅ Test email sent! Check your inbox.")
        print("   (Check Spam folder if not in Inbox)")
    else:
        print("\n❌ Failed to send email.")
else:
    print("\n⚠️ Email not enabled. Check:")
    print("   1. SENDER_EMAIL is set")
    print("   2. SENDER_PASSWORD is set (App Password)")
    print("   3. RECIPIENT_EMAIL is set")