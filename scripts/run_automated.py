# scripts/run_automated.py
"""
Automated Security Scanner - Runs scans and sends alerts.
Designed for cron/Task Scheduler integration.
"""

import sys
import os
import json
from datetime import datetime

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.utils.scheduler import SecurityScheduler
from src.alerts.email_alerter import EmailAlerter
from src.alerts.slack_alerter import SlackAlerter

def run_automated_scan():
    """
    Run automated security scan and send alerts if needed.
    """
    print("=" * 60)
    print("🤖 AI AWS CSPM - Automated Security Scan")
    print("=" * 60)
    print(f"Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("=" * 60)
    
    # Initialize components
    scheduler = SecurityScheduler()
    email_alerter = EmailAlerter()
    slack_alerter = SlackAlerter()
    
    # Run the scan
    result = scheduler.run_scan()
    
    if not result['success']:
        print(f"\n❌ Scan failed: {result.get('error', 'Unknown error')}")
        return result
    
    scan = result['scan']
    comparison = result['comparison']
    
    print(f"\n📊 Scan Results:")
    print(f"   Security Score: {scan.get('security_assessment', {}).get('security_score', 0)}%")
    print(f"   Total Findings: {scan.get('total_findings', 0)}")
    print(f"   Score Change: {comparison.get('score_change', 0):+.1f}%")
    
    # Send alerts if needed
    if scheduler.should_alert(comparison):
        print("\n🚨 Sending alerts...")
        
        # Send email
        email_alerter.send_alert(scan, comparison)
        
        # Send Slack
        slack_alerter.send_alert(scan, comparison)
    else:
        print("\n✅ No critical changes detected. Alerts not sent.")
    
    # Save alert log
    log_entry = {
        "timestamp": datetime.now().isoformat(),
        "success": True,
        "score": scan.get('security_assessment', {}).get('security_score', 0),
        "findings": scan.get('total_findings', 0),
        "alerts_sent": scheduler.should_alert(comparison)
    }
    
    log_file = "data/automation_log.json"
    logs = []
    if os.path.exists(log_file):
        with open(log_file, 'r') as f:
            logs = json.load(f)
    
    logs.append(log_entry)
    
    # Keep last 100 logs
    logs = logs[-100:]
    
    with open(log_file, 'w') as f:
        json.dump(logs, f, indent=2)
    
    print("\n" + "=" * 60)
    print("✅ Automated scan completed")
    print("=" * 60)
    
    return result

def main():
    try:
        run_automated_scan()
    except KeyboardInterrupt:
        print("\n\n⚠️ Scan interrupted by user")
    except Exception as e:
        print(f"\n❌ Error: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    main()