# src/alerts/slack_alerter.py
"""
Slack Alert System - Sends security notifications to Slack.
"""

import requests
import json
import os
from datetime import datetime
from typing import Dict, Any, List
from dotenv import load_dotenv

class SlackAlerter:
    """
    Sends security alerts to Slack via webhook.
    """
    
    def __init__(self):
        # Load .env file
        env_path = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))), '.env')
        load_dotenv(env_path)
        
        self.webhook_url = os.getenv('SLACK_WEBHOOK_URL', '')
        self.enabled = bool(self.webhook_url)
        
        if self.enabled:
            print("💬 Slack alerts: ENABLED")
        else:
            print("💬 Slack alerts: DISABLED (set SLACK_WEBHOOK_URL in .env)")
    
    def send_alert(self, scan_result: Dict[str, Any], comparison: Dict[str, Any]) -> bool:
        """
        Send Slack notification about scan results.
        
        Args:
            scan_result: The scan results
            comparison: Comparison with previous scan
            
        Returns:
            True if sent successfully, False otherwise
        """
        if not self.enabled:
            return False
        
        # Check if alert is needed
        new_critical = [f for f in comparison.get('new_findings', []) 
                       if f.get('severity') in ['CRITICAL', 'HIGH']]
        
        score_change = comparison.get('score_change', 0)
        
        # Only send if there are critical/high findings or score dropped
        if not new_critical and score_change >= 0:
            return False
        
        payload = self._build_slack_payload(scan_result, comparison, new_critical)
        
        try:
            response = requests.post(self.webhook_url, json=payload, timeout=10)
            if response.status_code == 200:
                print("💬 Slack notification sent successfully")
                return True
            else:
                print(f"❌ Slack notification failed: {response.status_code}")
                return False
        except Exception as e:
            print(f"❌ Slack notification error: {e}")
            return False
    
    def _build_slack_payload(self, scan_result: Dict, comparison: Dict, new_critical: List) -> Dict:
        """Build Slack webhook payload."""
        assessment = scan_result.get('security_assessment', {})
        score = assessment.get('security_score', 0)
        grade = assessment.get('grade', 'F')
        risk_summary = assessment.get('risk_assessment', {}).get('risk_summary', {})
        
        # Determine color based on severity
        if new_critical:
            color = "#e74c3c"  # Red
            status = "CRITICAL"
        elif risk_summary.get('HIGH', 0) > 0:
            color = "#e67e22"  # Orange
            status = "HIGH"
        elif score < 70:
            color = "#f1c40f"  # Yellow
            status = "WARNING"
        else:
            color = "#2ecc71"  # Green
            status = "GOOD"
        
        # Build fields
        fields = [
            {"title": "Security Score", "value": f"{score}% ({grade})", "short": True},
            {"title": "Score Change", "value": f"{comparison.get('score_change', 0):+.1f}%", "short": True},
            {"title": "Total Findings", "value": str(scan_result.get('total_findings', 0)), "short": True},
        ]
        
        if risk_summary.get('CRITICAL', 0) > 0:
            fields.append({"title": "🔴 CRITICAL", "value": str(risk_summary['CRITICAL']), "short": True})
        if risk_summary.get('HIGH', 0) > 0:
            fields.append({"title": "🟠 HIGH", "value": str(risk_summary['HIGH']), "short": True})
        if risk_summary.get('MEDIUM', 0) > 0:
            fields.append({"title": "🟡 MEDIUM", "value": str(risk_summary['MEDIUM']), "short": True})
        
        # Add new findings if any
        if new_critical:
            finding_text = ""
            for f in new_critical[:3]:
                finding_text += f"• *[{f.get('severity')}] {f.get('service')}*: {f.get('issue')[:60]}...\n"
            if len(new_critical) > 3:
                finding_text += f"*... and {len(new_critical) - 3} more*"
            
            fields.append({
                "title": f"🚨 New {len(new_critical)} Critical/High Finding(s)",
                "value": finding_text,
                "short": False
            })
        
        payload = {
            "attachments": [
                {
                    "color": color,
                    "title": f"🔒 AWS Security Scan - {status}",
                    "text": f"Security scan completed at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
                    "fields": fields,
                    "footer": "AI AWS CSPM",
                    "ts": int(datetime.now().timestamp())
                }
            ]
        }
        
        return payload
    
    def send_test_message(self) -> bool:
        """Send a test message to verify Slack integration."""
        test_payload = {
            "text": "🔒 *AI AWS CSPM Test Notification*\n\nYour Slack integration is working correctly! 🎉"
        }
        
        try:
            response = requests.post(self.webhook_url, json=test_payload, timeout=10)
            return response.status_code == 200
        except:
            return False