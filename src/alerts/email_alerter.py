# src/alerts/email_alerter.py
"""
Email Alert System - Sends security scan results via email.
Supports SMTP (Gmail, Outlook, custom SMTP).
"""

import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime
import os
from typing import Dict, Any, List, Optional

class EmailAlerter:
    """
    Sends email notifications about security scan results.
    """
    
    def __init__(self):
        # Load email configuration from environment
        self.smtp_server = os.getenv('SMTP_SERVER', 'smtp.gmail.com')
        self.smtp_port = int(os.getenv('SMTP_PORT', '587'))
        self.sender_email = os.getenv('SENDER_EMAIL', '')
        self.sender_password = os.getenv('SENDER_PASSWORD', '')
        self.recipient_email = os.getenv('RECIPIENT_EMAIL', '')
        self.enabled = bool(self.sender_email and self.sender_password and self.recipient_email)
        
        if self.enabled:
            print("📧 Email alerts: ENABLED")
        else:
            print("📧 Email alerts: DISABLED (set SENDER_EMAIL, SENDER_PASSWORD, RECIPIENT_EMAIL in .env)")
    
    def send_alert(self, scan_result: Dict[str, Any], comparison: Dict[str, Any]) -> bool:
        """
        Send email alert about scan results.
        
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
        
        subject = self._generate_subject(comparison)
        body = self._generate_email_body(scan_result, comparison, new_critical)
        
        return self._send_email(subject, body)
    
    def _generate_subject(self, comparison: Dict) -> str:
        """Generate email subject line."""
        score_change = comparison.get('score_change', 0)
        new_findings_count = len(comparison.get('new_findings', []))
        
        if score_change < 0:
            return f"🔴 SECURITY ALERT: Score dropped by {abs(score_change)}% - {new_findings_count} new issues"
        elif new_findings_count > 0:
            return f"⚠️ AWS Security Alert: {new_findings_count} new issue(s) detected"
        else:
            return f"✅ AWS Security Report: Score {comparison.get('new_score', 0)}%"
    
    def _generate_email_body(self, scan_result: Dict, comparison: Dict, new_critical: List) -> str:
        """Generate HTML email body."""
        assessment = scan_result.get('security_assessment', {})
        risk_summary = assessment.get('risk_assessment', {}).get('risk_summary', {})
        
        html = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <style>
                body {{ font-family: Arial, sans-serif; }}
                .header {{ background: #2c3e50; color: white; padding: 20px; text-align: center; }}
                .score {{ font-size: 36px; font-weight: bold; }}
                .good {{ color: green; }}
                .bad {{ color: red; }}
                .finding {{ border-left: 4px solid #e74c3c; margin: 10px 0; padding: 10px; background: #f9f9f9; }}
                table {{ width: 100%; border-collapse: collapse; }}
                th, td {{ padding: 10px; text-align: left; border-bottom: 1px solid #ddd; }}
                th {{ background: #34495e; color: white; }}
            </style>
        </head>
        <body>
            <div class="header">
                <h1>🔒 AI AWS CSPM Security Report</h1>
                <p>{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
            </div>
            
            <div style="padding: 20px;">
                <h2>Security Score: <span class="{'good' if assessment.get('security_score', 0) >= 80 else 'bad'}">
                    {assessment.get('security_score', 0)}% ({assessment.get('grade', 'F')})
                </span></h2>
                
                <p>Previous score: {comparison.get('old_score', 'N/A')}% → New score: {comparison.get('new_score', 'N/A')}%</p>
                <p>Score change: {comparison.get('score_change', 0):+.1f}%</p>
        """
        
        if new_critical:
            html += """
                <div style="background: #ffeeee; padding: 15px; border-left: 4px solid #e74c3c; margin: 20px 0;">
                    <h3 style="color: #e74c3c;">🚨 NEW CRITICAL/HIGH FINDINGS</h3>
            """
            for finding in new_critical[:5]:
                html += f"""
                    <div class="finding">
                        <strong>[{finding.get('severity')}] {finding.get('service')}</strong><br>
                        {finding.get('issue')}<br>
                        <strong>Resource:</strong> {finding.get('resource_id')}<br>
                        <strong>Fix:</strong> {finding.get('remediation', {}).get('cli_command', 'No fix available')[:100]}...
                    </div>
                """
            html += "</div>"
        
        html += f"""
                <h3>Summary</h3>
                <table>
                    <tr><th>Severity</th><th>Count</th></tr>
                    <tr><td>🔴 CRITICAL</td><td>{risk_summary.get('CRITICAL', 0)}</td></tr>
                    <tr><td>🟠 HIGH</td><td>{risk_summary.get('HIGH', 0)}</td></tr>
                    <tr><td>🟡 MEDIUM</td><td>{risk_summary.get('MEDIUM', 0)}</td></tr>
                    <tr><td>🔵 LOW</td><td>{risk_summary.get('LOW', 0)}</td></tr>
                </table>
                
                <h3>Remediation Actions</h3>
                <p>To fix these issues:</p>
                <ol>
                    <li>Run: <code>streamlit run dashboard/app.py</code></li>
                    <li>Go to "AI Remediation" page</li>
                    <li>Copy and run the provided CLI commands</li>
                </ol>
                
                <hr>
                <p style="font-size: 12px; color: gray;">This is an automated message from AI AWS CSPM.</p>
            </div>
        </body>
        </html>
        """
        
        return html
    
    def _send_email(self, subject: str, body: str) -> bool:
        """Send the email via SMTP."""
        try:
            msg = MIMEMultipart()
            msg['From'] = self.sender_email
            msg['To'] = self.recipient_email
            msg['Subject'] = subject
            
            msg.attach(MIMEText(body, 'html'))
            
            with smtplib.SMTP(self.smtp_server, self.smtp_port) as server:
                server.starttls()
                server.login(self.sender_email, self.sender_password)
                server.send_message(msg)
            
            print(f"📧 Email alert sent to {self.recipient_email}")
            return True
            
        except Exception as e:
            print(f"❌ Failed to send email: {e}")
            return False