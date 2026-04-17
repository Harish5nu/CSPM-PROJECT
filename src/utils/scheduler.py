# src/utils/scheduler.py
"""
Scheduler Module - Handles automated scanning with cron/scheduler integration.
"""

import subprocess
import json
import os
from datetime import datetime
from typing import Dict, Any, List, Optional

class SecurityScheduler:
    """
    Manages scheduled security scans and compares results with previous scans.
    """
    
    def __init__(self, history_file: str = "data/scan_history.json"):
        self.history_file = history_file
        self.last_scan = self._get_last_scan()
    
    def _get_last_scan(self) -> Optional[Dict[str, Any]]:
        """Get the most recent scan from history."""
        if not os.path.exists(self.history_file):
            return None
        
        try:
            with open(self.history_file, 'r') as f:
                history = json.load(f)
                scans = history.get('scans', [])
                if scans:
                    return scans[0]  # Most recent first
        except:
            pass
        return None
    
    def run_scan(self) -> Dict[str, Any]:
        """
        Execute a security scan by running the main script.
        
        Returns:
            Dictionary with scan results and comparison to previous scan
        """
        print(f"[{datetime.now()}] Starting scheduled security scan...")
        
        try:
            # Run the main scanner
            result = subprocess.run(
                ['python', 'scripts/run_with_scoring.py'],
                capture_output=True,
                text=True,
                cwd=os.path.dirname(os.path.dirname(os.path.dirname(__file__)))
            )
            
            # Load the new scan results
            with open('data/full_assessment.json', 'r') as f:
                new_scan = json.load(f)
            
            # Compare with previous scan
            comparison = self._compare_scans(self.last_scan, new_scan)
            
            print(f"[{datetime.now()}] Scan completed. Found {new_scan.get('total_findings', 0)} issues.")
            
            return {
                'success': True,
                'scan': new_scan,
                'comparison': comparison,
                'timestamp': datetime.now().isoformat()
            }
            
        except Exception as e:
            print(f"[{datetime.now()}] Scan failed: {e}")
            return {
                'success': False,
                'error': str(e),
                'timestamp': datetime.now().isoformat()
            }
    
    def _compare_scans(self, old_scan: Optional[Dict], new_scan: Dict) -> Dict[str, Any]:
        """
        Compare two scans to identify new or resolved issues.
        
        Returns:
            Dictionary with new_findings, resolved_findings, score_change
        """
        if not old_scan:
            return {
                'new_findings': [],
                'resolved_findings': [],
                'score_change': 0,
                'is_first_scan': True
            }
        
        old_assessment = old_scan.get('security_assessment', {})
        new_assessment = new_scan.get('security_assessment', {})
        
        old_findings = old_scan.get('findings', [])
        new_findings = new_scan.get('findings', [])
        
        # Create sets for comparison (using issue + resource as key)
        old_keys = set([f"{f.get('service')}|{f.get('resource_id')}|{f.get('issue')}" for f in old_findings])
        new_keys = set([f"{f.get('service')}|{f.get('resource_id')}|{f.get('issue')}" for f in new_findings])
        
        new_finding_keys = new_keys - old_keys
        resolved_finding_keys = old_keys - new_keys
        
        # Get full finding objects for new findings
        new_findings_list = []
        for f in new_findings:
            key = f"{f.get('service')}|{f.get('resource_id')}|{f.get('issue')}"
            if key in new_finding_keys:
                new_findings_list.append(f)
        
        old_score = old_assessment.get('security_score', 0)
        new_score = new_assessment.get('security_score', 0)
        
        return {
            'new_findings': new_findings_list,
            'resolved_findings_count': len(resolved_finding_keys),
            'score_change': round(new_score - old_score, 1),
            'old_score': old_score,
            'new_score': new_score,
            'is_first_scan': False
        }
    
    def get_critical_changes(self, comparison: Dict) -> List[Dict]:
        """Extract only CRITICAL and HIGH new findings."""
        new_findings = comparison.get('new_findings', [])
        critical_high = []
        
        for finding in new_findings:
            severity = finding.get('severity', 'LOW')
            if severity in ['CRITICAL', 'HIGH']:
                critical_high.append(finding)
        
        return critical_high
    
    def should_alert(self, comparison: Dict) -> bool:
        """Determine if alerts should be sent."""
        # Alert if score dropped by more than 5 points
        if comparison.get('score_change', 0) <= -5:
            return True
        
        # Alert if new CRITICAL or HIGH findings
        if self.get_critical_changes(comparison):
            return True
        
        return False