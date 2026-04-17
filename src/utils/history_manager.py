# src/utils/history_manager.py
"""
History Manager - Tracks security scores over time for trend analysis.
"""

import json
import os
from datetime import datetime
from typing import Dict, Any, List, Optional

class HistoryManager:
    """
    Manages historical scan data for trend analysis.
    """
    
    def __init__(self, history_file: str = "data/scan_history.json"):
        self.history_file = history_file
        self._ensure_history_file()
    
    def _ensure_history_file(self):
        """Create history file if it doesn't exist."""
        if not os.path.exists(self.history_file):
            os.makedirs(os.path.dirname(self.history_file), exist_ok=True)
            with open(self.history_file, 'w') as f:
                json.dump({"scans": []}, f, indent=2)
    
    def save_scan(self, assessment: Dict[str, Any]) -> None:
        """
        Save a scan result to history.
        
        Args:
            assessment: Full security assessment dictionary
        """
        # Load existing history
        with open(self.history_file, 'r') as f:
            history = json.load(f)
        
        # Extract key metrics
        scan_record = {
            "scan_time": assessment.get('scan_time', datetime.now().isoformat()),
            "security_score": assessment.get('security_assessment', {}).get('security_score', 0),
            "risk_score": assessment.get('security_assessment', {}).get('risk_score', 0),
            "compliance_score": assessment.get('security_assessment', {}).get('compliance_score', 0),
            "grade": assessment.get('security_assessment', {}).get('grade', 'F'),
            "total_findings": assessment.get('total_findings', 0),
            "risk_summary": assessment.get('security_assessment', {}).get('risk_assessment', {}).get('risk_summary', {}),
            "compliance_by_framework": assessment.get('security_assessment', {}).get('compliance_report', {}).get('compliance_by_framework', {})
        }
        
        # Add to history (prepend - newest first)
        history["scans"].insert(0, scan_record)
        
        # Keep last 50 scans
        history["scans"] = history["scans"][:50]
        
        # Save back
        with open(self.history_file, 'w') as f:
            json.dump(history, f, indent=2)
        
        print(f"✅ Scan saved to history: {scan_record['scan_time']}")
    
    def get_history(self, limit: int = 30) -> List[Dict[str, Any]]:
        """
        Get historical scan data.
        
        Args:
            limit: Maximum number of scans to return
            
        Returns:
            List of historical scan records
        """
        with open(self.history_file, 'r') as f:
            history = json.load(f)
        
        return history["scans"][:limit]
    
    def get_score_trend(self) -> Dict[str, List]:
        """
        Get trend data for charts.
        
        Returns:
            Dictionary with dates and scores
        """
        history = self.get_history(limit=30)
        
        # Reverse to show chronological order (oldest to newest)
        history.reverse()
        
        dates = []
        security_scores = []
        risk_scores = []
        compliance_scores = []
        
        for scan in history:
            dates.append(scan['scan_time'][:10])  # YYYY-MM-DD only
            security_scores.append(scan['security_score'])
            risk_scores.append(scan['risk_score'])
            compliance_scores.append(scan['compliance_score'])
        
        return {
            "dates": dates,
            "security_scores": security_scores,
            "risk_scores": risk_scores,
            "compliance_scores": compliance_scores
        }
    
    def get_compliance_trend(self, framework: str) -> Dict[str, List]:
        """
        Get trend data for a specific compliance framework.
        
        Args:
            framework: Framework name (cis, nist, gdpr, hipaa, pci, sox)
            
        Returns:
            Dictionary with dates and compliance scores
        """
        history = self.get_history(limit=30)
        history.reverse()
        
        dates = []
        scores = []
        
        for scan in history:
            compliance = scan.get('compliance_by_framework', {})
            if framework in compliance:
                dates.append(scan['scan_time'][:10])
                scores.append(compliance[framework])
        
        return {"dates": dates, "scores": scores}