# src/ai/security_score.py
"""
Security Score Calculator - Unified scoring combining risk and compliance.
"""

from typing import Dict, Any, List
from src.ai.risk_scorer import RiskScorer
from src.ai.compliance_mapper import ComplianceMapper

class SecurityScoreCalculator:
    """
    Calculates overall security score combining risk and compliance.
    """
    
    def __init__(self):
        self.risk_scorer = RiskScorer()
        self.compliance_mapper = ComplianceMapper()
    
    def calculate_full_score(self, findings: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Calculate complete security score with risk and compliance.
        
        Args:
            findings: List of security findings
            
        Returns:
            Complete security assessment
        """
        # Calculate risk score
        risk_assessment = self.risk_scorer.calculate_overall_score(findings)
        
        # Calculate compliance report
        compliance_report = self.compliance_mapper.generate_compliance_report(findings)
        
        # Combine scores (70% risk, 30% compliance)
        risk_score = risk_assessment['overall_score']
        compliance_score = compliance_report['overall_compliance_score']
        
        combined_score = (risk_score * 0.7) + (compliance_score * 0.3)
        
        # Get scored findings
        scored_findings = risk_assessment.get('scored_findings', [])
        
        # Map compliance to findings
        for finding in scored_findings:
            # Add compliance info to each finding
            comp_info = self.compliance_mapper.map_finding(finding.copy())
            finding['compliance'] = comp_info.get('compliance', {})
        
        return {
            "security_score": round(combined_score, 1),
            "risk_score": risk_score,
            "compliance_score": compliance_score,
            "grade": self._get_grade(combined_score),
            "risk_assessment": risk_assessment,
            "compliance_report": compliance_report,
            "findings_with_scores": scored_findings,
            "summary": self._generate_summary(risk_assessment, compliance_report, combined_score)
        }
    
    def _get_grade(self, score: float) -> str:
        """Convert score to letter grade."""
        if score >= 95:
            return "A+"
        elif score >= 90:
            return "A"
        elif score >= 80:
            return "B"
        elif score >= 70:
            return "C"
        elif score >= 60:
            return "D"
        else:
            return "F"
    
    def _generate_summary(self, risk: Dict, compliance: Dict, combined: float) -> str:
        """Generate human-readable summary."""
        critical = risk['risk_summary'].get('CRITICAL', 0)
        high = risk['risk_summary'].get('HIGH', 0)
        
        if combined >= 90:
            return f"Excellent security posture! Score: {combined}% (Grade A). {critical} critical, {high} high severity issues."
        elif combined >= 80:
            return f"Good security posture. Score: {combined}% (Grade B). Address {critical} critical, {high} high issues for better score."
        elif combined >= 70:
            return f"Average security posture. Score: {combined}% (Grade C). {critical} critical issues need immediate attention."
        elif combined >= 60:
            return f"Below average security posture. Score: {combined}% (Grade D). Significant improvements required."
        else:
            return f"Poor security posture. Score: {combined}% (Grade F). Immediate action required on {critical} critical issues."