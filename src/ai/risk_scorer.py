# src/ai/risk_scorer.py
"""
Risk Scoring Engine - Calculates security scores for AWS resources.
Based on severity, service criticality, and exploitability.
"""

from typing import Dict, Any, List, Tuple

class RiskScorer:
    """
    Calculates risk scores for security findings and overall security posture.
    Score range: 0 (worst) to 100 (best/secure)
    """
    
    # Base weights for different severities
    SEVERITY_WEIGHTS = {
        "CRITICAL": 10.0,
        "HIGH": 5.0,
        "MEDIUM": 2.0,
        "LOW": 0.5
    }
    
    # Service criticality multipliers (how important is this service)
    SERVICE_MULTIPLIERS = {
        "IAM": 2.0,      # Identity is most critical
        "S3": 1.5,       # Data storage
        "RDS": 1.5,      # Databases
        "EC2": 1.2,      # Compute
        "default": 1.0
    }
    
    # Exploitability score (how easy to exploit)
    EXPLOITABILITY = {
        "public_access": 10,
        "open_ssh": 9,
        "no_mfa": 8,
        "admin_access": 8,
        "no_encryption": 7,
        "no_password_policy": 6,
        "old_keys": 5,
        "unused_users": 3,
        "no_versioning": 3,
        "no_logging": 2,
        "default": 5
    }
    
    def __init__(self):
        self.total_possible_score = 100
    
    def calculate_finding_score(self, finding: Dict[str, Any]) -> Dict[str, Any]:
        """
        Calculate risk score for a single finding.
        
        Args:
            finding: Security finding dictionary
            
        Returns:
            Finding with score added
        """
        severity = finding.get('severity', 'MEDIUM')
        service = finding.get('service', 'default')
        issue = finding.get('issue', '').lower()
        
        # Get base weight from severity
        base_weight = self.SEVERITY_WEIGHTS.get(severity, 2.0)
        
        # Apply service multiplier
        service_mult = self.SERVICE_MULTIPLIERS.get(service, 1.0)
        
        # Get exploitability score
        exploit_score = 5  # default
        for key, score in self.EXPLOITABILITY.items():
            if key in issue:
                exploit_score = score
                break
        
        # Calculate final risk contribution
        risk_contribution = base_weight * service_mult * (exploit_score / 10)
        
        # Cap at 10 per finding
        risk_contribution = min(risk_contribution, 10)
        
        # Add to finding
        finding['risk_score'] = round(risk_contribution, 2)
        finding['risk_factors'] = {
            "severity_weight": base_weight,
            "service_multiplier": service_mult,
            "exploitability_score": exploit_score
        }
        
        return finding
    
    def calculate_overall_score(self, findings: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Calculate overall security score for the entire account.
        
        Args:
            findings: List of all security findings
            
        Returns:
            Dictionary with overall score and breakdown
        """
        if not findings:
            return {
                "overall_score": 100,
                "grade": "A+",
                "total_findings": 0,
                "risk_summary": {
                    "CRITICAL": 0,
                    "HIGH": 0,
                    "MEDIUM": 0,
                    "LOW": 0
                },
                "message": "Perfect! No security issues found."
            }
        
        # Calculate individual finding scores
        scored_findings = [self.calculate_finding_score(f) for f in findings]
        
        # Sum up risk
        total_risk = sum(f.get('risk_score', 0) for f in scored_findings)
        
        # Cap maximum risk at 100
        total_risk = min(total_risk, 100)
        
        # Calculate overall score (100 - risk)
        overall_score = max(0, 100 - total_risk)
        
        # Determine letter grade
        if overall_score >= 95:
            grade = "A+"
        elif overall_score >= 90:
            grade = "A"
        elif overall_score >= 80:
            grade = "B"
        elif overall_score >= 70:
            grade = "C"
        elif overall_score >= 60:
            grade = "D"
        else:
            grade = "F"
        
        # Count by severity
        severity_counts = {
            "CRITICAL": 0,
            "HIGH": 0,
            "MEDIUM": 0,
            "LOW": 0
        }
        
        for f in findings:
            severity = f.get('severity', 'MEDIUM')
            if severity in severity_counts:
                severity_counts[severity] += 1
        
        # Calculate risk by service
        risk_by_service = {}
        for f in scored_findings:
            service = f.get('service', 'unknown')
            risk_by_service[service] = risk_by_service.get(service, 0) + f.get('risk_score', 0)
        
        # Generate recommendations
        recommendations = self._generate_recommendations(severity_counts, overall_score)
        
        return {
            "overall_score": round(overall_score, 1),
            "grade": grade,
            "total_findings": len(findings),
            "total_risk": round(total_risk, 1),
            "risk_summary": severity_counts,
            "risk_by_service": risk_by_service,
            "scored_findings": scored_findings,
            "recommendations": recommendations,
            "message": self._get_score_message(overall_score, severity_counts)
        }
    
    def _generate_recommendations(self, severity_counts: Dict[str, int], score: float) -> List[str]:
        """
        Generate prioritized recommendations based on findings.
        """
        recommendations = []
        
        if severity_counts.get('CRITICAL', 0) > 0:
            recommendations.append(f"🔴 CRITICAL: Fix {severity_counts['CRITICAL']} critical issue(s) immediately")
        
        if severity_counts.get('HIGH', 0) > 0:
            recommendations.append(f"🟠 HIGH: Address {severity_counts['HIGH']} high severity issue(s) this week")
        
        if score < 70:
            recommendations.append("📊 Your security score is below average. Prioritize critical and high findings.")
        
        if severity_counts.get('CRITICAL', 0) == 0 and severity_counts.get('HIGH', 0) == 0 and score < 90:
            recommendations.append("✅ Good progress! Focus on medium severity issues to reach A grade.")
        
        if score >= 90:
            recommendations.append("🎉 Excellent security posture! Maintain with regular scans.")
        
        if not recommendations:
            recommendations.append("✅ No immediate recommendations. Keep up the good work!")
        
        return recommendations
    
    def _get_score_message(self, score: float, severity_counts: Dict[str, int]) -> str:
        """
        Get a human-readable message about the score.
        """
        if score == 100:
            return "Perfect security posture! No issues detected."
        elif score >= 90:
            return "Excellent security posture. Minor improvements available."
        elif score >= 80:
            return "Good security posture. Address high severity issues for better score."
        elif score >= 70:
            return "Average security posture. Several improvements needed."
        elif score >= 60:
            return "Below average security posture. Significant improvements required."
        else:
            return "Poor security posture. Immediate action required on critical issues."