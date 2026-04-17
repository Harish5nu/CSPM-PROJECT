# src/ai/compliance_mapper.py
"""
Compliance Mapper - Maps security findings to compliance frameworks.
Supports: CIS Benchmarks, NIST 800-53, GDPR, HIPAA (basic)
"""

from typing import Dict, Any, List, Tuple

class ComplianceMapper:
    """
    Maps security findings to compliance framework requirements.
    """
    
    # Mapping of issue patterns to compliance controls
    COMPLIANCE_MAPPINGS = {
        # CIS AWS Benchmarks (v3.0)
        "password_policy": {
            "cis": "1.1 - Ensure IAM password policy meets minimum requirements",
            "nist": "AC-7 - Unsuccessful Logon Attempts",
            "gdpr": "Article 32 - Security of Processing"
        },
        "mfa": {
            "cis": "1.2 - Ensure MFA is enabled for all IAM users",
            "nist": "IA-2 - Identification and Authentication",
            "gdpr": "Article 5 - Lawfulness, fairness and transparency"
        },
        "admin_access": {
            "cis": "1.5 - Ensure least privilege principle is followed",
            "nist": "AC-6 - Least Privilege",
            "sox": "Access Control"
        },
        "public_access": {
            "cis": "2.1.1 - Ensure S3 block public access is enabled",
            "nist": "AC-3 - Access Enforcement",
            "gdpr": "Article 32 - Security of Processing"
        },
        "encryption": {
            "cis": "2.2.1 - Ensure default encryption is enabled",
            "nist": "SC-13 - Cryptographic Protection",
            "gdpr": "Article 32 - Security of Processing"
        },
        "versioning": {
            "cis": "2.1.2 - Ensure S3 versioning is enabled",
            "nist": "AU-11 - Audit Record Retention",
            "hipaa": "164.312 - Audit Controls"
        },
        "logging": {
            "cis": "2.1.3 - Ensure S3 bucket logging is enabled",
            "nist": "AU-2 - Audit Events",
            "gdpr": "Article 30 - Records of Processing"
        },
        "open_ssh": {
            "cis": "4.1 - Ensure no security groups allow unrestricted SSH access",
            "nist": "AC-3 - Access Enforcement",
            "pci": "Requirement 1.2.1"
        },
        "backup_retention": {
            "cis": "3.1 - Ensure backup retention meets requirements",
            "nist": "CP-9 - System Backup",
            "gdpr": "Article 32 - Security of Processing"
        },
        "old_keys": {
            "cis": "1.4 - Ensure access keys are rotated every 90 days",
            "nist": "IA-5 - Authenticator Management",
            "sox": "Access Management"
        }
    }
    
    def __init__(self):
        self.frameworks = ["cis", "nist", "gdpr", "hipaa", "pci", "sox"]
    
    def map_finding(self, finding: Dict[str, Any]) -> Dict[str, Any]:
        """
        Map a single finding to compliance frameworks.
        
        Args:
            finding: Security finding dictionary
            
        Returns:
            Finding with compliance mapping added
        """
        issue = finding.get('issue', '').lower()
        service = finding.get('service', '').lower()
        
        # Find matching compliance rule
        matched_controls = []
        
        for pattern, controls in self.COMPLIANCE_MAPPINGS.items():
            if pattern in issue or pattern in service:
                matched_controls.append(controls)
        
        # If no specific match, provide generic guidance
        if not matched_controls:
            matched_controls = [{
                "cis": "Review AWS Well-Architected Framework",
                "nist": "Review NIST 800-53 controls",
                "gdpr": "Review GDPR compliance requirements"
            }]
        
        # Get the best match (first one)
        controls = matched_controls[0]
        
        # Add to finding
        finding['compliance'] = {
            "cis": controls.get("cis", "Not mapped"),
            "nist": controls.get("nist", "Not mapped"),
            "gdpr": controls.get("gdpr", "Not applicable"),
            "hipaa": controls.get("hipaa", "Not applicable"),
            "pci": controls.get("pci", "Not applicable"),
            "sox": controls.get("sox", "Not applicable")
        }
        
        return finding
    
    def generate_compliance_report(self, findings: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Generate a full compliance report from all findings.
        
        Args:
            findings: List of security findings
            
        Returns:
            Compliance report dictionary
        """
        # Map all findings
        mapped_findings = [self.map_finding(f.copy()) for f in findings]
        
        # Track compliance status by framework
        compliance_status = {
            "cis": {"passed": 0, "failed": 0, "total": 0},
            "nist": {"passed": 0, "failed": 0, "total": 0},
            "gdpr": {"passed": 0, "failed": 0, "total": 0},
            "hipaa": {"passed": 0, "failed": 0, "total": 0},
            "pci": {"passed": 0, "failed": 0, "total": 0},
            "sox": {"passed": 0, "failed": 0, "total": 0}
        }
        
        # Track failed controls
        failed_controls = {
            "cis": [],
            "nist": [],
            "gdpr": [],
            "hipaa": [],
            "pci": [],
            "sox": []
        }
        
        for finding in mapped_findings:
            comp = finding.get('compliance', {})
            for framework in self.frameworks:
                control = comp.get(framework, "")
                if control and control != "Not mapped" and control != "Not applicable":
                    compliance_status[framework]["total"] += 1
                    # If finding has severity HIGH or CRITICAL, consider it failing
                    if finding.get('severity') in ['CRITICAL', 'HIGH']:
                        compliance_status[framework]["failed"] += 1
                        failed_controls[framework].append({
                            "finding": finding.get('issue'),
                            "control": control,
                            "severity": finding.get('severity')
                        })
                    else:
                        compliance_status[framework]["passed"] += 1
        
        # Calculate compliance percentages
        compliance_percentages = {}
        for framework, status in compliance_status.items():
            total = status["total"]
            if total > 0:
                passed = status["passed"]
                compliance_percentages[framework] = round((passed / total) * 100, 1)
            else:
                compliance_percentages[framework] = 100.0  # No controls to check
        
        # Determine overall compliance readiness
        overall_compliance = sum(compliance_percentages.values()) / len(self.frameworks)
        
        return {
            "overall_compliance_score": round(overall_compliance, 1),
            "compliance_by_framework": compliance_percentages,
            "compliance_status": compliance_status,
            "failed_controls": failed_controls,
            "mapped_findings": mapped_findings,
            "recommendations": self._generate_compliance_recommendations(failed_controls)
        }
    
    def _generate_compliance_recommendations(self, failed_controls: Dict[str, List]) -> List[str]:
        """
        Generate compliance-specific recommendations.
        """
        recommendations = []
        
        for framework, controls in failed_controls.items():
            if controls:
                framework_name = framework.upper()
                control_count = len(controls)
                recommendations.append(f"📋 {framework_name}: {control_count} control(s) need attention")
                
                # Add specific top failures (max 3)
                for ctrl in controls[:3]:
                    recommendations.append(f"   - {ctrl['control']}: {ctrl['finding'][:60]}...")
        
        if not recommendations:
            recommendations.append("✅ All compliance checks passed!")
        
        return recommendations