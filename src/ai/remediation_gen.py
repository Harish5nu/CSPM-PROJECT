# src/ai/remediation_gen.py
"""
Remediation Generator - Adds AI-powered fix suggestions to security findings.
"""

import sys
import os
import json
from typing import List, Dict, Any

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from src.ai.ai_client import AIClient

class RemediationGenerator:
    """
    Generates remediation suggestions for security findings using AI.
    """
    
    def __init__(self, use_ai: bool = True):
        """
        Initialize remediation generator.
        
        Args:
            use_ai: If True, use Ollama AI. If False, use fallback templates.
        """
        self.use_ai = use_ai
        self.ai_client = AIClient() if use_ai else None
        
        if use_ai:
            print("🤖 AI Remediation: ENABLED")
            if not self.ai_client.is_available():
                print("   ⚠️  Ollama not available - using fallback templates")
                self.use_ai = False
        else:
            print("📝 AI Remediation: DISABLED (using templates)")
    
    def add_remediation_to_finding(self, finding: Dict[str, Any]) -> Dict[str, Any]:
        """
        Add remediation to a single finding.
        
        Args:
            finding: Security finding dictionary
            
        Returns:
            Finding with remediation added
        """
        print(f"      DEBUG: Processing {finding.get('service')} - {finding.get('issue')[:30]}...")
        if self.use_ai and self.ai_client:
            return self.ai_client.generate_remediation(finding)
        else:
            return self._add_template_remediation(finding)
    
    def add_remediation_to_findings(self, findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Add remediation to multiple findings.
        
        Args:
            findings: List of security findings
            
        Returns:
            Findings with remediation added
        """
        print(f"\n🤖 Generating remediation for {len(findings)} finding(s)...")
        
        updated_findings = []
        for i, finding in enumerate(findings):
            # Show progress
            print(f"   [{i+1}/{len(findings)}] {finding['service']}: {finding['issue'][:50]}...")
            
            updated_finding = self.add_remediation_to_finding(finding)
            updated_findings.append(updated_finding)
        
        print(f"✅ Remediation complete for {len(updated_findings)} finding(s)")
        return updated_findings
    
    def _add_template_remediation(self, finding: Dict[str, Any]) -> Dict[str, Any]:
        """
        Add template-based remediation (no AI).
        """
        service = finding.get('service', 'unknown')
        issue = finding.get('issue', 'security issue')
        severity = finding.get('severity', 'MEDIUM')
        
        # Service-specific templates
        templates = {
            "S3": {
                "public_access": {
                    "cli": "aws s3api put-public-access-block --bucket {resource} --public-access-block-configuration BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true",
                    "terraform": """resource "aws_s3_bucket_public_access_block" "{resource}" {
  bucket = "{resource}"
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}"""
                },
                "encryption": {
                    "cli": "aws s3api put-bucket-encryption --bucket {resource} --server-side-encryption-configuration '{\"Rules\": [{\"ApplyServerSideEncryptionByDefault\": {\"SSEAlgorithm\": \"AES256\"}}]}'",
                    "terraform": """resource "aws_s3_bucket_server_side_encryption_configuration" "{resource}" {
  bucket = "{resource}"
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}"""
                }
            },
            "IAM": {
                "mfa": {
                    "cli": "aws iam create-virtual-mfa-device --virtual-mfa-device-name {resource}-mfa --outfile QRCode.png",
                    "terraform": "N/A - Requires user interaction"
                },
                "password_policy": {
                    "cli": "aws iam update-account-password-policy --minimum-password-length 14 --require-symbols --require-numbers --require-uppercase-characters --require-lowercase-characters --allow-users-to-change-password --max-password-age 90 --password-reuse-prevention 24",
                    "terraform": """resource "aws_iam_account_password_policy" "strict" {
  minimum_password_length        = 14
  require_lowercase_characters   = true
  require_numbers                = true
  require_uppercase_characters   = true
  require_symbols                = true
  allow_users_to_change_password = true
  max_password_age               = 90
  password_reuse_prevention      = 24
}"""
                }
            },
            "EC2": {
                "open_ssh": {
                    "cli": "aws ec2 revoke-security-group-ingress --group-id {group_id} --protocol tcp --port 22 --cidr 0.0.0.0/0",
                    "terraform": """resource "aws_security_group_rule" "restrict_ssh" {
  type              = "ingress"
  from_port         = 22
  to_port           = 22
  protocol          = "tcp"
  cidr_blocks       = ["YOUR_IP_ADDRESS/32"]  # Replace with your IP
  security_group_id = "{group_id}"
}"""
                }
            },
            "RDS": {
                "public_access": {
                    "cli": "aws rds modify-db-instance --db-instance-identifier {resource} --no-publicly-accessible --apply-immediately",
                    "terraform": "N/A - Must be set at creation time. Recreate database in private subnet."
                }
            }
        }
        
        # Find matching template
        template = None
        if service in templates:
            for key in templates[service]:
                if key.lower() in issue.lower():
                    template = templates[service][key]
                    break
        
        if not template:
            # Generic template
            template = {
                "cli": f"aws {service.lower()} update --security-configuration",
                "terraform": f"# Review {service} security configuration in Terraform"
            }
        
        # Format template with resource ID
        resource_id = finding.get('resource_id', 'resource')
        group_id = finding.get('details', {}).get('group_id', 'sg-xxxxxxxx')
        
        cli_command = template.get('cli', '').format(resource=resource_id, group_id=group_id)
        terraform_fix = template.get('terraform', '').format(resource=resource_id, group_id=group_id)
        
        finding['remediation'] = {
            "explanation": f"This {severity} severity issue in {service} needs attention: {issue}",
            "cli_command": cli_command,
            "terraform_fix": terraform_fix,
            "best_practice": f"Follow AWS security best practices for {service} to prevent {severity.lower()} risk findings.",
            "ai_generated": False
        }
        
        return finding
    
    def save_with_remediation(self, findings: List[Dict[str, Any]], output_file: str = "findings_with_remediation.json"):
        """
        Save findings with remediation to JSON file.
        
        Args:
            findings: List of findings with remediation
            output_file: Output filename
        """
        output = {
            "total_findings": len(findings),
            "findings": findings
        }
        
        # Ensure data directory exists
        os.makedirs("data", exist_ok=True)
        
        with open(f"data/{output_file}", "w") as f:
            json.dump(output, f, indent=2)
        
        print(f"\n💾 Remediated findings saved to data/{output_file}")