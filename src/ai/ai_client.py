# src/ai/ai_client.py
"""
AI Client for Ollama - Handles communication with local LLM.
Generates remediation suggestions for security findings.
"""

import requests
import json
from typing import Dict, Any, Optional

class AIClient:
    """
    Client for interacting with Ollama local LLM.
    """
    
    def __init__(self, model: str = "llama3.2:1b", base_url: str = "http://localhost:11434"):
        """
        Initialize AI client.
        
        Args:
            model: Ollama model name (llama3.2:1b is small and fast)
            base_url: Ollama API endpoint
        """
        self.model = model
        self.base_url = base_url
        self.api_url = f"{base_url}/api/generate"
        
    def is_available(self) -> bool:
        """
        Check if Ollama is running and model is available.
        
        Returns:
            True if AI is ready, False otherwise
        """
        try:
            response = requests.get(f"{self.base_url}/api/tags", timeout=5)
            if response.status_code == 200:
                models = response.json().get('models', [])
                for m in models:
                    if m.get('name', '').startswith(self.model):
                        return True
                print(f"⚠️  Model {self.model} not found. Run: ollama pull {self.model}")
                return False
            return False
        except requests.exceptions.ConnectionError:
            print("⚠️  Ollama not running. Start with: ollama serve")
            return False
    
    def generate_remediation(self, finding: Dict[str, Any]) -> Dict[str, Any]:
        """
        Generate remediation suggestion for a security finding.
        
        Args:
            finding: Dictionary containing finding details (service, issue, severity, etc.)
            
        Returns:
            Finding dictionary with remediation added
        """
        if not self.is_available():
            # Return finding with fallback remediation
            finding['remediation'] = self._get_fallback_remediation(finding)
            finding['ai_generated'] = False
            return finding
        
        # Build prompt for the AI
        prompt = self._build_prompt(finding)
        
        try:
            # Call Ollama API
            response = requests.post(
                self.api_url,
                json={
                    "model": self.model,
                    "prompt": prompt,
                    "stream": False,
                    "options": {
                        "temperature": 0.3,  # Lower = more focused, less creative
                        "max_tokens": 500
                    }
                },
                timeout=30
            )
            
            if response.status_code == 200:
                result = response.json()
                remediation_text = result.get('response', '').strip()
                
                # Parse AI response into structured format
                finding['remediation'] = self._parse_ai_response(remediation_text, finding)
                finding['ai_generated'] = True
            else:
                finding['remediation'] = self._get_fallback_remediation(finding)
                finding['ai_generated'] = False
                
        except Exception as e:
            print(f"      ⚠️  AI error: {e}")
            finding['remediation'] = self._get_fallback_remediation(finding)
            finding['ai_generated'] = False
        
        return finding
    
    def _build_prompt(self, finding: Dict[str, Any]) -> str:
        """
        Build prompt for the AI based on finding type.
        """
        service = finding.get('service', 'unknown')
        issue = finding.get('issue', 'unknown issue')
        severity = finding.get('severity', 'MEDIUM')
        details = finding.get('details', {})
        
        prompt = f"""You are an AWS security expert. Give remediation advice for this finding.

Service: {service}
Issue: {issue}
Severity: {severity}
Context: {json.dumps(details, indent=2)}

Provide response in this EXACT format:

[EXPLANATION]
One sentence explaining why this is a problem.

[CLI FIX]
The exact AWS CLI command to fix it.

[TERRAFORM FIX]
The Terraform code to fix it (if applicable, otherwise write "N/A").

[BEST PRACTICE]
One sentence about the security best practice.

Keep responses concise and practical. Only include the sections above, nothing else."""
        
        return prompt
    
    def _parse_ai_response(self, response_text: str, finding: Dict[str, Any]) -> Dict[str, Any]:
        """
        Parse AI response into structured remediation format.
        """
        remediation = {
            "explanation": "",
            "cli_command": "",
            "terraform_fix": "",
            "best_practice": "",
            "raw_response": response_text
        }
        
        # Extract sections
        if "[EXPLANATION]" in response_text:
            parts = response_text.split("[EXPLANATION]")
            if len(parts) > 1:
                rest = parts[1]
                if "[CLI FIX]" in rest:
                    remediation["explanation"] = rest.split("[CLI FIX]")[0].strip()
                    rest = rest.split("[CLI FIX]")[1]
                    if "[TERRAFORM FIX]" in rest:
                        remediation["cli_command"] = rest.split("[TERRAFORM FIX]")[0].strip()
                        rest = rest.split("[TERRAFORM FIX]")[1]
                        if "[BEST PRACTICE]" in rest:
                            remediation["terraform_fix"] = rest.split("[BEST PRACTICE]")[0].strip()
                            remediation["best_practice"] = rest.split("[BEST PRACTICE]")[1].strip()
        
        # Clean up
        for key in remediation:
            if not remediation[key]:
                remediation[key] = self._get_fallback_for_field(key, finding)
        
        return remediation
    
    def _get_fallback_for_field(self, field: str, finding: Dict[str, Any]) -> str:
        """
        Get fallback text for a specific remediation field.
        """
        service = finding.get('service', 'AWS')
        resource = finding.get('resource_id', 'resource')
        
        fallbacks = {
            "explanation": f"This {service} configuration does not follow security best practices and could lead to data exposure or unauthorized access.",
            "cli_command": f"aws {service.lower()} update --{resource} --secure-configuration",
            "terraform_fix": "N/A - Use AWS Console or CLI",
            "best_practice": f"Always follow the principle of least privilege and enable encryption by default for {service}."
        }
        
        return fallbacks.get(field, "Review AWS security best practices for this service.")
    
    def _get_fallback_remediation(self, finding: Dict[str, Any]) -> Dict[str, Any]:
        """
        Generate fallback remediation when AI is unavailable.
        """
        service = finding.get('service', 'AWS')
        issue = finding.get('issue', 'security issue')
        
        return {
            "explanation": f"This {service} security issue needs attention: {issue}",
            "cli_command": f"aws {service.lower()} describe-{finding.get('resource_id', 'resource')} --query 'SecurityConfiguration'",
            "terraform_fix": "N/A - AI service unavailable. Please review manually.",
            "best_practice": f"Follow AWS Well-Architected Framework security pillar for {service}.",
            "raw_response": "AI fallback - Ollama not available"
        }