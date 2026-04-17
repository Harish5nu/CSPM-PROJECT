# scripts/run_with_ai.py
"""
Unified scanner with AI remediation.
Runs all collectors, then adds AI-powered remediation suggestions.
"""

import sys
import os
import json
from datetime import datetime

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Import collectors
from src.collectors.s3_collector import S3Collector
from src.collectors.iam_collector import IAMCollector
from src.collectors.ec2_collector import EC2Collector
from src.collectors.rds_collector import RDSCollector

# Import AI remediation
from src.ai.remediation_gen import RemediationGenerator

def run_scan_with_ai(use_real_ai: bool = True):
    """
    Run all scanners and add AI remediation.
    
    Args:
        use_real_ai: If True, use Ollama AI. If False, use templates.
    """
    print("=" * 60)
    print("🚀 AI AWS CSPM - Security Scan with AI Remediation")
    print("=" * 60)
    print(f"Scan started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"AI Mode: {'Ollama (Real AI)' if use_real_ai else 'Templates (Fallback)'}")
    print("=" * 60)
    
    all_findings = []
    
    # Run all collectors
    print("\n📡 COLLECTING DATA...")
    print("-" * 40)
    
    collectors = [
        ("S3", S3Collector()),
        ("IAM", IAMCollector()),
        ("EC2", EC2Collector()),
        ("RDS", RDSCollector())
    ]
    
    for name, collector in collectors:
        print(f"\n[{name}]")
        findings = collector.collect()
        all_findings.extend(findings)
    
    print("\n" + "=" * 60)
    print(f"📊 Found {len(all_findings)} security issue(s)")
    print("=" * 60)
    
    if len(all_findings) == 0:
        print("\n🎉 No issues found! Your AWS account is secure!")
        return
    
    # Add AI remediation
    print("\n🤖 GENERATING AI REMEDIATION...")
    print("-" * 40)
    
    remediator = RemediationGenerator(use_ai=use_real_ai)
    remediated_findings = remediator.add_remediation_to_findings(all_findings)
    
    # Save results
    output = {
        "scan_time": datetime.now().isoformat(),
        "ai_used": use_real_ai and remediator.use_ai,
        "total_findings": len(remediated_findings),
        "findings": remediated_findings
    }
    
    # Save to file
    os.makedirs("data", exist_ok=True)
    with open("data/scan_with_ai.json", "w") as f:
        json.dump(output, f, indent=2)
    
    # Print summary with remediation preview
    print("\n" + "=" * 60)
    print("📋 FINDINGS WITH REMEDIATION")
    print("=" * 60)
    
    for i, finding in enumerate(remediated_findings[:5]):  # Show first 5
        print(f"\n[{i+1}] {finding['severity']} - {finding['service']}: {finding['issue']}")
        remediation = finding.get('remediation', {})
        print(f"    🔧 Fix: {remediation.get('cli_command', 'N/A')[:80]}...")
    
    if len(remediated_findings) > 5:
        print(f"\n... and {len(remediated_findings) - 5} more findings")
    
    print("\n" + "=" * 60)
    print(f"💾 Full results with remediation saved to: data/scan_with_ai.json")
    print("=" * 60)
    
    # Show AI status
    ai_count = sum(1 for f in remediated_findings if f.get('remediation', {}).get('ai_generated', False))
    print(f"\n📊 AI Stats: {ai_count}/{len(remediated_findings)} findings have AI-generated remediation")
    
    return remediated_findings

def main():
    import argparse
    
    parser = argparse.ArgumentParser(description='AWS Security Scanner with AI Remediation')
    parser.add_argument('--no-ai', action='store_true', help='Disable AI, use templates only')
    parser.add_argument('--force-ai', action='store_true', help='Force AI even if Ollama not detected')
    
    args = parser.parse_args()
    
    use_ai = not args.no_ai
    
    try:
        findings = run_scan_with_ai(use_real_ai=use_ai)
    except KeyboardInterrupt:
        print("\n\n⚠️  Scan interrupted by user")
    except Exception as e:
        print(f"\n❌ Error: {e}")
        print("\nTroubleshooting:")
        print("1. For AI: Make sure Ollama is running (ollama serve)")
        print("2. Run with --no-ai to use templates instead")

if __name__ == "__main__":
    main()