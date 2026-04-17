# scripts/run_with_scoring.py
"""
Full security scanner with AI remediation, risk scoring, and compliance mapping.
"""

import sys
import os
import json
from datetime import datetime

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.collectors.s3_collector import S3Collector
from src.collectors.iam_collector import IAMCollector
from src.collectors.ec2_collector import EC2Collector
from src.collectors.rds_collector import RDSCollector
from src.ai.remediation_gen import RemediationGenerator
from src.ai.security_score import SecurityScoreCalculator

def run_full_scan():
    """
    Run complete security scan with AI, scoring, and compliance.
    """
    print("=" * 70)
    print("🔒 AI AWS CSPM - Complete Security Assessment")
    print("=" * 70)
    print(f"Scan started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("=" * 70)
    
    all_findings = []
    
    # Run collectors
    print("\n📡 STEP 1: Collecting AWS Configuration Data")
    print("-" * 50)
    
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
    
    print("\n" + "=" * 70)
    print(f"📊 Found {len(all_findings)} security issue(s)")
    print("=" * 70)
    
    if len(all_findings) > 0:
        # Add AI remediation
        print("\n🤖 STEP 2: Generating AI Remediation")
        print("-" * 50)
        
        remediator = RemediationGenerator(use_ai=True)
        remediated_findings = remediator.add_remediation_to_findings(all_findings)
        
        # Calculate security scores
        print("\n📈 STEP 3: Calculating Security Scores")
        print("-" * 50)
        
        calculator = SecurityScoreCalculator()
        assessment = calculator.calculate_full_score(remediated_findings)
        
        # Display scores
        print(f"\n   🎯 Security Score: {assessment['security_score']}%")
        print(f"   📝 Grade: {assessment['grade']}")
        print(f"   ⚠️  Risk Score: {assessment['risk_score']}%")
        print(f"   📋 Compliance Score: {assessment['compliance_score']}%")
        
        # Display risk summary
        risk_summary = assessment['risk_assessment']['risk_summary']
        print(f"\n   🔴 CRITICAL: {risk_summary['CRITICAL']}")
        print(f"   🟠 HIGH: {risk_summary['HIGH']}")
        print(f"   🟡 MEDIUM: {risk_summary['MEDIUM']}")
        print(f"   🔵 LOW: {risk_summary['LOW']}")
        
        # Display top recommendations
        print("\n📋 STEP 4: Recommendations")
        print("-" * 50)
        for rec in assessment['risk_assessment']['recommendations'][:3]:
            print(f"   {rec}")
        
        # Display compliance summary
        print("\n📜 STEP 5: Compliance Summary")
        print("-" * 50)
        compliance = assessment['compliance_report']['compliance_by_framework']
        for framework, score in compliance.items():
            bar = "█" * int(score / 10) + "░" * (10 - int(score / 10))
            print(f"   {framework.upper():6} [{bar}] {score}%")
        
        # Save results
        output = {
            "scan_time": datetime.now().isoformat(),
            "total_findings": len(remediated_findings),
            "security_assessment": assessment,
            "findings": remediated_findings
        }
        
        os.makedirs("data", exist_ok=True)
        with open("data/full_assessment.json", "w") as f:
            json.dump(output, f, indent=2)
        
        print("\n" + "=" * 70)
        print(f"💾 Complete assessment saved to: data/full_assessment.json")
        print("=" * 70)
        
        # Final verdict
        print("\n" + "=" * 70)
        print(assessment['risk_assessment']['message'])
        print("=" * 70)
        
    else:
        print("\n🎉 PERFECT! No security issues found!")
        print("   Your AWS account follows security best practices.")
        
        # Still save a clean assessment
        assessment = {
            "security_score": 100,
            "grade": "A+",
            "risk_score": 100,
            "compliance_score": 100,
            "message": "No security issues found. Perfect security posture!"
        }
        
        with open("data/full_assessment.json", "w") as f:
            json.dump({"scan_time": datetime.now().isoformat(), "total_findings": 0, "assessment": assessment}, f, indent=2)
    
    return assessment
# Save to history
    from src.utils.history_manager import HistoryManager
    history_manager = HistoryManager()
    
    # Create a record for history
    history_record = {
        "scan_time": datetime.now().isoformat(),
        "total_findings": len(remediated_findings),
        "security_assessment": assessment
    }
    history_manager.save_scan(history_record)

def main():
    try:
        run_full_scan()
    except KeyboardInterrupt:
        print("\n\n⚠️  Scan interrupted by user")
    except Exception as e:
        print(f"\n❌ Error: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    main()