# scripts/run_all_scanners.py
"""
Unified scanner that runs all AWS security collectors.
Scans: S3, IAM, EC2, RDS
"""

import sys
import os
import json
from datetime import datetime

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Import all collectors
from src.collectors.s3_collector import S3Collector
from src.collectors.iam_collector import IAMCollector
from src.collectors.ec2_collector import EC2Collector
from src.collectors.rds_collector import RDSCollector

def run_all_scanners():
    """
    Run all security scanners and collect results.
    """
    print("=" * 60)
    print("🚀 AI AWS CSPM - Full Security Scan")
    print("=" * 60)
    print(f"Scan started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("=" * 60)
    
    all_findings = []
    
    # Run S3 scanner
    s3 = S3Collector()
    s3_findings = s3.collect()
    all_findings.extend(s3_findings)
    
    # Run IAM scanner
    iam = IAMCollector()
    iam_findings = iam.collect()
    all_findings.extend(iam_findings)
    
    # Run EC2 scanner
    ec2 = EC2Collector()
    ec2_findings = ec2.collect()
    all_findings.extend(ec2_findings)
    
    # Run RDS scanner
    rds = RDSCollector()
    rds_findings = rds.collect()
    all_findings.extend(rds_findings)
    
    # Save all findings
    output = {
        "scan_time": datetime.now().isoformat(),
        "total_findings": len(all_findings),
        "scanners_used": ["S3", "IAM", "EC2", "RDS"],
        "findings": all_findings
    }
    
    # Ensure data directory exists
    os.makedirs("data", exist_ok=True)
    
    # Save to file
    with open("data/all_findings.json", "w") as f:
        json.dump(output, f, indent=2)
    
    # Print summary
    print("\n" + "=" * 60)
    print("📊 SCAN SUMMARY")
    print("=" * 60)
    
    # Count by severity
    severity_counts = {
        "CRITICAL": 0,
        "HIGH": 0,
        "MEDIUM": 0,
        "LOW": 0
    }
    
    for finding in all_findings:
        severity = finding['severity']
        if severity in severity_counts:
            severity_counts[severity] += 1
    
    print(f"\n🔴 CRITICAL: {severity_counts['CRITICAL']}")
    print(f"🟠 HIGH:      {severity_counts['HIGH']}")
    print(f"🟡 MEDIUM:    {severity_counts['MEDIUM']}")
    print(f"🔵 LOW:       {severity_counts['LOW']}")
    print(f"\n📊 TOTAL:     {len(all_findings)} finding(s)")
    
    # Print top issues by service
    print("\n📋 Findings by Service:")
    service_counts = {}
    for finding in all_findings:
        service = finding['service']
        service_counts[service] = service_counts.get(service, 0) + 1
    
    for service, count in sorted(service_counts.items(), key=lambda x: x[1], reverse=True):
        print(f"   {service}: {count}")
    
    print("\n" + "=" * 60)
    print(f"💾 Full results saved to: data/all_findings.json")
    print("=" * 60)
    
    return all_findings

def main():
    try:
        findings = run_all_scanners()
        
        if len(findings) == 0:
            print("\n🎉 EXCELLENT! No security issues found!")
            print("   Your AWS account follows security best practices.")
        else:
            print(f"\n⚠️  Found {len(findings)} issue(s) to review.")
            
            
    except KeyboardInterrupt:
        print("\n\n⚠️  Scan interrupted by user")
    except Exception as e:
        print(f"\n❌ Error during scan: {e}")
        print("\nTroubleshooting:")
        print("1. Check your AWS credentials in .env")
        print("2. Verify you have permissions for all services")
        print("3. Some services may not be available in your region")

if __name__ == "__main__":
    main()