# scripts/run_s3_scan.py
"""
Run S3 scanner only - good for testing.
"""

import sys
import os

# Add project root to path so Python can find src/
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.collectors.s3_collector import S3Collector

def main():
    print("=" * 50)
    print("AWS S3 Security Scanner")
    print("=" * 50)
    
    # Create S3 collector
    collector = S3Collector()
    
    # Run the scan
    findings = collector.collect()
    
    # Save results
    collector.save_to_file("s3_findings.json")
    
    # Summary
    print("\n" + "=" * 50)
    print("SCAN SUMMARY")
    print("=" * 50)
    
    if findings:
        # Count by severity
        critical = sum(1 for f in findings if f['severity'] == 'CRITICAL')
        high = sum(1 for f in findings if f['severity'] == 'HIGH')
        medium = sum(1 for f in findings if f['severity'] == 'MEDIUM')
        low = sum(1 for f in findings if f['severity'] == 'LOW')
        
        print(f"🔴 CRITICAL: {critical}")
        print(f"🟠 HIGH: {high}")
        print(f"🟡 MEDIUM: {medium}")
        print(f"🔵 LOW: {low}")
        print(f"\n📊 Total findings: {len(findings)}")
    else:
        print("✅ No issues found! Your S3 buckets are secure!")
    
    print("=" * 50)

if __name__ == "__main__":
    main()