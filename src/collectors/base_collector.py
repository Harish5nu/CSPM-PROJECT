# src/collectors/base_collector.py
"""
Base collector class that all AWS service collectors will inherit from.
This provides common functionality like AWS client setup and error handling.
"""

import boto3
import json
from datetime import datetime,timezone
from dotenv import load_dotenv
import os

# Load environment variables
load_dotenv()

class BaseCollector:
    """
    Base class for all AWS collectors.
    Each service collector (S3, IAM, EC2, RDS) will inherit from this class.
    """
    
    def __init__(self, region=None):
        """
        Initialize the collector with AWS credentials.
        
        Args:
            region: AWS region (defaults to us-east-1)
        """
        # Get credentials from environment
        self.access_key = os.getenv("AWS_ACCESS_KEY_ID")
        self.secret_key = os.getenv("AWS_SECRET_ACCESS_KEY")
        self.region = region or os.getenv("AWS_DEFAULT_REGION", "us-east-1")
        
        # Check if using LocalStack (for local testing)
        self.use_localstack = os.getenv("USE_LOCALSTACK", "false").lower() == "true"
        
        # Store collected data
        self.findings = []
        
        # AWS session (will be created by child classes)
        self.session = None
        
    def get_client(self, service_name):
        """
        Create an AWS client for a specific service.
        
        Args:
            service_name: e.g., 's3', 'iam', 'ec2', 'rds'
            
        Returns:
            boto3 client object
        """
        try:
            # For LocalStack testing
            if self.use_localstack:
                endpoint_url = os.getenv("AWS_ENDPOINT_URL", "http://localhost:4566")
                client = boto3.client(
                    service_name,
                    aws_access_key_id=self.access_key,
                    aws_secret_access_key=self.secret_key,
                    region_name=self.region,
                    endpoint_url=endpoint_url
                )
            else:
                # Real AWS
                client = boto3.client(
                    service_name,
                    aws_access_key_id=self.access_key,
                    aws_secret_access_key=self.secret_key,
                    region_name=self.region
                )
            
            print(f"    ✅ Connected to AWS {service_name.upper()}")
            return client
            
        except Exception as e:
            print(f"    ❌ Failed to connect to {service_name}: {e}")
            return None
    
    def add_finding(self, resource_id, service, issue, severity, details=None):
        """
        Add a security finding to the results list.
        
        Args:
            resource_id: Name/ID of the AWS resource
            service: AWS service (S3, IAM, EC2, RDS)
            issue: Description of the security issue
            severity: CRITICAL, HIGH, MEDIUM, LOW
            details: Optional extra information
        """
        finding = {
            "timestamp": datetime.now().isoformat(),
            "resource_id": resource_id,
            "service": service,
            "issue": issue,
            "severity": severity,
            "details": details or {},
            "remediation": None  # Will be filled by AI later
        }
        self.findings.append(finding)
        
        # Print to console so you see progress
        print(f"    🔴 [{severity}] {service}: {resource_id} - {issue}")
    
    def get_results(self):
        """
        Return all findings collected.
        
        Returns:
            List of finding dictionaries
        """
        return self.findings
    
    def save_to_file(self, filename="findings.json"):
        """
        Save findings to a JSON file.
        
        Args:
            filename: Output file name
        """
        output = {
            "scan_time": datetime.now().isoformat(),
            "total_findings": len(self.findings),
            "findings": self.findings
        }
        
        with open(f"data/{filename}", "w") as f:
            json.dump(output, f, indent=2)
        
        print(f"\n💾 Findings saved to data/{filename}")
    
    def collect(self):
        """
        Main collection method - must be overridden by child classes.
        
        Raises:
            NotImplementedError: If child class doesn't implement this
        """
        raise NotImplementedError("Each collector must implement its own collect() method")