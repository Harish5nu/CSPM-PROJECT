# test_aws.py
import os
import boto3
from dotenv import load_dotenv

# Load credentials from .env file
load_dotenv()

print("=" * 50)
print("Testing AWS Connection")
print("=" * 50)

# Get AWS credentials
access_key = os.getenv("AWS_ACCESS_KEY_ID")
secret_key = os.getenv("AWS_SECRET_ACCESS_KEY")
region = os.getenv("AWS_DEFAULT_REGION", "us-east-1")

print(f"\n[1] Credentials loaded:")
print(f"    Access Key: {access_key[:10]}..." if access_key else "    ❌ Access Key missing")
print(f"    Region: {region}")

# Try to connect
try:
    # Create STS client (Security Token Service - always available)
    sts = boto3.client(
        'sts',
        aws_access_key_id=access_key,
        aws_secret_access_key=secret_key,
        region_name=region
    )
    
    # Get caller identity (who am I?)
    identity = sts.get_caller_identity()
    
    print(f"\n[2] AWS Connection: ✅ SUCCESS")
    print(f"    Account ID: {identity['Account']}")
    print(f"    User ARN: {identity['Arn']}")
    
    # Test S3 access (list buckets)
    s3 = boto3.client(
        's3',
        aws_access_key_id=access_key,
        aws_secret_access_key=secret_key,
        region_name=region
    )
    
    response = s3.list_buckets()
    bucket_count = len(response['Buckets'])
    
    print(f"\n[3] S3 Access: ✅ SUCCESS")
    print(f"    Found {bucket_count} bucket(s)")
    
    if bucket_count > 0:
        print("    Bucket names:")
        for bucket in response['Buckets']:
            print(f"      - {bucket['Name']}")
    
    print("\n" + "=" * 50)
    print("✅ AWS is ready! You can proceed to Day 2")
    
except Exception as e:
    print(f"\n❌ AWS Connection Failed!")
    print(f"Error: {e}")
    print("\nTroubleshooting:")
    print("1. Check your .env file has correct keys")
    print("2. Make sure there are no spaces around = in .env")
    print("3. Verify your AWS account is active")