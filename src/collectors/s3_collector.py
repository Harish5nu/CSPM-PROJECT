# src/collectors/s3_collector.py
"""
S3 Collector - Scans AWS S3 buckets for security misconfigurations.
Checks for: public access, missing encryption, logging disabled, versioning off.
"""

from src.collectors.base_collector import BaseCollector

class S3Collector(BaseCollector):
    """
    Collects security information about S3 buckets.
    Inherits from BaseCollector.
    """
    
    def collect(self):
        """
        Main method that scans all S3 buckets.
        
        Returns:
            List of security findings
        """
        print("\n📦 Scanning S3 buckets...")
        
        # Get S3 client
        s3 = self.get_client('s3')
        if not s3:
            print("    ❌ Cannot scan S3 - client creation failed")
            return self.findings
        
        try:
            # Get list of all buckets
            response = s3.list_buckets()
            buckets = response.get('Buckets', [])
            
            print(f"    Found {len(buckets)} bucket(s)")
            
            # Scan each bucket
            for bucket in buckets:
                bucket_name = bucket['Name']
                print(f"\n    Checking bucket: {bucket_name}")
                
                # --- CHECK 1: Public access ---
                self._check_public_access(s3, bucket_name)
                
                # --- CHECK 2: Encryption at rest ---
                self._check_encryption(s3, bucket_name)
                
                # --- CHECK 3: Bucket versioning ---
                self._check_versioning(s3, bucket_name)
                
                # --- CHECK 4: Access logging ---
                self._check_logging(s3, bucket_name)
                
                # --- CHECK 5: MFA delete (advanced) ---
                self._check_mfa_delete(s3, bucket_name)
            
        except Exception as e:
            print(f"    ❌ Error scanning S3: {e}")
        
        print(f"\n✅ S3 scan complete. Found {len(self.findings)} issue(s)")
        return self.findings
    
    def _check_public_access(self, s3, bucket_name):
        """
        Check if bucket allows public access.
        This is a CRITICAL finding if true.
        """
        try:
            # Get bucket ACL (Access Control List)
            acl = s3.get_bucket_acl(Bucket=bucket_name)
            
            # Check for public access grants
            is_public = False
            for grant in acl.get('Grants', []):
                grantee = grant.get('Grantee', {})
                
                # Check for "AllUsers" (public) or "AuthenticatedUsers" (any AWS user)
                if grantee.get('URI') == 'http://acs.amazonaws.com/groups/global/AllUsers':
                    is_public = True
                    break
                if grantee.get('URI') == 'http://acs.amazonaws.com/groups/global/AuthenticatedUsers':
                    is_public = True
                    break
            
            # Also check bucket policy for public access
            try:
                policy = s3.get_bucket_policy(Bucket=bucket_name)
                # If policy exists, could still be public - simple check
                # Full policy parsing is complex, so we just note it
                if policy:
                    print(f"      ⚠️  Bucket has a policy (needs manual review)")
            except:
                pass  # No policy is fine
            
            if is_public:
                self.add_finding(
                    resource_id=bucket_name,
                    service="S3",
                    issue="Bucket is publicly accessible",
                    severity="CRITICAL",
                    details={
                        "check": "public_access",
                        "recommendation": "Block all public access using S3 Block Public Access settings"
                    }
                )
            else:
                print(f"      ✅ Not publicly accessible")
                
        except Exception as e:
            print(f"      ⚠️  Could not check public access: {e}")
    
    def _check_encryption(self, s3, bucket_name):
        """
        Check if bucket has default encryption enabled.
        This is a HIGH finding if missing.
        """
        try:
            # Try to get encryption configuration
            encryption = s3.get_bucket_encryption(Bucket=bucket_name)
            
            # If we get here, encryption is enabled
            rules = encryption.get('ServerSideEncryptionConfiguration', {}).get('Rules', [])
            if rules:
                print(f"      ✅ Encryption enabled")
            else:
                self.add_finding(
                    resource_id=bucket_name,
                    service="S3",
                    issue="Default encryption not enabled",
                    severity="HIGH",
                    details={
                        "check": "encryption",
                        "recommendation": "Enable default encryption with AES-256 or AWS KMS"
                    }
                )
        except s3.exceptions.ServerSideEncryptionConfigurationNotFoundError:
            # This exception means encryption is NOT configured
            self.add_finding(
                resource_id=bucket_name,
                service="S3",
                issue="Default encryption not enabled",
                severity="HIGH",
                details={
                    "check": "encryption",
                    "recommendation": "Enable default encryption with AES-256 or AWS KMS"
                }
            )
        except Exception as e:
            print(f"      ⚠️  Could not check encryption: {e}")
    
    def _check_versioning(self, s3, bucket_name):
        """
        Check if bucket versioning is enabled.
        This is a MEDIUM finding if missing.
        """
        try:
            versioning = s3.get_bucket_versioning(Bucket=bucket_name)
            status = versioning.get('Status', 'Disabled')
            
            if status == 'Enabled':
                print(f"      ✅ Versioning enabled")
            else:
                self.add_finding(
                    resource_id=bucket_name,
                    service="S3",
                    issue="Versioning not enabled",
                    severity="MEDIUM",
                    details={
                        "check": "versioning",
                        "current_status": status,
                        "recommendation": "Enable versioning to protect against accidental deletion"
                    }
                )
        except Exception as e:
            print(f"      ⚠️  Could not check versioning: {e}")
    
    def _check_logging(self, s3, bucket_name):
        """
        Check if access logging is enabled.
        This is a MEDIUM finding if missing.
        """
        try:
            logging = s3.get_bucket_logging(Bucket=bucket_name)
            enabled = logging.get('LoggingEnabled')
            
            if enabled:
                print(f"      ✅ Access logging enabled")
            else:
                self.add_finding(
                    resource_id=bucket_name,
                    service="S3",
                    issue="Access logging not enabled",
                    severity="MEDIUM",
                    details={
                        "check": "logging",
                        "recommendation": "Enable access logging to track requests"
                    }
                )
        except Exception as e:
            print(f"      ⚠️  Could not check logging: {e}")
    
    def _check_mfa_delete(self, s3, bucket_name):
        """
        Check if MFA delete is enabled (advanced security).
        This is a LOW finding if missing (nice to have).
        """
        try:
            # Note: MFA delete requires versioning to be enabled first
            versioning = s3.get_bucket_versioning(Bucket=bucket_name)
            mfa_delete = versioning.get('MFADelete', 'Disabled')
            
            if mfa_delete == 'Enabled':
                print(f"      ✅ MFA delete enabled")
            else:
                self.add_finding(
                    resource_id=bucket_name,
                    service="S3",
                    issue="MFA delete not enabled",
                    severity="LOW",
                    details={
                        "check": "mfa_delete",
                        "recommendation": "Enable MFA delete for sensitive buckets"
                    }
                )
        except Exception as e:
            pass  # Skip if can't check (often needs special permissions)