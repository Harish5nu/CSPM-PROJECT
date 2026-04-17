# src/collectors/iam_collector.py
"""
IAM Collector - Scans AWS IAM for security issues.
Checks for: root user MFA, unused credentials, over-permissive policies, password policy.
"""

from src.collectors.base_collector import BaseCollector
from datetime import datetime, timezone
class IAMCollector(BaseCollector):
    """
    Collects security information about IAM users, roles, and policies.
    """
    
    def collect(self):
        """
        Main method that scans IAM configuration.
        
        Returns:
            List of security findings
        """
        print("\n👥 Scanning IAM (Identity & Access Management)...")
        
        # Get IAM client
        iam = self.get_client('iam')
        if not iam:
            print("    ❌ Cannot scan IAM - client creation failed")
            return self.findings
        
        try:
            # --- CHECK 1: Root user MFA ---
            self._check_root_mfa(iam)
            
            # --- CHECK 2: Account password policy ---
            self._check_password_policy(iam)
            
            # --- CHECK 3: Unused IAM users ---
            self._check_unused_users(iam)
            
            # --- CHECK 4: Users without MFA ---
            self._check_users_without_mfa(iam)
            
            # --- CHECK 5: Old access keys ---
            self._check_old_access_keys(iam)
            
            # --- CHECK 6: Admin policy on users ---
            self._check_admin_policies(iam)
            
        except Exception as e:
            print(f"    ❌ Error scanning IAM: {e}")
        
        print(f"\n✅ IAM scan complete. Found {len(self.findings)} issue(s)")
        return self.findings
    
    def _check_root_mfa(self, iam):
        """
        Check if root account has MFA enabled.
        This is a CRITICAL finding.
        """
        try:
            # Get account summary
            summary = iam.get_account_summary()
            
            # Check if root MFA is enabled
            # Note: This requires special permissions, may not work for all users
            mfa_enabled = summary.get('SummaryMap', {}).get('AccountMFAEnabled', 0)
            
            if not mfa_enabled:
                self.add_finding(
                    resource_id="root-user",
                    service="IAM",
                    issue="Root user does not have MFA enabled",
                    severity="CRITICAL",
                    details={
                        "check": "root_mfa",
                        "recommendation": "Enable MFA on the root account immediately",
                        "how_to": "AWS Console → IAM → Account settings → Manage MFA"
                    }
                )
                print(f"      🔴 Root user MFA is DISABLED")
            else:
                print(f"      ✅ Root user MFA enabled")
                
        except Exception as e:
            # Some accounts restrict access to this info
            print(f"      ⚠️  Could not check root MFA: {e}")
    
    def _check_password_policy(self, iam):
        """
        Check if account has a strong password policy.
        This is a HIGH finding if missing or weak.
        """
        try:
            policy = iam.get_account_password_policy()
            policy_dict = policy.get('PasswordPolicy', {})
            
            issues = []
            
            # Check minimum password length
            min_length = policy_dict.get('MinimumPasswordLength', 0)
            if min_length < 14:
                issues.append(f"Minimum length is {min_length} (should be 14+)")
            
            # Check for complexity requirements
            if not policy_dict.get('RequireUppercaseCharacters', False):
                issues.append("No uppercase letter requirement")
            if not policy_dict.get('RequireLowercaseCharacters', False):
                issues.append("No lowercase letter requirement")
            if not policy_dict.get('RequireNumbers', False):
                issues.append("No number requirement")
            if not policy_dict.get('RequireSymbols', False):
                issues.append("No symbol requirement")
            
            # Check password expiration
            if not policy_dict.get('MaxPasswordAge', 0):
                issues.append("No password expiration")
            
            # Check password reuse prevention
            if not policy_dict.get('PasswordReusePrevention', 0):
                issues.append("No password reuse prevention")
            
            if issues:
                self.add_finding(
                    resource_id="account-password-policy",
                    service="IAM",
                    issue="Weak password policy",
                    severity="HIGH",
                    details={
                        "check": "password_policy",
                        "issues": issues,
                        "recommendation": "Configure a strong password policy with minimum 14 characters, complexity requirements, and expiration"
                    }
                )
                print(f"      🔴 Weak password policy: {issues[0]}")
            else:
                print(f"      ✅ Strong password policy configured")
                
        except iam.exceptions.NoSuchEntityException:
            # No password policy set at all
            self.add_finding(
                resource_id="account-password-policy",
                service="IAM",
                issue="No password policy configured",
                severity="HIGH",
                details={
                    "check": "password_policy",
                    "recommendation": "Create a password policy with security best practices"
                }
            )
            print(f"      🔴 No password policy configured")
        except Exception as e:
            print(f"      ⚠️  Could not check password policy: {e}")
    
    def _check_unused_users(self, iam):
        """
        Find IAM users that haven't been used recently.
        This is a MEDIUM finding.
        """
        try:
            # Get all users
            users = iam.list_users()
            
            for user in users.get('Users', []):
                username = user['UserName']
                
                # Get user's last activity
                try:
                    # Get last used time for access keys
                    keys = iam.list_access_keys(UserName=username)
                    last_used = None
                    
                    for key in keys.get('AccessKeyMetadata', []):
                        key_info = iam.get_access_key_last_used(AccessKeyId=key['AccessKeyId'])
                        last_used_date = key_info.get('AccessKeyLastUsed', {}).get('LastUsedDate')
                        
                        if last_used_date:
                            if not last_used or last_used_date > last_used:
                                last_used = last_used_date
                    
                    # If no activity in 90 days, flag it
                    if last_used:
                        now = datetime.now(timezone.utc)
                        if create_date.tzinfo is None:
                             create_date = create_date.replace(tzinfo=timezone.utc)
                        days_inactive = (now - create_date).days
                        if days_inactive > 90:
                            self.add_finding(
                                resource_id=username,
                                service="IAM",
                                issue=f"IAM user inactive for {days_inactive} days",
                                severity="MEDIUM",
                                details={
                                    "check": "unused_users",
                                    "last_activity": last_used.isoformat(),
                                    "recommendation": "Review if this user still needs access, consider deleting"
                                }
                            )
                            print(f"      ⚠️  User '{username}' inactive for {days_inactive} days")
                    else:
                        # User has never used their keys
                        self.add_finding(
                            resource_id=username,
                            service="IAM",
                            issue="IAM user has never used access keys",
                            severity="LOW",
                            details={
                                "check": "unused_users",
                                "recommendation": "Review if this user needs API access"
                            }
                        )
                        
                except Exception as e:
                    # Skip if can't check (might be service-linked role)
                    pass
                    
        except Exception as e:
            print(f"      ⚠️  Could not check unused users: {e}")
    
    def _check_users_without_mfa(self, iam):
        """
        Check which users don't have MFA enabled.
        This is a HIGH finding for human users.
        """
        try:
            users = iam.list_users()
            users_without_mfa = []
            
            for user in users.get('Users', []):
                username = user['UserName']
                
                # Skip service-linked roles
                if username.endswith('-role'):
                    continue
                
                # List MFA devices for this user
                mfa_devices = iam.list_mfa_devices(UserName=username)
                
                if not mfa_devices.get('MFADevices'):
                    users_without_mfa.append(username)
            
            if users_without_mfa:
                # Only flag as finding if there are users without MFA
                # But don't flag all individually to avoid spam
                self.add_finding(
                    resource_id="multiple-users",
                    service="IAM",
                    issue=f"{len(users_without_mfa)} IAM user(s) without MFA enabled",
                    severity="HIGH",
                    details={
                        "check": "mfa_required",
                        "users": users_without_mfa[:5],  # Show first 5
                        "recommendation": "Enable MFA for all human users"
                    }
                )
                print(f"      🔴 {len(users_without_mfa)} user(s) without MFA: {', '.join(users_without_mfa[:3])}...")
            else:
                print(f"      ✅ All users have MFA enabled")
                
        except Exception as e:
            print(f"      ⚠️  Could not check MFA status: {e}")
    
    def _check_old_access_keys(self, iam):
        """
        Find access keys older than 90 days.
        This is a MEDIUM finding.
        """
        from datetime import timedelta
        
        try:
            users = iam.list_users()
            old_keys_found = []
            
            for user in users.get('Users', []):
                username = user['UserName']
                
                keys = iam.list_access_keys(UserName=username)
                
                for key in keys.get('AccessKeyMetadata', []):
                    create_date = key['CreateDate']
                    now = datetime.now(timezone.utc)
                    if create_date.tzinfo is None:
                        create_date = create_date.replace(tzinfo=timezone.utc)
                    days_old = (now - create_date).days
                    
                    if days_old > 90:
                        old_keys_found.append({
                            "user": username,
                            "key_id": key['AccessKeyId'][-8:],  # Last 8 chars only
                            "days_old": days_old
                        })
            
            if old_keys_found:
                self.add_finding(
                    resource_id="access-keys",
                    service="IAM",
                    issue=f"{len(old_keys_found)} access key(s) older than 90 days",
                    severity="MEDIUM",
                    details={
                        "check": "old_keys",
                        "keys": old_keys_found[:5],
                        "recommendation": "Rotate access keys every 90 days"
                    }
                )
                print(f"      ⚠️  {len(old_keys_found)} old access key(s) found")
            else:
                print(f"      ✅ All access keys are recent (<90 days)")
                
        except Exception as e:
            print(f"      ⚠️  Could not check access key age: {e}")
    
    def _check_admin_policies(self, iam):
        """
        Check for users/roles with full admin access.
        This is a finding (severity depends on context).
        """
        try:
            # Get managed policies
            policies = iam.list_policies(Scope='AWS')
            
            admin_policies = []
            for policy in policies.get('Policies', []):
                # Look for AdministratorAccess policy
                if policy['PolicyName'] == 'AdministratorAccess':
                    admin_policies.append(policy['Arn'])
            
            # Find entities attached to admin policies
            entities_with_admin = []
            
            for policy_arn in admin_policies:
                # Get entities attached to this policy
                entities = iam.list_entities_for_policy(PolicyArn=policy_arn)
                
                for user in entities.get('PolicyUsers', []):
                    entities_with_admin.append(f"User: {user['UserName']}")
                for role in entities.get('PolicyRoles', []):
                    entities_with_admin.append(f"Role: {role['RoleName']}")
                for group in entities.get('PolicyGroups', []):
                    entities_with_admin.append(f"Group: {group['GroupName']}")
            
            if entities_with_admin:
                self.add_finding(
                    resource_id="admin-access",
                    service="IAM",
                    issue=f"{len(entities_with_admin)} entity(s) have full AdministratorAccess",
                    severity="MEDIUM",
                    details={
                        "check": "admin_policies",
                        "entities": entities_with_admin[:5],
                        "recommendation": "Follow least privilege principle - restrict admin access"
                    }
                )
                print(f"      ⚠️  {len(entities_with_admin)} entity(s) have admin access")
            else:
                print(f"      ✅ No unexpected admin access found")
                
        except Exception as e:
            print(f"      ⚠️  Could not check admin policies: {e}")