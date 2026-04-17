# src/collectors/rds_collector.py
"""
RDS Collector - Scans RDS databases for security issues.
Checks for: public accessibility, encryption, backup retention, audit logging.
"""

from src.collectors.base_collector import BaseCollector

class RDSCollector(BaseCollector):
    """
    Collects security information about RDS databases.
    """
    
    def collect(self):
        """
        Main method that scans RDS configuration.
        
        Returns:
            List of security findings
        """
        print("\n🗄️  Scanning RDS (Relational Database Service)...")
        
        # Get RDS client
        rds = self.get_client('rds')
        if not rds:
            print("    ❌ Cannot scan RDS - client creation failed")
            return self.findings
        
        try:
            # Get all DB instances
            instances = rds.describe_db_instances()
            db_instances = instances.get('DBInstances', [])
            
            print(f"    Found {len(db_instances)} database instance(s)")
            
            for db in db_instances:
                db_id = db.get('DBInstanceIdentifier', 'unknown')
                print(f"\n    Checking database: {db_id}")
                
                # --- CHECK 1: Public accessibility ---
                self._check_public_access(db, db_id)
                
                # --- CHECK 2: Encryption at rest ---
                self._check_encryption(db, db_id)
                
                # --- CHECK 3: Backup retention ---
                self._check_backup_retention(db, db_id)
                
                # --- CHECK 4: Audit logging (PostgreSQL/MySQL) ---
                self._check_audit_logging(rds, db_id)
                
                # --- CHECK 5: Minor version upgrades ---
                self._check_auto_upgrades(db, db_id)
            
        except Exception as e:
            print(f"    ❌ Error scanning RDS: {e}")
        
        print(f"\n✅ RDS scan complete. Found {len(self.findings)} issue(s)")
        return self.findings
    
    def _check_public_access(self, db, db_id):
        """
        Check if database is publicly accessible.
        This is a CRITICAL finding.
        """
        publicly_accessible = db.get('PubliclyAccessible', False)
        
        if publicly_accessible:
            self.add_finding(
                resource_id=db_id,
                service="RDS",
                issue="Database is publicly accessible",
                severity="CRITICAL",
                details={
                    "check": "public_access",
                    "endpoint": db.get('Endpoint', {}).get('Address', 'unknown'),
                    "recommendation": "Set PubliclyAccessible=false and place database in private subnet"
                }
            )
            print(f"      🔴 Publicly accessible!")
        else:
            print(f"      ✅ Not publicly accessible")
    
    def _check_encryption(self, db, db_id):
        """
        Check if database is encrypted at rest.
        This is a HIGH finding if unencrypted.
        """
        encrypted = db.get('StorageEncrypted', False)
        
        if not encrypted:
            self.add_finding(
                resource_id=db_id,
                service="RDS",
                issue="Database is not encrypted at rest",
                severity="HIGH",
                details={
                    "check": "encryption",
                    "engine": db.get('Engine', 'unknown'),
                    "recommendation": "Enable encryption when creating databases (cannot be added after creation)"
                }
            )
            print(f"      🔴 Not encrypted")
        else:
            print(f"      ✅ Encrypted at rest")
    
    def _check_backup_retention(self, db, db_id):
        """
        Check backup retention period.
        This is a MEDIUM finding if less than 7 days.
        """
        retention_days = db.get('BackupRetentionPeriod', 0)
        
        if retention_days < 7:
            self.add_finding(
                resource_id=db_id,
                service="RDS",
                issue=f"Backup retention period is only {retention_days} days",
                severity="MEDIUM",
                details={
                    "check": "backup_retention",
                    "current_days": retention_days,
                    "recommendation": "Increase backup retention to at least 7 days (or 35 for compliance)"
                }
            )
            print(f"      ⚠️  Backup retention: {retention_days} days (low)")
        else:
            print(f"      ✅ Backup retention: {retention_days} days")
    
    def _check_audit_logging(self, rds, db_id):
        """
        Check if audit logging is enabled (PostgreSQL/MySQL specific).
        This is a MEDIUM finding for compliance.
        """
        try:
            # Check DB parameter groups for logging settings
            # This is a simplified check
            db_instances = rds.describe_db_instances(DBInstanceIdentifier=db_id)
            db = db_instances.get('DBInstances', [{}])[0]
            
            # Get parameter group
            param_group_list = db.get('DBParameterGroups', [])
            if param_group_list:
                param_group_name = param_group_list[0].get('DBParameterGroupName')
                
                if param_group_name:
                    # This is a simplified check - full implementation would need to get parameters
                    # For now, just note if it's using default groups
                    if 'default' in param_group_name.lower():
                        self.add_finding(
                            resource_id=db_id,
                            service="RDS",
                            issue="Database may not have audit logging enabled (using default parameter group)",
                            severity="LOW",
                            details={
                                "check": "audit_logging",
                                "parameter_group": param_group_name,
                                "recommendation": "Create custom parameter group with audit logging enabled"
                            }
                        )
                        print(f"      ℹ️  Using default parameter group - check audit logging")
                    else:
                        print(f"      ✅ Custom parameter group in use")
                        
        except Exception as e:
            print(f"      ⚠️  Could not check audit logging: {e}")
    
    def _check_auto_upgrades(self, db, db_id):
        """
        Check if auto minor version upgrades are enabled.
        This is a LOW finding (good practice).
        """
        auto_upgrade = db.get('AutoMinorVersionUpgrade', False)
        
        if not auto_upgrade:
            self.add_finding(
                resource_id=db_id,
                service="RDS",
                issue="Auto minor version upgrades disabled",
                severity="LOW",
                details={
                    "check": "auto_upgrades",
                    "engine_version": db.get('EngineVersion', 'unknown'),
                    "recommendation": "Enable auto minor version upgrades to receive security patches"
                }
            )
            print(f"      ℹ️  Auto upgrades disabled")
        else:
            print(f"      ✅ Auto upgrades enabled")