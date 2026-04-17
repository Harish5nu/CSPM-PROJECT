# src/collectors/ec2_collector.py
"""
EC2 Collector - Scans EC2 instances and security groups.
Checks for: open SSH/RDP ports, public instances, unencrypted volumes.
"""

from src.collectors.base_collector import BaseCollector
from datetime import datetime

class EC2Collector(BaseCollector):
    """
    Collects security information about EC2 instances and security groups.
    """
    
    # Dangerous ports to check for
    DANGEROUS_PORTS = {
        22: "SSH (Remote access)",
        3389: "RDP (Windows Remote Desktop)",
        23: "Telnet (Unencrypted)",
        21: "FTP (Unencrypted)",
        1433: "MSSQL (Database)",
        3306: "MySQL (Database)",
        27017: "MongoDB (Database)",
        6379: "Redis (Database)",
        9200: "Elasticsearch",
        5900: "VNC (Remote desktop)"
    }
    
    def collect(self):
        """
        Main method that scans EC2 configuration.
        
        Returns:
            List of security findings
        """
        print("\n🖥️  Scanning EC2 (Elastic Compute Cloud)...")
        
        # Get EC2 client
        ec2 = self.get_client('ec2')
        if not ec2:
            print("    ❌ Cannot scan EC2 - client creation failed")
            return self.findings
        
        try:
            # --- CHECK 1: Security groups with open dangerous ports ---
            self._check_security_groups(ec2)
            
            # --- CHECK 2: Publicly accessible instances ---
            self._check_public_instances(ec2)
            
            # --- CHECK 3: Instances without EBS encryption ---
            self._check_encrypted_volumes(ec2)
            
            # --- CHECK 4: Unused security groups ---
            self._check_unused_security_groups(ec2)
            
            # --- CHECK 5: Old AMIs (Amazon Machine Images) ---
            self._check_old_amis(ec2)
            
        except Exception as e:
            print(f"    ❌ Error scanning EC2: {e}")
        
        print(f"\n✅ EC2 scan complete. Found {len(self.findings)} issue(s)")
        return self.findings
    
    def _check_security_groups(self, ec2):
        """
        Check security groups for open dangerous ports (0.0.0.0/0).
        This is a CRITICAL finding for SSH/RDP.
        """
        try:
            # Get all security groups
            sgs = ec2.describe_security_groups()
            open_ports_found = []
            
            for sg in sgs.get('SecurityGroups', []):
                group_name = sg.get('GroupName', 'unnamed')
                group_id = sg.get('GroupId')
                
                for rule in sg.get('IpPermissions', []):
                    port = rule.get('FromPort')
                    ip_ranges = rule.get('IpRanges', [])
                    
                    # Check if port is dangerous and open to world (0.0.0.0/0)
                    if port in self.DANGEROUS_PORTS:
                        for ip_range in ip_ranges:
                            cidr = ip_range.get('CidrIp', '')
                            if cidr == '0.0.0.0/0':
                                open_ports_found.append({
                                    "group": group_name,
                                    "group_id": group_id,
                                    "port": port,
                                    "service": self.DANGEROUS_PORTS[port]
                                })
            
            # Group findings by severity
            critical_ports = [22, 3389]  # SSH and RDP are CRITICAL
            high_ports = [23, 21]  # Telnet, FTP are HIGH
            medium_ports = [1433, 3306, 27017, 6379, 9200, 5900]  # Databases are MEDIUM
            
            for finding in open_ports_found:
                port = finding['port']
                if port in critical_ports:
                    severity = "CRITICAL"
                elif port in high_ports:
                    severity = "HIGH"
                else:
                    severity = "MEDIUM"
                
                self.add_finding(
                    resource_id=finding['group'],
                    service="EC2",
                    issue=f"Security group allows {finding['service']} (port {port}) from anywhere (0.0.0.0/0)",
                    severity=severity,
                    details={
                        "check": "open_ports",
                        "group_id": finding['group_id'],
                        "port": port,
                        "recommendation": f"Restrict {finding['service']} access to specific IP addresses only"
                    }
                )
            
            if open_ports_found:
                print(f"      🔴 Found {len(open_ports_found)} open dangerous port(s)")
            else:
                print(f"      ✅ No dangerous ports open to world")
                
        except Exception as e:
            print(f"      ⚠️  Could not check security groups: {e}")
    
    def _check_public_instances(self, ec2):
        """
        Check for instances with public IP addresses.
        This is a MEDIUM finding (depends on use case).
        """
        try:
            instances = ec2.describe_instances()
            public_instances = []
            
            for reservation in instances.get('Reservations', []):
                for instance in reservation.get('Instances', []):
                    instance_id = instance.get('InstanceId')
                    public_ip = instance.get('PublicIpAddress')
                    
                    # Also check if instance is in a public subnet (simplified check)
                    if public_ip:
                        public_instances.append({
                            "id": instance_id,
                            "ip": public_ip,
                            "state": instance.get('State', {}).get('Name', 'unknown')
                        })
            
            if public_instances:
                # Filter to running instances only
                running = [i for i in public_instances if i['state'] == 'running']
                
                if running:
                    self.add_finding(
                        resource_id="public-instances",
                        service="EC2",
                        issue=f"{len(running)} instance(s) have public IP addresses",
                        severity="MEDIUM",
                        details={
                            "check": "public_instances",
                            "instances": running[:5],
                            "recommendation": "Use private subnets and load balancers instead of public IPs when possible"
                        }
                    )
                    print(f"      ⚠️  {len(running)} instance(s) have public IPs")
                else:
                    print(f"      ✅ No running instances with public IPs")
            else:
                print(f"      ✅ No instances with public IPs")
                
        except Exception as e:
            print(f"      ⚠️  Could not check public instances: {e}")
    
    def _check_encrypted_volumes(self, ec2):
        """
        Check if EBS volumes are encrypted.
        This is a HIGH finding for sensitive data.
        """
        try:
            volumes = ec2.describe_volumes()
            unencrypted_volumes = []
            
            for volume in volumes.get('Volumes', []):
                if not volume.get('Encrypted', False):
                    unencrypted_volumes.append({
                        "id": volume['VolumeId'],
                        "size": volume['Size'],
                        "type": volume['VolumeType']
                    })
            
            if unencrypted_volumes:
                self.add_finding(
                    resource_id="ebs-volumes",
                    service="EC2",
                    issue=f"{len(unencrypted_volumes)} EBS volume(s) are not encrypted",
                    severity="HIGH",
                    details={
                        "check": "volume_encryption",
                        "volumes": unencrypted_volumes[:5],
                        "recommendation": "Enable EBS encryption by default for your account"
                    }
                )
                print(f"      🔴 {len(unencrypted_volumes)} unencrypted volume(s)")
            else:
                print(f"      ✅ All volumes encrypted")
                
        except Exception as e:
            print(f"      ⚠️  Could not check volume encryption: {e}")
    
    def _check_unused_security_groups(self, ec2):
        """
        Find security groups not attached to any instance.
        This is a LOW finding (cleanup recommendation).
        """
        try:
            # Get all security groups
            all_sgs = ec2.describe_security_groups()
            all_sg_ids = [sg['GroupId'] for sg in all_sgs.get('SecurityGroups', [])]
            
            # Get security groups attached to instances
            used_sg_ids = set()
            instances = ec2.describe_instances()
            
            for reservation in instances.get('Reservations', []):
                for instance in reservation.get('Instances', []):
                    for sg in instance.get('SecurityGroups', []):
                        used_sg_ids.add(sg['GroupId'])
            
            # Find unused groups
            unused_sgs = [sg_id for sg_id in all_sg_ids if sg_id not in used_sg_ids]
            
            # Don't flag default security group (it's fine to keep)
            unused_sgs = [sg for sg in unused_sgs if not sg.startswith('sg-') or 'default' not in sg.lower()]
            
            if unused_sgs and len(unused_sgs) > 3:  # Only flag if more than a few
                self.add_finding(
                    resource_id="unused-sgs",
                    service="EC2",
                    issue=f"{len(unused_sgs)} security group(s) not attached to any instance",
                    severity="LOW",
                    details={
                        "check": "unused_security_groups",
                        "groups": unused_sgs[:5],
                        "recommendation": "Remove unused security groups to reduce complexity"
                    }
                )
                print(f"      ℹ️  {len(unused_sgs)} unused security group(s)")
                
        except Exception as e:
            pass  # Low priority check, skip on error
    
    def _check_old_amis(self, ec2):
        """
        Check if instances are running on old AMIs.
        This is a MEDIUM finding.
        """
        try:
            instances = ec2.describe_instances()
            old_amis = []
            
            for reservation in instances.get('Reservations', []):
                for instance in reservation.get('Instances', []):
                    # Check launch time
                    launch_time = instance.get('LaunchTime')
                    if launch_time:
                        days_old = (datetime.now(launch_time.tzinfo) - launch_time).days
                        
                        if days_old > 180:  # 6 months
                            old_amis.append({
                                "id": instance['InstanceId'],
                                "launch_time": launch_time.isoformat(),
                                "days_old": days_old
                            })
            
            if old_amis:
                self.add_finding(
                    resource_id="old-instances",
                    service="EC2",
                    issue=f"{len(old_amis)} instance(s) running for over 6 months without refresh",
                    severity="MEDIUM",
                    details={
                        "check": "old_amis",
                        "instances": old_amis[:5],
                        "recommendation": "Regularly refresh instances with updated AMIs to apply security patches"
                    }
                )
                print(f"      ⚠️  {len(old_amis)} instance(s) older than 6 months")
            else:
                print(f"      ✅ All instances relatively new")
                
        except Exception as e:
            print(f"      ⚠️  Could not check instance age: {e}")