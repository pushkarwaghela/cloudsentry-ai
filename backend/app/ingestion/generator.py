"""
CloudSentry AI - Multi-Cloud Realistic Telemetry & Attack Scenario Generator
============================================================================

WHY SYNTHETIC GENERATION MATTERS IN SOC HIRING:
Real production cloud security logs contain sensitive PII, customer secrets, and
proprietary infrastructure topologies that cannot be published to GitHub or shared
in portfolio presentations.

This generator synthesizes authentic AWS and Azure audit telemetry adhering strictly
to production schemas (CloudTrail v1.08, Entra ID, VPC Flow, Defender, GuardDuty).
It models ~95% benign enterprise baseline activity and ~5% multi-stage adversary
tactics mapped to MITRE ATT&CK for Cloud.
"""

import json
import random
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Tuple
from uuid import uuid4

# ==============================================================================
# Simulation Personas & Baseline Assets
# ==============================================================================

BENIGN_USERS = [
    {"name": "alex.chen", "email": "alex.chen@cybercorp.com", "role": "DevOpsLead"},
    {"name": "sarah.connor", "email": "sarah.connor@cybercorp.com", "role": "CloudArchitect"},
    {"name": "elena.rostova", "email": "elena.rostova@cybercorp.com", "role": "DataScientist"},
    {"name": "marcus.vance", "email": "marcus.vance@cybercorp.com", "role": "FrontendEngineer"},
    {"name": "svc_ci_deployer", "email": "svc_ci_deployer@cybercorp.com", "role": "ServicePrincipal"},
]

OFFICE_IPS = [
    "198.51.100.22",
    "198.51.100.45",
    "198.51.100.88",
    "203.0.113.14",
]

TOR_EXIT_IPS = [
    "185.220.101.5",
    "185.220.101.9",
    "185.220.102.14",
]

SUSPICIOUS_EXTERNAL_IPS = [
    "45.33.32.156",
    "194.26.29.112",
    "91.240.118.82",
]


class MultiCloudDataGenerator:
    """
    Generates realistic multi-cloud baseline telemetry and injected attacks.
    """

    def __init__(self, base_time: datetime = None):
        self.base_time = base_time or (datetime.now(timezone.utc) - timedelta(hours=6))

    # --------------------------------------------------------------------------
    # AWS Baseline Generators
    # --------------------------------------------------------------------------

    def generate_benign_cloudtrail(self, offset_minutes: int) -> Dict[str, Any]:
        user = random.choice(BENIGN_USERS)
        event_time = (self.base_time + timedelta(minutes=offset_minutes)).strftime("%Y-%m-%dT%H:%M:%SZ")
        ip = random.choice(OFFICE_IPS)

        benign_actions = [
            ("ec2.amazonaws.com", "DescribeInstances", "ec2-instance"),
            ("ec2.amazonaws.com", "DescribeSecurityGroups", "security-group"),
            ("s3.amazonaws.com", "ListBuckets", "s3-service"),
            ("s3.amazonaws.com", "GetObject", "corp-artifacts-public"),
            ("cloudwatch.amazonaws.com", "GetMetricData", "cw-metrics"),
            ("signin.amazonaws.com", "ConsoleLogin", "console"),
            ("sts.amazonaws.com", "GetCallerIdentity", "sts"),
        ]
        source, event_name, res_name = random.choice(benign_actions)

        return {
            "eventVersion": "1.08",
            "userIdentity": {
                "type": "IAMUser" if not user["name"].startswith("svc_") else "AssumedRole",
                "principalId": f"AIDA{random.randint(100000, 999999)}EXAMPLE",
                "arn": f"arn:aws:iam::123456789012:user/{user['name']}",
                "accountId": "123456789012",
                "userName": user["name"],
            },
            "eventTime": event_time,
            "eventSource": source,
            "eventName": event_name,
            "awsRegion": random.choice(["us-east-1", "us-west-2"]),
            "sourceIPAddress": ip,
            "userAgent": "aws-sdk-go/v1.44.204 (go1.20; windows; amd64) terraform/1.6.0",
            "requestParameters": {"bucketName": res_name} if "s3" in source else {},
            "responseElements": None,
            "eventID": str(uuid4()),
            "eventType": "AwsApiCall",
            "errorCode": None,
            "errorMessage": None,
        }

    def generate_benign_vpc_flow(self, offset_minutes: int) -> Dict[str, Any]:
        t_start = int((self.base_time + timedelta(minutes=offset_minutes)).timestamp())
        return {
            "version": 2,
            "account_id": "123456789012",
            "interface_id": f"eni-0a{random.randint(10000000, 99999999)}",
            "srcaddr": f"10.0.{random.randint(1, 10)}.{random.randint(2, 250)}",
            "dstaddr": random.choice(["10.0.1.5", "10.0.2.10", "198.51.100.22"]),
            "srcport": random.randint(30000, 65000),
            "dstport": random.choice([80, 443, 3306, 5432]),
            "protocol": 6,  # TCP
            "packets": random.randint(10, 200),
            "bytes": random.randint(1500, 150000),
            "start": t_start,
            "end": t_start + 60,
            "action": "ACCEPT",
            "log_status": "OK",
        }

    # --------------------------------------------------------------------------
    # Azure Baseline Generators
    # --------------------------------------------------------------------------

    def generate_benign_entra_signin(self, offset_minutes: int) -> Dict[str, Any]:
        user = random.choice(BENIGN_USERS)
        event_time = (self.base_time + timedelta(minutes=offset_minutes)).strftime("%Y-%m-%dT%H:%M:%SZ")
        ip = random.choice(OFFICE_IPS)

        return {
            "id": str(uuid4()),
            "createdDateTime": event_time,
            "userPrincipalName": user["email"],
            "userId": f"usr-{random.randint(10000, 99999)}",
            "appDisplayName": random.choice(["Office 365 Exchange Online", "Azure Portal", "Slack Enterprise"]),
            "appId": "00000002-0000-0ff1-ce00-000000000000",
            "ipAddress": ip,
            "clientAppUsed": "Browser",
            "userAgent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/122.0.0.0",
            "location": {
                "city": "Seattle",
                "state": "WA",
                "countryOrRegion": "US",
                "geoCoordinates": {"latitude": 47.6062, "longitude": -122.3321},
            },
            "status": {"errorCode": 0, "failureReason": None},
            "conditionalAccessStatus": "success",
            "riskDetail": "none",
            "riskLevelAggregated": "none",
            "riskState": "none",
        }

    def generate_benign_activity_log(self, offset_minutes: int) -> Dict[str, Any]:
        user = random.choice(BENIGN_USERS)
        event_time = (self.base_time + timedelta(minutes=offset_minutes)).strftime("%Y-%m-%dT%H:%M:%SZ")

        operations = [
            "Microsoft.Compute/virtualMachines/read",
            "Microsoft.Storage/storageAccounts/read",
            "Microsoft.Network/networkSecurityGroups/read",
            "Microsoft.Resources/subscriptions/resourceGroups/read",
            "Microsoft.KeyVault/vaults/secrets/read",
        ]

        return {
            "time": event_time,
            "resourceId": "/subscriptions/sub-prod-001/resourceGroups/rg-prod-us/providers/Microsoft.Compute/virtualMachines/vm-app-01",
            "operationName": random.choice(operations),
            "category": "Administrative",
            "resultType": "Success",
            "caller": user["email"],
            "callerIpAddress": random.choice(OFFICE_IPS),
            "correlationId": str(uuid4()),
            "subscriptionId": "sub-prod-001",
            "properties": {"region": "eastus"},
        }

    # --------------------------------------------------------------------------
    # Injected Multi-Stage Attack Scenarios (MITRE ATT&CK Mapped)
    # --------------------------------------------------------------------------

    def generate_scenario_impossible_travel(self, offset_minutes: int) -> List[Dict[str, Any]]:
        """
        Scenario 1: Impossible Travel & Credential Compromise
        MITRE ATT&CK: T1078 (Valid Accounts), T1535 (Unused/Unsupported Cloud Regions)
        Event 1: Normal user login from Seattle office at T.
        Event 2: Rogue login for the same user 15 minutes later from a Tor Exit Node in Frankfurt, Germany.
        """
        user = BENIGN_USERS[1]  # sarah.connor
        t1 = self.base_time + timedelta(minutes=offset_minutes)
        t2 = t1 + timedelta(minutes=15)

        event1 = {
            "id": str(uuid4()),
            "createdDateTime": t1.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "userPrincipalName": user["email"],
            "userId": "usr-sarah-connor",
            "appDisplayName": "Azure Portal",
            "ipAddress": "198.51.100.45",
            "userAgent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Edge/122.0",
            "location": {
                "city": "Seattle",
                "state": "WA",
                "countryOrRegion": "US",
                "geoCoordinates": {"latitude": 47.6062, "longitude": -122.3321},
            },
            "status": {"errorCode": 0},
            "conditionalAccessStatus": "success",
            "riskDetail": "none",
            "riskLevelAggregated": "none",
        }

        event2 = {
            "id": str(uuid4()),
            "createdDateTime": t2.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "userPrincipalName": user["email"],
            "userId": "usr-sarah-connor",
            "appDisplayName": "Azure Portal",
            "ipAddress": TOR_EXIT_IPS[0],  # Frankfurt Tor node
            "userAgent": "python-requests/2.31.0",  # Automated credential stuffing / tool
            "location": {
                "city": "Frankfurt",
                "state": "HE",
                "countryOrRegion": "DE",
                "geoCoordinates": {"latitude": 50.1109, "longitude": 8.6821},
            },
            "status": {"errorCode": 0},
            "conditionalAccessStatus": "failure",
            "riskDetail": "unlikelyTravel",
            "riskLevelAggregated": "high",
            "riskState": "atRisk",
        }

        return [event1, event2]

    def generate_scenario_iam_privilege_escalation(self, offset_minutes: int) -> List[Dict[str, Any]]:
        """
        Scenario 2: AWS IAM Privilege Escalation & Backdoor Access Key
        MITRE ATT&CK: T1098 (Account Manipulation), T1078.004 (Cloud Accounts)
        A low-privilege service account suddenly attaches AdministratorAccess to an inactive user
        and creates a persistent backdoor access key.
        """
        t1 = self.base_time + timedelta(minutes=offset_minutes)
        t2 = t1 + timedelta(minutes=2)
        rogue_ip = SUSPICIOUS_EXTERNAL_IPS[0]

        event1 = {
            "eventVersion": "1.08",
            "userIdentity": {
                "type": "IAMUser",
                "principalId": "AIDA_COMPROMISED_JENKINS",
                "arn": "arn:aws:iam::123456789012:user/svc_ci_deployer",
                "accountId": "123456789012",
                "userName": "svc_ci_deployer",
            },
            "eventTime": t1.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "eventSource": "iam.amazonaws.com",
            "eventName": "AttachUserPolicy",
            "awsRegion": "us-east-1",
            "sourceIPAddress": rogue_ip,
            "userAgent": "aws-cli/2.15.15 Python/3.11.8 Linux/x86_64",
            "requestParameters": {
                "userName": "shadow_admin_backup",
                "policyArn": "arn:aws:iam::aws:policy/AdministratorAccess",
            },
            "responseElements": None,
            "eventID": str(uuid4()),
            "eventType": "AwsApiCall",
            "errorCode": None,
            "errorMessage": None,
        }

        event2 = {
            "eventVersion": "1.08",
            "userIdentity": {
                "type": "IAMUser",
                "principalId": "AIDA_COMPROMISED_JENKINS",
                "arn": "arn:aws:iam::123456789012:user/svc_ci_deployer",
                "accountId": "123456789012",
                "userName": "svc_ci_deployer",
            },
            "eventTime": t2.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "eventSource": "iam.amazonaws.com",
            "eventName": "CreateAccessKey",
            "awsRegion": "us-east-1",
            "sourceIPAddress": rogue_ip,
            "userAgent": "aws-cli/2.15.15 Python/3.11.8 Linux/x86_64",
            "requestParameters": {"userName": "shadow_admin_backup"},
            "responseElements": {
                "accessKey": {
                    "accessKeyId": "AKIA_BACKDOOR_KEY_99",
                    "status": "Active",
                    "userName": "shadow_admin_backup",
                }
            },
            "eventID": str(uuid4()),
            "eventType": "AwsApiCall",
            "errorCode": None,
        }

        return [event1, event2]

    def generate_scenario_s3_data_exfiltration(self, offset_minutes: int) -> List[Dict[str, Any]]:
        """
        Scenario 3: S3 Ransomware & Mass Data Exfiltration
        MITRE ATT&CK: T1530 (Data from Cloud Storage), T1485 (Data Destruction)
        Attacker bulk-downloads confidential financial buckets, then alters the bucket policy
        to lock out engineers and expose data publicly.
        """
        t1 = self.base_time + timedelta(minutes=offset_minutes)
        rogue_ip = SUSPICIOUS_EXTERNAL_IPS[1]

        events = []
        # Mass download burst
        for i in range(5):
            events.append({
                "eventVersion": "1.08",
                "userIdentity": {
                    "type": "IAMUser",
                    "userName": "alex.chen",
                    "arn": "arn:aws:iam::123456789012:user/alex.chen",
                },
                "eventTime": (t1 + timedelta(seconds=i * 10)).strftime("%Y-%m-%dT%H:%M:%SZ"),
                "eventSource": "s3.amazonaws.com",
                "eventName": "GetObject",
                "awsRegion": "us-east-1",
                "sourceIPAddress": rogue_ip,
                "userAgent": "curl/8.4.0",
                "requestParameters": {
                    "bucketName": "corp-confidential-mna-financials",
                    "key": f"financial_audit_ledger_2026_part{i+1}.xlsx",
                },
                "eventID": str(uuid4()),
            })

        # Policy lockout (ransomware / extortion)
        events.append({
            "eventVersion": "1.08",
            "userIdentity": {
                "type": "IAMUser",
                "userName": "alex.chen",
                "arn": "arn:aws:iam::123456789012:user/alex.chen",
            },
            "eventTime": (t1 + timedelta(minutes=2)).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "eventSource": "s3.amazonaws.com",
            "eventName": "PutBucketPolicy",
            "awsRegion": "us-east-1",
            "sourceIPAddress": rogue_ip,
            "userAgent": "curl/8.4.0",
            "requestParameters": {
                "bucketName": "corp-confidential-mna-financials",
                "policy": '{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Principal":"*","Action":"s3:*"}]}',
            },
            "eventID": str(uuid4()),
        })

        return events

    def generate_scenario_c2_beaconing(self, offset_minutes: int) -> List[Dict[str, Any]]:
        """
        Scenario 4: VPC Flow Log C2 Beaconing (Command & Control)
        MITRE ATT&CK: T1071 (Application Layer Protocol), T1571 (Non-Standard Port)
        An internal database host initiates persistent outbound connections to an external
        bulletproof IP on port 4444 every 60 seconds with identical small packet counts.
        """
        t1 = int((self.base_time + timedelta(minutes=offset_minutes)).timestamp())
        events = []
        for interval in range(4):
            events.append({
                "version": 2,
                "account_id": "123456789012",
                "interface_id": "eni-0c2beacon9999",
                "srcaddr": "10.0.2.15",  # Internal DB server
                "dstaddr": "45.33.32.156",  # External C2 Server
                "srcport": 49152 + interval,
                "dstport": 4444,  # Metasploit / Cobalt Strike default listener
                "protocol": 6,
                "packets": 5,
                "bytes": 320,  # Exact heartbeat pulse size
                "start": t1 + (interval * 60),
                "end": t1 + (interval * 60) + 10,
                "action": "ACCEPT",
                "log_status": "OK",
            })
        return events

    def generate_scenario_azure_rbac_backdoor(self, offset_minutes: int) -> List[Dict[str, Any]]:
        """
        Scenario 5: Azure RBAC Backdoor Role Assignment
        MITRE ATT&CK: T1098.003 (Additional Cloud Roles)
        Attacker grants 'Owner' role across root management group to an external rogue account.
        """
        t1 = self.base_time + timedelta(minutes=offset_minutes)
        return [{
            "time": t1.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "resourceId": "/subscriptions/sub-prod-001/providers/Microsoft.Authorization/roleAssignments/ra-shadow-owner-99",
            "operationName": "Microsoft.Authorization/roleAssignments/write",
            "category": "Administrative",
            "resultType": "Success",
            "caller": "elena.rostova@cybercorp.com",
            "callerIpAddress": SUSPICIOUS_EXTERNAL_IPS[2],
            "correlationId": str(uuid4()),
            "subscriptionId": "sub-prod-001",
            "properties": {
                "roleDefinitionId": "/providers/Microsoft.Authorization/roleDefinitions/8e3af657-a8ff-443c-a75c-2fe8c4bcb635",  # Azure Owner Role ID
                "principalId": "usr-ext-rogue-shadow@evilcorp.org",
                "scope": "/subscriptions/sub-prod-001",
            },
        }]

    # --------------------------------------------------------------------------
    # Full Dataset Assembler
    # --------------------------------------------------------------------------

    def generate_full_dataset(self, total_baseline: int = 500) -> List[Dict[str, Any]]:
        """
        Generates a blended timeline of benign telemetry and injected adversary attacks.
        Events are sorted chronologically.
        """
        all_events: List[Tuple[datetime, Dict[str, Any]]] = []

        # 1. Generate Benign Baseline (~95%)
        for i in range(total_baseline):
            offset = random.randint(0, 360)
            choice = random.random()
            if choice < 0.35:
                raw = self.generate_benign_cloudtrail(offset)
                ts = datetime.fromisoformat(raw["eventTime"].replace("Z", "+00:00"))
            elif choice < 0.60:
                raw = self.generate_benign_entra_signin(offset)
                ts = datetime.fromisoformat(raw["createdDateTime"].replace("Z", "+00:00"))
            elif choice < 0.85:
                raw = self.generate_benign_vpc_flow(offset)
                ts = datetime.fromtimestamp(raw["start"], timezone.utc)
            else:
                raw = self.generate_benign_activity_log(offset)
                ts = datetime.fromisoformat(raw["time"].replace("Z", "+00:00"))
            all_events.append((ts, raw))

        # 2. Inject Coordinated Attack Scenarios
        # Scenario 1: Impossible Travel at min 45
        for ev in self.generate_scenario_impossible_travel(45):
            ts = datetime.fromisoformat(ev["createdDateTime"].replace("Z", "+00:00"))
            all_events.append((ts, ev))

        # Scenario 2: IAM Privilege Escalation at min 120
        for ev in self.generate_scenario_iam_privilege_escalation(120):
            ts = datetime.fromisoformat(ev["eventTime"].replace("Z", "+00:00"))
            all_events.append((ts, ev))

        # Scenario 3: S3 Data Exfiltration at min 190
        for ev in self.generate_scenario_s3_data_exfiltration(190):
            ts = datetime.fromisoformat(ev["eventTime"].replace("Z", "+00:00"))
            all_events.append((ts, ev))

        # Scenario 4: C2 Beaconing at min 240
        for ev in self.generate_scenario_c2_beaconing(240):
            ts = datetime.fromtimestamp(ev["start"], timezone.utc)
            all_events.append((ts, ev))

        # Scenario 5: Azure RBAC Backdoor at min 310
        for ev in self.generate_scenario_azure_rbac_backdoor(310):
            ts = datetime.fromisoformat(ev["time"].replace("Z", "+00:00"))
            all_events.append((ts, ev))

        # Sort all telemetry strictly by timestamp
        all_events.sort(key=lambda x: x[0])
        return [item[1] for item in all_events]


def export_sample_dataset(output_path: str, count: int = 500) -> int:
    """Exports generated dataset to a JSON file."""
    gen = MultiCloudDataGenerator()
    data = gen.generate_full_dataset(total_baseline=count)
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)
    return len(data)


if __name__ == "__main__":
    count = export_sample_dataset("sample_multi_cloud_logs.json", 200)
    print(f"Generated {count} multi-cloud security records.")
