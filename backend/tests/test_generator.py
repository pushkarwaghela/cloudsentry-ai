"""
Unit Tests - Multi-Cloud Telemetry & Attack Scenario Generator
==============================================================
Verifies that the synthetic generator creates valid raw schemas for both AWS and
Azure, and successfully generates all 5 multi-stage attack scenarios.
"""

from app.ingestion.generator import MultiCloudDataGenerator, export_sample_dataset
import tempfile
import os
import json


def test_generator_benign_events():
    gen = MultiCloudDataGenerator()

    # AWS CloudTrail
    ct = gen.generate_benign_cloudtrail(5)
    assert ct["eventVersion"] == "1.08"
    assert "userIdentity" in ct
    assert ct["eventSource"] in ["ec2.amazonaws.com", "s3.amazonaws.com", "cloudwatch.amazonaws.com", "signin.amazonaws.com", "sts.amazonaws.com"]

    # AWS VPC Flow
    vpc = gen.generate_benign_vpc_flow(10)
    assert vpc["version"] == 2
    assert vpc["action"] == "ACCEPT"
    assert vpc["protocol"] == 6

    # Azure Entra ID
    entra = gen.generate_benign_entra_signin(15)
    assert "@" in entra["userPrincipalName"]
    assert entra["status"]["errorCode"] == 0

    # Azure Activity
    act = gen.generate_benign_activity_log(20)
    assert "Microsoft." in act["operationName"]
    assert act["resultType"] == "Success"


def test_generator_attack_scenarios():
    gen = MultiCloudDataGenerator()

    # Scenario 1: Impossible Travel
    scen1 = gen.generate_scenario_impossible_travel(30)
    assert len(scen1) == 2
    assert scen1[0]["location"]["countryOrRegion"] == "US"
    assert scen1[1]["location"]["countryOrRegion"] == "DE"

    # Scenario 2: IAM Privilege Escalation
    scen2 = gen.generate_scenario_iam_privilege_escalation(60)
    assert len(scen2) == 2
    assert scen2[0]["eventName"] == "AttachUserPolicy"
    assert scen2[1]["eventName"] == "CreateAccessKey"

    # Scenario 3: S3 Ransomware / Exfiltration
    scen3 = gen.generate_scenario_s3_data_exfiltration(90)
    assert len(scen3) == 6  # 5 downloads + 1 policy denial
    assert scen3[-1]["eventName"] == "PutBucketPolicy"

    # Scenario 4: VPC Flow C2 Beaconing
    scen4 = gen.generate_scenario_c2_beaconing(120)
    assert len(scen4) == 4
    for record in scen4:
        assert record["dstport"] == 4444
        assert record["bytes"] == 320

    # Scenario 5: Azure RBAC Backdoor
    scen5 = gen.generate_scenario_azure_rbac_backdoor(150)
    assert len(scen5) == 1
    assert "roleAssignments" in scen5[0]["operationName"]


def test_export_sample_dataset():
    with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tf:
        tmp_path = tf.name

    try:
        count = export_sample_dataset(tmp_path, count=50)
        assert count >= 50
        with open(tmp_path, "r", encoding="utf-8") as f:
            data = json.load(f)
        assert len(data) == count
    finally:
        if os.path.exists(tmp_path):
            os.remove(tmp_path)
