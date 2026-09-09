"""
Unit Tests - Multi-Cloud Ingestion & OCSF Normalization
======================================================
Verifies that disparate telemetry schemas from AWS and Azure are correctly
parsed, fingerprinted, and normalized into standard OCSF UnifiedOCSFEvent models.
"""

import pytest
from app.schemas.ocsf import (
    CloudProvider,
    OCSFCategory,
    EventSeverity,
    EventStatus,
    UnifiedOCSFEvent,
)
from app.ingestion.normalizer import (
    detect_telemetry_type,
    normalize_event,
    normalize_batch,
)
from app.ingestion.generator import MultiCloudDataGenerator


@pytest.fixture
def generator():
    return MultiCloudDataGenerator()


def test_detect_telemetry_type(generator):
    ct = generator.generate_benign_cloudtrail(0)
    assert detect_telemetry_type(ct) == ("aws", "cloudtrail")

    vpc = generator.generate_benign_vpc_flow(0)
    assert detect_telemetry_type(vpc) == ("aws", "vpc_flow")

    entra = generator.generate_benign_entra_signin(0)
    assert detect_telemetry_type(entra) == ("azure", "azure_ad")

    act = generator.generate_benign_activity_log(0)
    assert detect_telemetry_type(act) == ("azure", "activity_log")


def test_normalize_aws_cloudtrail(generator):
    ct = generator.generate_benign_cloudtrail(10)
    event = normalize_event(ct)

    assert isinstance(event, UnifiedOCSFEvent)
    assert event.cloud_provider == CloudProvider.AWS
    assert event.source_service == "cloudtrail"
    assert event.actor.user_name is not None
    assert event.status in [EventStatus.SUCCESS, EventStatus.FAILURE]
    assert event.raw_log == ct


def test_normalize_aws_vpc_flow(generator):
    vpc = generator.generate_benign_vpc_flow(15)
    event = normalize_event(vpc)

    assert isinstance(event, UnifiedOCSFEvent)
    assert event.cloud_provider == CloudProvider.AWS
    assert event.source_service == "vpc_flow"
    assert event.category == OCSFCategory.NETWORK_ACTIVITY
    assert event.protocol == "TCP"
    assert event.bytes_transferred > 0
    assert event.packets_transferred > 0
    assert event.src_endpoint.ip is not None
    assert event.dst_endpoint.ip is not None


def test_normalize_azure_entra_signin(generator):
    entra = generator.generate_benign_entra_signin(20)
    event = normalize_event(entra)

    assert isinstance(event, UnifiedOCSFEvent)
    assert event.cloud_provider == CloudProvider.AZURE
    assert event.source_service == "azure_ad"
    assert event.category == OCSFCategory.AUTHENTICATION
    assert event.action == "ENTRA_SIGNIN"
    assert "@" in event.actor.user_name
    assert event.src_endpoint.geo.country == "US"


def test_normalize_azure_activity_log(generator):
    act = generator.generate_benign_activity_log(25)
    event = normalize_event(act)

    assert isinstance(event, UnifiedOCSFEvent)
    assert event.cloud_provider == CloudProvider.AZURE
    assert event.source_service == "activity_log"
    assert event.target is not None
    assert event.actor.account_id == "sub-prod-001"


def test_normalize_attack_impossible_travel(generator):
    scenario = generator.generate_scenario_impossible_travel(30)
    assert len(scenario) == 2

    # Normal login
    ev1 = normalize_event(scenario[0])
    assert ev1.src_endpoint.geo.city == "Seattle"
    assert ev1.severity == EventSeverity.INFORMATIONAL

    # Tor exit node rogue login
    ev2 = normalize_event(scenario[1])
    assert ev2.src_endpoint.geo.city == "Frankfurt"
    assert ev2.severity in [EventSeverity.HIGH, EventSeverity.CRITICAL]
    assert any("risk:high" in tag for tag in ev2.tags)


def test_normalize_attack_iam_escalation(generator):
    scenario = generator.generate_scenario_iam_privilege_escalation(40)
    ev_policy = normalize_event(scenario[0])
    ev_key = normalize_event(scenario[1])

    assert ev_policy.category == OCSFCategory.AUTHORIZATION
    assert ev_policy.severity == EventSeverity.HIGH
    assert ev_policy.action == "IAM_ATTACHUSERPOLICY"

    assert ev_key.category == OCSFCategory.AUTHORIZATION
    assert ev_key.action == "IAM_CREATEACCESSKEY"


def test_normalize_batch(generator):
    records = generator.generate_full_dataset(total_baseline=50)
    normalized = normalize_batch(records)

    assert len(normalized) >= 50
    # Confirm both AWS and Azure are represented
    providers = {e.cloud_provider for e in normalized}
    assert CloudProvider.AWS in providers
    assert CloudProvider.AZURE in providers
