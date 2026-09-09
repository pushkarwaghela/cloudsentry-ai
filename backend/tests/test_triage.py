"""
Unit Tests - LLM & Expert Alert Triage Engine
=============================================
Verifies MITRE ATT&CK mapping, incident summarization, containment playbook
generation, and pluggable provider fallbacks.
"""

import pytest
from app.ingestion.generator import MultiCloudDataGenerator
from app.ingestion.normalizer import normalize_event
from app.schemas.triage import AlertTriageReport, TriageVerdict
from app.triage.expert_rules import (
    triage_impossible_travel,
    triage_iam_privilege_escalation,
    triage_s3_data_exfiltration,
    triage_c2_beaconing,
    triage_azure_rbac_backdoor,
)
from app.triage.llm_client import LLMTriageClient


@pytest.fixture
def generator():
    return MultiCloudDataGenerator()


def test_triage_impossible_travel(generator):
    scenario = generator.generate_scenario_impossible_travel(10)
    rogue_event = normalize_event(scenario[1])

    report = triage_impossible_travel(rogue_event)
    assert isinstance(report, AlertTriageReport)
    assert report.triage_verdict == TriageVerdict.TRUE_POSITIVE_MALICIOUS
    assert report.recommended_severity == "CRITICAL"
    assert any(m.technique_id == "T1078.004" for m in report.mitre_attack)
    assert len(report.containment_playbook) >= 2
    assert "revokeSignInSessions" in report.containment_playbook[0].command


def test_triage_iam_privilege_escalation(generator):
    scenario = generator.generate_scenario_iam_privilege_escalation(20)
    escalation_event = normalize_event(scenario[0])

    report = triage_iam_privilege_escalation(escalation_event)
    assert isinstance(report, AlertTriageReport)
    assert report.triage_verdict == TriageVerdict.TRUE_POSITIVE_MALICIOUS
    assert any(m.technique_id == "T1098" for m in report.mitre_attack)
    assert "detach-user-policy" in report.containment_playbook[0].command


def test_triage_s3_data_exfiltration(generator):
    scenario = generator.generate_scenario_s3_data_exfiltration(30)
    lockout_event = normalize_event(scenario[-1])

    report = triage_s3_data_exfiltration(lockout_event)
    assert isinstance(report, AlertTriageReport)
    assert any(m.technique_id == "T1530" for m in report.mitre_attack)
    assert "delete-bucket-policy" in report.containment_playbook[0].command


def test_triage_c2_beaconing(generator):
    scenario = generator.generate_scenario_c2_beaconing(40)
    beacon_event = normalize_event(scenario[0])

    report = triage_c2_beaconing(beacon_event)
    assert isinstance(report, AlertTriageReport)
    assert any(m.technique_id == "T1071" for m in report.mitre_attack)
    assert "modify-instance-attribute" in report.containment_playbook[0].command


def test_triage_azure_rbac_backdoor(generator):
    scenario = generator.generate_scenario_azure_rbac_backdoor(50)
    rbac_event = normalize_event(scenario[0])

    report = triage_azure_rbac_backdoor(rbac_event)
    assert isinstance(report, AlertTriageReport)
    assert any(m.technique_id == "T1098.003" for m in report.mitre_attack)
    assert "az role assignment delete" in report.containment_playbook[0].command


def test_llm_triage_client_fallback(generator):
    client = LLMTriageClient(provider="auto")
    scenario = generator.generate_scenario_impossible_travel(60)
    event = normalize_event(scenario[1])
    event.anomaly_score = 92.0
    event.risk_score = 94.0

    report = client.triage_event(event)
    assert isinstance(report, AlertTriageReport)
    assert report.event_id == event.event_id
    assert report.confidence_score >= 0.8
    assert len(report.mitre_attack) > 0
    assert len(report.containment_playbook) > 0
    assert report.inference_time_ms >= 0.0
