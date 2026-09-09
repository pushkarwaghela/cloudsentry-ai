"""
Unit & Integration Tests - FastAPI SOC Platform Endpoints
=========================================================
Verifies REST API behavior, KQL querying, CSPM calculations, and live attack simulations.
"""

import pytest
from fastapi.testclient import TestClient
from app.main import app, store, _initialize_platform_data


@pytest.fixture(scope="module")
def client():
    _initialize_platform_data()
    with TestClient(app) as c:
        yield c


def test_api_health(client):
    res = client.get("/api/health")
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "HEALTHY"
    assert data["total_events"] > 0
    assert data["total_alerts"] > 0


def test_api_stats(client):
    res = client.get("/api/stats")
    assert res.status_code == 200
    data = res.json()
    assert data["total_events"] >= 300
    assert data["total_alerts"] >= 4
    assert data["critical_alerts"] > 0
    assert data["cspm_score"] > 0


def test_api_alerts_list(client):
    res = client.get("/api/alerts")
    assert res.status_code == 200
    alerts = res.json()
    assert len(alerts) > 0

    # Ensure sorted by risk_score desc
    scores = [a["risk_score"] for a in alerts]
    assert scores == sorted(scores, reverse=True)

    first = alerts[0]
    assert "incident_title" in first
    assert "mitre_techniques" in first
    assert "status" in first


def test_api_alert_detail_and_status_update(client):
    res = client.get("/api/alerts")
    alerts = res.json()
    alert_id = alerts[0]["event_id"]

    # Detail
    res_detail = client.get(f"/api/alerts/{alert_id}")
    assert res_detail.status_code == 200
    detail = res_detail.json()
    assert "triage" in detail
    assert "correlated_events" in detail
    assert "raw_log" in detail
    assert len(detail["triage"]["containment_playbook"]) > 0

    # Status update
    res_patch = client.patch(f"/api/alerts/{alert_id}/status", json={"status": "INVESTIGATING"})
    assert res_patch.status_code == 200
    assert res_patch.json()["status"] == "INVESTIGATING"


def test_api_kql_query(client):
    # Query: filter AWS events
    q1 = {"query": 'where cloud == "aws" | take 5'}
    res1 = client.post("/api/query/kql", json=q1)
    assert res1.status_code == 200
    data1 = res1.json()
    assert data1["count"] <= 5
    for row in data1["rows"]:
        assert row["cloud"] == "aws"

    # Query: project specific columns
    q2 = {"query": "where risk_score >= 60 | project timestamp, actor, action, risk_score | take 10"}
    res2 = client.post("/api/query/kql", json=q2)
    assert res2.status_code == 200
    data2 = res2.json()
    assert set(data2["columns"]) == {"timestamp", "actor", "action", "risk_score"}


def test_api_cspm_posture(client):
    res = client.get("/api/cspm")
    assert res.status_code == 200
    cspm = res.json()
    assert 0 <= cspm["posture_score"] <= 100
    assert cspm["total_checks"] == len(cspm["findings"])
    assert any(f["cloud"] == "aws" for f in cspm["findings"])
    assert any(f["cloud"] == "azure" for f in cspm["findings"])


def test_api_simulate_attack(client):
    res = client.post("/api/simulate/impossible_travel")
    assert res.status_code == 200
    data = res.json()
    assert data["scenario"] == "impossible_travel"
    assert data["events_injected"] == 2
    assert data["alerts_generated"] >= 1
    assert "Impossible Travel" in data["alerts"][0]["incident_title"]
