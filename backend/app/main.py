"""
CloudSentry AI - Production FastAPI Security Operations Backend
==============================================================

Main REST API service delivering real-time multi-cloud telemetry ingestion,
AI anomaly detection, LLM alert triage, KQL querying, and CSPM posture checks.
"""

from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
import logging
from typing import Any, Dict, List, Optional
from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from app.schemas.ocsf import CloudProvider, EventSeverity, UnifiedOCSFEvent
from app.schemas.triage import AlertTriageReport
from app.ingestion.generator import MultiCloudDataGenerator
from app.ingestion.normalizer import normalize_batch, normalize_event
from app.detection.engine import ThreatDetectionEngine
from app.triage.llm_client import LLMTriageClient
from app.api.kql_engine import execute_kql
from app.api.cspm import evaluate_cspm_posture, CSPMReport

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")
logger = logging.getLogger("cloudsentry.api")


# Global Application State
class SOCDataStore:
    events: List[UnifiedOCSFEvent] = []
    triage_reports: Dict[str, AlertTriageReport] = {}
    alert_statuses: Dict[str, str] = {}  # event_id -> "NEW" | "INVESTIGATING" | "CONTAINED" | "RESOLVED"
    detection_engine: ThreatDetectionEngine = ThreatDetectionEngine()
    llm_client: LLMTriageClient = LLMTriageClient()


store = SOCDataStore()


def _initialize_platform_data():
    """Generates baseline telemetry, trains ML models, and triages injected threats."""
    logger.info("Initializing CloudSentry AI multi-cloud state...")
    gen = MultiCloudDataGenerator()
    raw_telemetry = gen.generate_full_dataset(total_baseline=300)
    normalized = normalize_batch(raw_telemetry)

    # Train and score with detection engine
    scored_events = store.detection_engine.analyze_batch(normalized)
    store.events = scored_events

    # Automatically triage anomalies with LLM engine
    for event in store.events:
        if event.is_anomaly or event.severity in [EventSeverity.CRITICAL, EventSeverity.HIGH]:
            report = store.llm_client.triage_event(event)
            store.triage_reports[event.event_id] = report
            store.alert_statuses[event.event_id] = "NEW"

    logger.info(f"Initialized with {len(store.events)} events and {len(store.triage_reports)} triaged alerts.")


@asynccontextmanager
async def lifespan(app: FastAPI):
    _initialize_platform_data()
    yield


app = FastAPI(
    title="CloudSentry AI - SOC Threat Detection & Triage API",
    description="Multi-cloud AI-powered SOC threat detection, OCSF normalization, and LLM triage engine.",
    version="1.0.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ==============================================================================
# Request / Response Models
# ==============================================================================

class KQLQueryRequest(BaseModel):
    query: str


class AlertStatusUpdate(BaseModel):
    status: str  # "NEW", "INVESTIGATING", "CONTAINED", "RESOLVED", "DISMISSED"


class DashboardStats(BaseModel):
    total_events: int
    total_alerts: int
    critical_alerts: int
    high_alerts: int
    aws_event_count: int
    azure_event_count: int
    cspm_score: int
    models_ready: bool
    llm_provider: str


# ==============================================================================
# REST Endpoints
# ==============================================================================

@app.get("/api/health")
def get_health():
    return {
        "status": "HEALTHY",
        "service": "CloudSentry AI SOC Backend",
        "models_ready": store.detection_engine.is_ready,
        "llm_provider": store.llm_client.provider,
        "total_events": len(store.events),
        "total_alerts": len(store.triage_reports),
    }


@app.get("/api/stats", response_model=DashboardStats)
def get_stats():
    alerts = [e for e in store.events if e.event_id in store.triage_reports]
    crit = sum(1 for a in alerts if a.severity == EventSeverity.CRITICAL)
    high = sum(1 for a in alerts if a.severity == EventSeverity.HIGH)
    aws_cnt = sum(1 for e in store.events if e.cloud_provider == CloudProvider.AWS)
    azure_cnt = sum(1 for e in store.events if e.cloud_provider == CloudProvider.AZURE)
    cspm = evaluate_cspm_posture()

    return DashboardStats(
        total_events=len(store.events),
        total_alerts=len(alerts),
        critical_alerts=crit,
        high_alerts=high,
        aws_event_count=aws_cnt,
        azure_event_count=azure_cnt,
        cspm_score=cspm.posture_score,
        models_ready=store.detection_engine.is_ready,
        llm_provider=store.llm_client.provider,
    )


@app.get("/api/alerts")
def list_alerts(
    cloud: Optional[str] = Query(None, description="Filter by cloud: aws, azure"),
    severity: Optional[str] = Query(None, description="Filter by severity: CRITICAL, HIGH, MEDIUM, LOW"),
    status: Optional[str] = Query(None, description="Filter by status: NEW, INVESTIGATING, etc."),
    limit: int = 50,
):
    """Returns alerts sorted by composite risk score descending."""
    results = []
    for event in store.events:
        if event.event_id not in store.triage_reports:
            continue

        if cloud and event.cloud_provider.value.lower() != cloud.lower():
            continue
        if severity and event.severity.value.upper() != severity.upper():
            continue

        current_status = store.alert_statuses.get(event.event_id, "NEW")
        if status and current_status.upper() != status.upper():
            continue

        triage = store.triage_reports[event.event_id]
        results.append({
            "event_id": event.event_id,
            "timestamp": event.timestamp.isoformat(),
            "cloud_provider": event.cloud_provider.value,
            "source_service": event.source_service,
            "action": event.action,
            "actor": event.actor.user_name,
            "actor_type": event.actor.principal_type,
            "severity": event.severity.value,
            "anomaly_score": event.anomaly_score,
            "risk_score": event.risk_score,
            "incident_title": triage.incident_title,
            "verdict": triage.triage_verdict.value,
            "mitre_techniques": [f"{m.technique_id} - {m.technique_name}" for m in triage.mitre_attack],
            "status": current_status,
        })

    # Sort by risk score descending
    results.sort(key=lambda x: x["risk_score"] or 0.0, reverse=True)
    return results[:limit]


@app.get("/api/alerts/{event_id}")
def get_alert_detail(event_id: str):
    """Deep dive into a single alert: event, LLM triage, correlated timeline, raw log."""
    event = next((e for e in store.events if e.event_id == event_id), None)
    if not event:
        raise HTTPException(status_code=404, detail="Alert event not found.")

    triage = store.triage_reports.get(event_id)
    if not triage:
        # Generate on-demand if not pre-cached
        triage = store.llm_client.triage_event(event)
        store.triage_reports[event_id] = triage
        store.alert_statuses[event_id] = "NEW"

    # Correlated Events Timeline (blast radius: ±60 mins from same actor or IP)
    actor_name = event.actor.user_name
    src_ip = event.src_endpoint.ip if event.src_endpoint else None
    t0 = event.timestamp

    correlated = []
    for other in store.events:
        if other.event_id == event.event_id:
            continue
        dt_mins = abs((other.timestamp - t0).total_seconds()) / 60.0
        if dt_mins <= 60.0:
            same_actor = (actor_name and other.actor.user_name == actor_name)
            same_ip = (src_ip and other.src_endpoint and other.src_endpoint.ip == src_ip)
            if same_actor or same_ip:
                correlated.append({
                    "event_id": other.event_id,
                    "timestamp": other.timestamp.isoformat(),
                    "action": other.action,
                    "actor": other.actor.user_name,
                    "cloud": other.cloud_provider.value,
                    "status": other.status.value,
                    "risk_score": other.risk_score,
                    "correlation_reason": "Same Actor" if same_actor else "Same IP Address",
                })

    correlated.sort(key=lambda x: x["timestamp"])

    return {
        "event": event,
        "triage": triage,
        "status": store.alert_statuses.get(event_id, "NEW"),
        "raw_log": event.raw_log,
        "correlated_events": correlated,
    }


@app.patch("/api/alerts/{event_id}/status")
def update_alert_status(event_id: str, update: AlertStatusUpdate):
    if event_id not in store.triage_reports:
        raise HTTPException(status_code=404, detail="Alert not found.")
    store.alert_statuses[event_id] = update.status.upper()
    return {"event_id": event_id, "status": store.alert_statuses[event_id]}


@app.post("/api/query/kql")
def run_kql_query(req: KQLQueryRequest):
    """Executes Sentinel-style KQL query over the ingested security events."""
    try:
        return execute_kql(req.query, store.events)
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"KQL execution error: {str(e)}")


@app.get("/api/cspm", response_model=CSPMReport)
def get_cspm_posture():
    """Returns CIS benchmark cloud posture checks and score."""
    return evaluate_cspm_posture()


@app.post("/api/simulate/{scenario_name}")
def trigger_attack_simulation(scenario_name: str):
    """
    Dynamically injects a specific multi-cloud attack scenario for live demo.
    Scenarios: 'impossible_travel', 'iam_escalation', 's3_exfiltration', 'c2_beaconing', 'azure_rbac'
    """
    gen = MultiCloudDataGenerator(base_time=datetime.now(timezone.utc) - timedelta(minutes=5))

    scenario_map = {
        "impossible_travel": gen.generate_scenario_impossible_travel,
        "iam_escalation": gen.generate_scenario_iam_privilege_escalation,
        "s3_exfiltration": gen.generate_scenario_s3_data_exfiltration,
        "c2_beaconing": gen.generate_scenario_c2_beaconing,
        "azure_rbac": gen.generate_scenario_azure_rbac_backdoor,
    }

    if scenario_name not in scenario_map:
        raise HTTPException(status_code=400, detail=f"Unknown scenario. Available: {list(scenario_map.keys())}")

    raw_events = scenario_map[scenario_name](0)
    normalized = normalize_batch(raw_events)
    scored = store.detection_engine.analyze_batch(normalized)

    new_alerts = []
    for ev in scored:
        store.events.insert(0, ev)
        if ev.is_anomaly or ev.severity in [EventSeverity.CRITICAL, EventSeverity.HIGH]:
            report = store.llm_client.triage_event(ev)
            store.triage_reports[ev.event_id] = report
            store.alert_statuses[ev.event_id] = "NEW"
            new_alerts.append(report)

    return {
        "scenario": scenario_name,
        "events_injected": len(scored),
        "alerts_generated": len(new_alerts),
        "alerts": new_alerts,
    }
