"""
CloudSentry AI - Unified Threat Detection & Composite Risk Scoring Engine
========================================================================

WHY COMPOSITE RISK SCORING?
In a real enterprise SOC, relying 100% on Machine Learning leads to high false positive
rates, while relying 100% on static rules causes blind spots against zero-days.

CloudSentry AI employs a Defense-in-Depth Composite Scoring Model:
  Risk_Score = (0.50 * Autoencoder_Score) + (0.15 * IsolationForest_Score) + (0.35 * Rule_Heuristic_Score)

This hybrid architecture combines:
1. Deep Autoencoder (unsupervised pattern anomaly)
2. Isolation Forest (fast tree-partitioning baseline)
3. Deterministic Security Rules (high-fidelity known attack signatures)
"""

import logging
from typing import List, Optional
import numpy as np
from app.schemas.ocsf import EventSeverity, UnifiedOCSFEvent
from app.detection.features import FeatureExtractor
from app.detection.autoencoder import DeepAutoencoderDetector
from app.detection.isolation_forest import IsolationForestDetector

logger = logging.getLogger("cloudsentry.engine")


def _calculate_rule_heuristic(event: UnifiedOCSFEvent) -> float:
    """
    Computes deterministic security heuristic score based on MITRE cloud attack patterns.
    """
    score = 15.0  # Baseline ambient risk

    action = event.action.lower()
    raw_str = str(event.raw_log).lower()

    # 1. Critical IAM / RBAC Backdoor Patterns
    if "attachuserpolicy" in action and "administratoraccess" in raw_str:
        return 98.0
    if ("roleassignments" in action or "rbac" in action) and "owner" in raw_str:
        return 96.0
    if "createaccesskey" in action and ("shadow" in raw_str or "temp" in raw_str):
        return 92.0

    # 2. Ransomware / Data Exfiltration
    if "putbucketpolicy" in action and "deny" in raw_str:
        return 95.0

    # 3. Impossible Travel & Tor Ingress
    if "unlikelytravel" in raw_str or "tor exit node" in str(event.src_endpoint).lower() or "frankfurt" in str(event.src_endpoint).lower():
        return 94.0

    # 4. Command & Control (C2) / Sensitive Ports
    dst_port = event.dst_endpoint.port if event.dst_endpoint else None
    if dst_port in [4444, 1337, 31337]:
        return 92.0

    # 5. Upstream Scanner Alert
    if event.category.value == "security_finding":
        return 90.0

    # 6. Status Penalties
    if event.status.value in ["DENIED", "FAILURE"]:
        score += 25.0

    # 7. Sensitive Action Base Boost
    if any(k in action for k in ["policy", "iam", "role", "key"]):
        score += 25.0

    return min(score, 100.0)


class ThreatDetectionEngine:
    """
    Main detection pipeline managing feature transformation, model inference,
    and composite risk evaluation.
    """

    def __init__(self):
        self.features = FeatureExtractor()
        self.autoencoder = DeepAutoencoderDetector(input_dim=13, latent_dim=6)
        self.iso_forest = IsolationForestDetector(contamination=0.05)
        self.is_ready = False

    def train(self, baseline_events: List[UnifiedOCSFEvent]) -> None:
        """Trains both ML models on normal baseline events."""
        logger.info(f"Training threat detection engine on {len(baseline_events)} events...")
        X = self.features.transform(baseline_events, fit=True)
        self.autoencoder.train(X)
        self.iso_forest.train(X)
        self.is_ready = True
        logger.info("Threat detection engine training completed successfully.")

    def analyze_batch(self, events: List[UnifiedOCSFEvent]) -> List[UnifiedOCSFEvent]:
        """
        Scores a batch of events with anomaly and composite risk scores.
        """
        if not events:
            return []

        # If models have not been trained yet, train on the first benign subset or fit on current batch
        if not self.is_ready:
            benign_events = [e for e in events if e.severity == EventSeverity.INFORMATIONAL]
            train_set = benign_events if len(benign_events) >= 20 else events
            self.train(train_set)

        X = self.features.transform(events, fit=False)

        ae_scores = self.autoencoder.score_samples(X)
        if_scores = self.iso_forest.score_samples(X)

        for idx, event in enumerate(events):
            ae_score = float(ae_scores[idx])
            if_score = float(if_scores[idx])
            rule_score = _calculate_rule_heuristic(event)

            # Composite weighted risk calculation
            composite_risk = (0.50 * ae_score) + (0.15 * if_score) + (0.35 * rule_score)
            if rule_score >= 80.0:
                composite_risk = max(composite_risk, rule_score * 0.85)
            composite_risk = float(np.clip(composite_risk, 0.0, 100.0))

            event.anomaly_score = round(ae_score, 1)
            event.risk_score = round(composite_risk, 1)
            event.is_anomaly = composite_risk >= 65.0

            # Calibrate severity based on composite risk
            if composite_risk >= 80.0:
                event.severity = EventSeverity.CRITICAL
            elif composite_risk >= 65.0:
                event.severity = EventSeverity.HIGH
            elif composite_risk >= 45.0:
                event.severity = EventSeverity.MEDIUM
            elif composite_risk >= 25.0:
                event.severity = EventSeverity.LOW
            else:
                event.severity = EventSeverity.INFORMATIONAL

        return events

    def analyze_event(self, event: UnifiedOCSFEvent) -> UnifiedOCSFEvent:
        """Scores a single event."""
        return self.analyze_batch([event])[0]
