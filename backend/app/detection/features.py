"""
CloudSentry AI - Threat Detection Feature Extraction Pipeline
============================================================

Transforms heterogeneous, normalized OCSF events into rich, dense numerical
feature vectors for machine learning anomaly detection.

WHY FEATURE ENGINEERING MATTERS IN SOC AI:
Raw logs cannot be directly fed to machine learning models. Feature extraction
encodes security domain heuristics (e.g. impossible travel velocity, sensitive port
activity, off-hours access, administrative privilege mutations) into continuous
latent vectors.
"""

import math
from datetime import datetime
from typing import Any, Dict, List, Tuple
import numpy as np
from sklearn.preprocessing import StandardScaler
from app.schemas.ocsf import OCSFCategory, UnifiedOCSFEvent

# Domain-specific action risk weights (0.0 to 1.0)
ACTION_RISK_WEIGHTS: Dict[str, float] = {
    # High-risk IAM & Privilege actions
    "IAM_ATTACHUSERPOLICY": 0.95,
    "IAM_ATTACHROLEPOLICY": 0.95,
    "IAM_CREATEACCESSKEY": 0.85,
    "IAM_CREATEUSER": 0.80,
    "AZURE_RBAC_MUTATION": 0.95,
    "PUT_POLICY": 0.90,
    "PUTBUCKETPOLICY": 0.90,
    # High-risk network / command actions
    "FLOW_ACCEPT": 0.10,
    "FLOW_REJECT": 0.35,
    "GUARDDUTY_DETECTION": 0.95,
    "DEFENDER_DETECTION": 0.95,
    # Standard identity & management
    "LOGIN": 0.20,
    "ENTRA_SIGNIN": 0.20,
    "ASSUME_ROLE": 0.30,
    "RESOURCE_WRITE": 0.40,
    "RESOURCE_READ": 0.05,
}

SENSITIVE_PORTS = {22, 3389, 4444, 1337, 31337, 6667, 8080, 8443}


class FeatureExtractor:
    """
    Extracts security-centric numerical vectors from UnifiedOCSFEvent objects.
    """

    FEATURE_NAMES = [
        "hour_sin",
        "hour_cos",
        "day_of_week",
        "is_off_hours",
        "log_bytes",
        "is_sensitive_port",
        "is_auth_event",
        "is_iam_mutation",
        "is_denied_or_failed",
        "is_high_risk_geo",
        "is_admin_actor",
        "has_security_finding",
        "action_risk_weight",
    ]

    def __init__(self):
        self.scaler = StandardScaler()
        self.is_fitted = False

    def extract_single_event(self, event: UnifiedOCSFEvent) -> List[float]:
        """Converts a single UnifiedOCSFEvent into a raw numerical feature list."""
        ts = event.timestamp

        # 1. Cyclical Time Encoding (captures hour 23 -> 0 continuity)
        hour = ts.hour + (ts.minute / 60.0)
        hour_sin = math.sin(2 * math.pi * hour / 24.0)
        hour_cos = math.cos(2 * math.pi * hour / 24.0)

        # 2. Day of Week & Off-hours Heuristic (typical work hours: 07:00 - 19:00 UTC)
        day_of_week = float(ts.weekday())
        is_off_hours = 1.0 if (ts.hour < 7 or ts.hour >= 19 or ts.weekday() >= 5) else 0.0

        # 3. Network Metrics (log-transformed to handle extreme outliers)
        raw_bytes = event.bytes_transferred or 0
        log_bytes = float(np.log1p(raw_bytes))

        # 4. Sensitive Port Check
        dst_port = event.dst_endpoint.port if event.dst_endpoint else None
        src_port = event.src_endpoint.port if event.src_endpoint else None
        is_sensitive_port = 1.0 if (dst_port in SENSITIVE_PORTS or src_port in SENSITIVE_PORTS) else 0.0

        # 5. Categorical Indicators
        is_auth = 1.0 if event.category == OCSFCategory.AUTHENTICATION else 0.0
        is_iam = 1.0 if (
            event.category == OCSFCategory.AUTHORIZATION
            or "iam" in event.action.lower()
            or "rbac" in event.action.lower()
            or "policy" in event.action.lower()
        ) else 0.0

        # 6. Status Indicator
        is_failed = 1.0 if event.status in ["FAILURE", "DENIED"] else 0.0

        # 7. Geo & IP Risk Indicators
        country = event.src_endpoint.geo.country if (event.src_endpoint and event.src_endpoint.geo) else "Unknown"
        isp = event.src_endpoint.geo.isp if (event.src_endpoint and event.src_endpoint.geo) else ""
        is_high_risk_geo = 1.0 if (
            "tor" in (isp or "").lower()
            or country in ["Russia", "China", "Iran", "North Korea"]
            or any("risk:high" in tag for tag in event.tags)
            or "unlikelyTravel" in str(event.raw_log)
        ) else 0.0

        # 8. Administrative Actor Indicator
        actor_name = (event.actor.user_name or "").lower()
        is_admin = 1.0 if any(k in actor_name for k in ["admin", "root", "shadow", "svc_ci", "deployer"]) else 0.0

        # 9. Upstream Security Finding
        has_finding = 1.0 if event.category == OCSFCategory.SECURITY_FINDING else 0.0

        # 10. Action Weight
        action_weight = ACTION_RISK_WEIGHTS.get(event.action.upper(), 0.2)

        return [
            hour_sin,
            hour_cos,
            day_of_week,
            is_off_hours,
            log_bytes,
            is_sensitive_port,
            is_auth,
            is_iam,
            is_failed,
            is_high_risk_geo,
            is_admin,
            has_finding,
            action_weight,
        ]

    def transform(self, events: List[UnifiedOCSFEvent], fit: bool = False) -> np.ndarray:
        """Transforms a batch of events into scaled NumPy matrix."""
        raw_matrix = np.array([self.extract_single_event(e) for e in events], dtype=np.float32)

        if fit or not self.is_fitted:
            scaled = self.scaler.fit_transform(raw_matrix)
            self.is_fitted = True
            return scaled
        return self.scaler.transform(raw_matrix)
