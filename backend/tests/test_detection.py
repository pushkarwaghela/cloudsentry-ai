"""
Unit Tests - AI/ML Threat Detection Engine
==========================================
Verifies feature extraction, model training, scoring calibration, and
detection precision on normal vs adversary telemetry.
"""

import numpy as np
import pytest
from app.schemas.ocsf import EventSeverity, UnifiedOCSFEvent
from app.ingestion.generator import MultiCloudDataGenerator
from app.ingestion.normalizer import normalize_batch, normalize_event
from app.detection.features import FeatureExtractor
from app.detection.autoencoder import DeepAutoencoderDetector
from app.detection.isolation_forest import IsolationForestDetector
from app.detection.engine import ThreatDetectionEngine


@pytest.fixture
def dataset():
    gen = MultiCloudDataGenerator()
    raw_data = gen.generate_full_dataset(total_baseline=100)
    return normalize_batch(raw_data)


def test_feature_extractor(dataset):
    extractor = FeatureExtractor()
    X = extractor.transform(dataset, fit=True)

    assert X.shape[0] == len(dataset)
    assert X.shape[1] == len(FeatureExtractor.FEATURE_NAMES)
    assert not np.isnan(X).any()
    assert not np.isinf(X).any()


def test_autoencoder_and_isolation_forest(dataset):
    extractor = FeatureExtractor()
    benign = [e for e in dataset if e.severity == EventSeverity.INFORMATIONAL]
    X_train = extractor.transform(benign, fit=True)

    # Test Autoencoder
    ae = DeepAutoencoderDetector(input_dim=13, latent_dim=6)
    loss = ae.train(X_train)
    assert loss >= 0.0

    scores_ae = ae.score_samples(X_train)
    assert len(scores_ae) == len(X_train)
    assert (scores_ae >= 0.0).all() and (scores_ae <= 100.0).all()

    # Test Isolation Forest
    iso = IsolationForestDetector()
    iso.train(X_train)
    scores_iso = iso.score_samples(X_train)
    assert len(scores_iso) == len(X_train)
    assert (scores_iso >= 0.0).all() and (scores_iso <= 100.0).all()


def test_detection_engine_scores_attacks_high(dataset):
    engine = ThreatDetectionEngine()
    scored_events = engine.analyze_batch(dataset)

    # Find the injected attack events
    attacks = [
        e for e in scored_events
        if e.action in ["IAM_ATTACHUSERPOLICY", "IAM_CREATEACCESSKEY", "AZURE_RBAC_MUTATION", "PUTBUCKETPOLICY"]
        or (e.src_endpoint and e.src_endpoint.geo and e.src_endpoint.geo.city == "Frankfurt")
        or (e.dst_endpoint and e.dst_endpoint.port == 4444)
    ]

    assert len(attacks) > 0

    # Ensure every detected attack received high risk and was flagged as an anomaly
    for attack in attacks:
        assert attack.is_anomaly is True
        assert attack.risk_score >= 65.0
        assert attack.severity in [EventSeverity.HIGH, EventSeverity.CRITICAL]

    # Check benign events baseline distribution
    benign = [e for e in scored_events if e not in attacks and e.action in ["DescribeInstances", "ListBuckets"]]
    if benign:
        avg_benign_risk = np.mean([e.risk_score for e in benign])
        avg_attack_risk = np.mean([e.risk_score for e in attacks])
        assert avg_attack_risk > avg_benign_risk + 30.0  # Clear statistical separation
