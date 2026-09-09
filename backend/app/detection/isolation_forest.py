"""
CloudSentry AI - Isolation Forest Anomaly Detection Baseline
===========================================================

WHY ISOLATION FOREST IN A SOC BENCHMARK?
Isolation Forest is a tree-based ensemble algorithm that isolates anomalies rather
than profiling normal points:
1. Anomalies are "few and different" — they require fewer random tree partitions
   to isolate from the rest of the dataset.
2. It serves as an essential comparative baseline against Deep Autoencoders.
3. In interview defense:
   "We benchmarked our PyTorch Autoencoder against Isolation Forest. While Isolation
   Forest is fast and requires no neural hyperparameter tuning, it struggles with
   complex non-linear interactions across high-dimensional multi-cloud events (e.g.
   subtle correlations between user velocity, API error sequences, and network ports)
   where the Deep Autoencoder's latent bottleneck excels."
"""

import logging
from typing import List, Optional
import numpy as np
from sklearn.ensemble import IsolationForest

logger = logging.getLogger("cloudsentry.isolation_forest")


class IsolationForestDetector:
    """
    Isolation Forest anomaly detector serving as the tabular comparator.
    """

    def __init__(self, contamination: float = 0.05, n_estimators: int = 100, random_state: int = 42):
        self.model = IsolationForest(
            contamination=contamination,
            n_estimators=n_estimators,
            random_state=random_state,
            n_jobs=-1,
        )
        self.is_trained = False

    def train(self, X_train: np.ndarray) -> None:
        """Trains the isolation forest on the baseline feature matrix."""
        self.model.fit(X_train)
        self.is_trained = True
        logger.info(f"Isolation Forest trained on {len(X_train)} samples.")

    def score_samples(self, X: np.ndarray) -> np.ndarray:
        """
        Computes calibrated anomaly scores (0.0 to 100.0).
        In scikit-learn:
        - score_samples returns negative scores for anomalies and positive for normal.
        We invert and normalize to [0, 100].
        """
        if not self.is_trained:
            return np.full(len(X), 20.0, dtype=np.float32)

        raw_scores = self.model.score_samples(X)  # Typical range: [-0.8, -0.3]
        # Invert: More negative -> higher anomaly
        inverted = -raw_scores

        # Min-max calibration to 0 - 100
        min_val = 0.35
        max_val = 0.75
        normalized = (inverted - min_val) / (max_val - min_val)
        scaled = normalized * 100.0

        return np.clip(scaled, 0.0, 100.0)
