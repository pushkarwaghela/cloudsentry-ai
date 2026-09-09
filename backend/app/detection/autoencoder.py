"""
CloudSentry AI - Deep Autoencoder Anomaly Detection Engine (PyTorch & Fallback)
==============================================================================

WHY A DEEP AUTOENCODER FOR SOC ANOMALY DETECTION?
In cybersecurity, supervised learning is difficult because:
1. True malicious attack samples are extremely rare in production (severe class imbalance).
2. Adversaries constantly invent novel zero-day techniques not present in training labels.

An Autoencoder solves this via unsupervised representation learning:
- The network is trained solely on benign enterprise telemetry.
- It compresses input features into a lower-dimensional latent bottleneck layer and
  attempts to reconstruct them.
- When normal events pass through, reconstruction error is minimal (near 0).
- When an adversary strikes (e.g. rare privilege escalation, impossible travel, C2 beacon),
  the network cannot accurately reconstruct the novel feature combination.
- The Reconstruction Mean Squared Error (MSE) directly correlates with the Anomaly Score.

CUDA / GPU ACCELERATION:
Tensor matrix operations benefit significantly from GPU hardware acceleration when
processing hundreds of thousands of events per minute. This module dynamically selects
CUDA if available, with graceful CPU execution.
"""

import logging
from typing import List, Optional, Tuple
import numpy as np

logger = logging.getLogger("cloudsentry.autoencoder")

# Check if PyTorch is available in current environment
try:
    import torch
    import torch.nn as nn
    import torch.optim as optim
    from torch.utils.data import DataLoader, TensorDataset
    HAS_TORCH = True
except ImportError:
    HAS_TORCH = False


if HAS_TORCH:
    class PyTorchAutoencoderNet(nn.Module):
        """
        Deep Neural Network Autoencoder with bottleneck latent representation.
        Architecture: Input(D) -> Dense(16) -> LeakyReLU -> Latent(6) -> Dense(16) -> LeakyReLU -> Output(D)
        """

        def __init__(self, input_dim: int, hidden_dim: int = 16, latent_dim: int = 6):
            super().__init__()
            self.encoder = nn.Sequential(
                nn.Linear(input_dim, hidden_dim),
                nn.BatchNorm1d(hidden_dim),
                nn.LeakyReLU(0.2),
                nn.Linear(hidden_dim, latent_dim),
            )
            self.decoder = nn.Sequential(
                nn.Linear(latent_dim, hidden_dim),
                nn.LeakyReLU(0.2),
                nn.Linear(hidden_dim, input_dim),
            )

        def forward(self, x: torch.Tensor) -> torch.Tensor:
            latent = self.encoder(x)
            reconstructed = self.decoder(latent)
            return reconstructed


class DeepAutoencoderDetector:
    """
    Autoencoder Anomaly Detector supporting PyTorch (GPU/CUDA + CPU)
    with seamless scikit-learn MLP neural network fallback.
    """

    def __init__(self, input_dim: int = 13, latent_dim: int = 6, lr: float = 0.005):
        self.input_dim = input_dim
        self.latent_dim = latent_dim
        self.lr = lr
        self.has_torch = HAS_TORCH
        self.is_trained = False
        self.threshold: float = 1.0

        if self.has_torch:
            self.device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
            logger.info(f"Initialized PyTorch Autoencoder on device: {self.device}")
            self.model = PyTorchAutoencoderNet(input_dim, hidden_dim=16, latent_dim=latent_dim).to(self.device)
            self.criterion = nn.MSELoss(reduction="none")
            self.optimizer = optim.Adam(self.model.parameters(), lr=lr)
        else:
            logger.info("PyTorch not detected. Initializing scikit-learn neural autoencoder fallback.")
            from sklearn.neural_network import MLPRegressor
            self.model = MLPRegressor(
                hidden_layer_sizes=(16, latent_dim, 16),
                activation="relu",
                solver="adam",
                max_iter=400,
                random_state=42,
            )

    def train(self, X_train: np.ndarray, epochs: int = 40, batch_size: int = 32) -> float:
        """
        Trains the autoencoder on normal baseline data.
        Returns final training loss.
        """
        if self.has_torch:
            self.model.train()
            tensor_x = torch.tensor(X_train, dtype=torch.float32)
            dataset = TensorDataset(tensor_x)
            loader = DataLoader(dataset, batch_size=batch_size, shuffle=True)

            final_loss = 0.0
            for epoch in range(epochs):
                total_loss = 0.0
                for batch in loader:
                    inputs = batch[0].to(self.device)
                    self.optimizer.zero_grad()
                    outputs = self.model(inputs)
                    loss = nn.MSELoss()(outputs, inputs)
                    loss.backward()
                    self.optimizer.step()
                    total_loss += loss.item() * len(inputs)
                final_loss = total_loss / len(X_train)

            # Compute 95th percentile baseline reconstruction error as anomaly threshold
            self.model.eval()
            with torch.no_grad():
                preds = self.model(tensor_x.to(self.device)).cpu().numpy()
                baseline_errors = np.mean(np.square(X_train - preds), axis=1)
                self.threshold = float(np.percentile(baseline_errors, 95))
        else:
            # Fit scikit-learn MLP Autoencoder (predicting X from X)
            self.model.fit(X_train, X_train)
            preds = self.model.predict(X_train)
            baseline_errors = np.mean(np.square(X_train - preds), axis=1)
            self.threshold = float(np.percentile(baseline_errors, 95))
            final_loss = float(np.mean(baseline_errors))

        self.is_trained = True
        logger.info(f"Autoencoder training complete. Baseline loss: {final_loss:.4f}, Anomaly Threshold: {self.threshold:.4f}")
        return final_loss

    def score_samples(self, X: np.ndarray) -> np.ndarray:
        """
        Computes reconstruction MSE error for each sample and scales to 0.0 - 100.0.
        Higher score = greater deviation from baseline.
        """
        if not self.is_trained:
            return np.full(len(X), 20.0, dtype=np.float32)

        if self.has_torch:
            self.model.eval()
            with torch.no_grad():
                tensor_x = torch.tensor(X, dtype=torch.float32).to(self.device)
                preds = self.model(tensor_x).cpu().numpy()
        else:
            preds = self.model.predict(X)

        # Calculate Mean Squared Error (MSE) per event
        reconstruction_errors = np.mean(np.square(X - preds), axis=1)

        # Non-linear piecewise calibration:
        # Inliers (<= threshold): score ranges from 5 to 40
        # Outliers (> threshold): score rapidly scales from 50 to 98
        relative_errors = reconstruction_errors / (self.threshold + 1e-6)
        scores = np.where(
            relative_errors <= 1.0,
            np.clip(relative_errors * 38.0, 5.0, 40.0),
            40.0 + 58.0 * (1.0 - np.exp(-1.5 * (relative_errors - 1.0))),
        )

        return np.clip(scores, 0.0, 100.0)
