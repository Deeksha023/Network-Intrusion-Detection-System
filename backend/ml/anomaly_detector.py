"""
ml/anomaly_detector.py — Stage 2: PyTorch Autoencoder zero-day anomaly detector.

Trained exclusively on BENIGN (normal) traffic flows. Flows with reconstruction
MSE above `threshold` are flagged as anomalies.

Produced by: scripts/train_autoencoder.py
Threshold:   loaded from ml/artifacts/autoencoder_threshold.json, or supplied
             via AUTOENCODER_THRESHOLD env var, or passed directly.
"""
from __future__ import annotations

import json
import logging
import os
from typing import Optional

import numpy as np
import torch
import torch.nn as nn

logger = logging.getLogger(__name__)


class PyTorchAutoencoder(nn.Module):
    """
    Symmetric autoencoder architecture:
        Input(76) -> Dense(64, relu) -> Dense(32, relu) -> Dense(16, relu) [encoder]
                  -> Dense(32, relu) -> Dense(64, relu) -> Dense(76, linear) [decoder]
    """

    def __init__(self, input_dim: int = 76) -> None:
        super().__init__()
        self.encoder = nn.Sequential(
            nn.Linear(input_dim, 64),
            nn.ReLU(),
            nn.Linear(64, 32),
            nn.ReLU(),
            nn.Linear(32, 16),
            nn.ReLU(),
        )
        self.decoder = nn.Sequential(
            nn.Linear(16, 32),
            nn.ReLU(),
            nn.Linear(32, 64),
            nn.ReLU(),
            nn.Linear(64, input_dim),
        )

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        return self.decoder(self.encoder(x))


class AutoencoderDetector:
    """
    Wraps a PyTorch Autoencoder model for reconstruction-error anomaly detection.

    Lifecycle:
        detector = AutoencoderDetector(model_path, threshold)
        detector.load()
        is_anomaly, recon_error = detector.detect(features)
    """

    def __init__(self, model_path: str, threshold: float) -> None:
        """
        Args:
            model_path:  Absolute path to the PyTorch autoencoder model file (.pt or .pth).
            threshold:   Reconstruction MSE threshold. Flows above this are anomalies.
        """
        self.model_path = model_path
        self.threshold = threshold

        self._model: Optional[PyTorchAutoencoder] = None
        self._is_loaded: bool = False
        self._device = torch.device("cuda" if torch.cuda.is_available() else "cpu")

        # Try to update threshold from the companion JSON file if it exists
        base_dir = os.path.dirname(model_path)
        threshold_json = os.path.join(base_dir, "autoencoder_threshold.json")
        if os.path.exists(threshold_json):
            try:
                with open(threshold_json) as f:
                    data = json.load(f)
                self.threshold = float(data["threshold"])
                logger.debug(
                    "Loaded threshold %.8f from %s", self.threshold, threshold_json
                )
            except Exception as e:
                logger.warning("Could not load threshold from JSON: %s", e)

    def load(self) -> None:
        """Load the PyTorch autoencoder from disk."""
        target_path = self.model_path
        if not os.path.exists(target_path):
            base_dir = os.path.dirname(self.model_path)
            for alt in ["autoencoder.pt", "autoencoder.pth", "autoencoder.keras"]:
                alt_path = os.path.join(base_dir, alt)
                if os.path.exists(alt_path):
                    target_path = alt_path
                    break

        if not os.path.exists(target_path):
            logger.error(
                "Autoencoder model not found at %s. "
                "Run scripts/train_autoencoder.py first.",
                self.model_path,
            )
            return

        logger.info("Loading PyTorch autoencoder from %s", target_path)
        try:
            model = PyTorchAutoencoder(input_dim=76)
            checkpoint = torch.load(target_path, map_location=self._device)
            if isinstance(checkpoint, dict) and "state_dict" in checkpoint:
                model.load_state_dict(checkpoint["state_dict"])
            elif isinstance(checkpoint, (dict, torch.nn.modules.container.Sequential)) or hasattr(checkpoint, "keys"):
                if isinstance(checkpoint, nn.Module):
                    model = checkpoint
                else:
                    model.load_state_dict(checkpoint)
            else:
                model = checkpoint

            model.to(self._device)
            model.eval()
            self._model = model
            self._is_loaded = True
            logger.info(
                "AutoencoderDetector ready. Threshold=%.8f (Device: %s)",
                self.threshold,
                self._device,
            )
        except Exception as e:
            logger.error("Failed to load PyTorch autoencoder from %s: %s", target_path, e)

    def detect(self, features: np.ndarray) -> tuple[bool, float]:
        """
        Determine whether a flow is anomalous using PyTorch reconstruction MSE.

        Args:
            features: np.ndarray of shape (1, 76), dtype float32, already scaled.

        Returns:
            (is_anomaly, reconstruction_error)
        """
        if not self._is_loaded or self._model is None:
            logger.debug("detect: model not loaded — returning (False, 0.0)")
            return False, 0.0

        with torch.no_grad():
            inp_tensor = torch.tensor(features, dtype=torch.float32, device=self._device)
            reconstructed = self._model(inp_tensor)
            mse = float(torch.mean((inp_tensor - reconstructed) ** 2).item())

        return mse > self.threshold, mse

