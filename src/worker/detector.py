"""
Unsupervised Anomaly Detector (IsolationForest).
Spec Reference: §6 System Design ("Why the risk score needs calibration").

Responsibilities:
1. Train unsupervised IsolationForest on unlabeled benign feature vectors.
2. Output unbounded anomaly scores s = -decision_function(X).
"""

from typing import Optional
import numpy as np
from sklearn.ensemble import IsolationForest


class AnomalyDetector:
    """Unsupervised IsolationForest detector scoring behavioral feature vectors."""

    def __init__(self, n_estimators: int = 100, contamination: float = 0.05, random_state: int = 42):
        self.model = IsolationForest(
            n_estimators=n_estimators,
            contamination=contamination,
            random_state=random_state
        )
        self.is_fitted = False

    def fit(self, X: np.ndarray) -> None:
        """Fit IsolationForest on baseline feature matrix X."""
        self.model.fit(X)
        self.is_fitted = True

    def score_raw(self, X: np.ndarray) -> np.ndarray:
        """
        Return raw unbounded anomaly score.
        score = -decision_function(X) -> Higher score means more anomalous.
        """
        if not self.is_fitted:
            raise RuntimeError("AnomalyDetector must be fitted before scoring.")
        if X.ndim == 1:
            X = X.reshape(1, -1)
        raw_dec = self.model.decision_function(X)
        # Invert so higher = more anomalous / risky
        return -raw_dec
