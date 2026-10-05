"""
Risk Score Calibrator and Calibration Diagnostics.
Spec Reference: §6 System Design ("Why the risk score needs calibration") & §5 Calibration Metrics.

Transforms raw decision scores into calibrated posterior probabilities:
  p = P(malice | score) ∈ [0, 1]
using Isotonic Regression or Platt Scaling (logistic sigmoid).
"""

from typing import Tuple, Dict, Any, Optional
import numpy as np
from sklearn.isotonic import IsotonicRegression
from sklearn.linear_model import LogisticRegression


class RiskCalibrator:
    """Calibrates raw decision scores to true posterior probabilities."""

    def __init__(self, method: str = "isotonic"):
        self.method = method
        self.calibrator = None
        self.is_fitted = False

    def fit(self, raw_scores: np.ndarray, y_labels: np.ndarray) -> None:
        """
        Fit isotonic regression or Platt scaling on validation holdout.
        raw_scores: 1D array of unbounded anomaly scores.
        y_labels: 1D binary array (0 = benign, 1 = malicious).
        """
        scores = np.asarray(raw_scores).ravel()
        labels = np.asarray(y_labels).ravel()

        if self.method == "isotonic":
            self.calibrator = IsotonicRegression(out_of_bounds="clip", y_min=0.001, y_max=0.999)
            self.calibrator.fit(scores, labels)
        elif self.method == "sigmoid":
            # Platt scaling via 1D Logistic Regression
            self.calibrator = LogisticRegression(C=1.0, solver="lbfgs")
            self.calibrator.fit(scores.reshape(-1, 1), labels)
        else:
            raise ValueError(f"Unknown calibration method: {self.method}")

        self.is_fitted = True

    def predict_proba(self, raw_scores: np.ndarray) -> np.ndarray:
        """
        Transform raw anomaly scores to calibrated probabilities p ∈ [0, 1].
        """
        if not self.is_fitted:
            raise RuntimeError("RiskCalibrator must be fitted before predict_proba.")

        scores = np.asarray(raw_scores).ravel()
        if self.method == "isotonic":
            probs = self.calibrator.predict(scores)
        else:
            probs = self.calibrator.predict_proba(scores.reshape(-1, 1))[:, 1]

        return np.clip(probs, 0.0, 1.0)

    @staticmethod
    def compute_ece(y_true: np.ndarray, y_prob: np.ndarray, n_bins: int = 10) -> float:
        """
        Compute Expected Calibration Error (ECE).
        ECE = sum_b (|B_b| / N) * |acc(B_b) - conf(B_b)|
        """
        y_true = np.asarray(y_true).ravel()
        y_prob = np.asarray(y_prob).ravel()
        n = len(y_true)
        if n == 0:
            return 0.0

        bin_boundaries = np.linspace(0.0, 1.0, n_bins + 1)
        ece = 0.0

        for i in range(n_bins):
            bin_lower = bin_boundaries[i]
            bin_upper = bin_boundaries[i + 1]

            if i == n_bins - 1:
                in_bin = (y_prob >= bin_lower) & (y_prob <= bin_upper)
            else:
                in_bin = (y_prob >= bin_lower) & (y_prob < bin_upper)

            bin_size = np.sum(in_bin)
            if bin_size > 0:
                bin_acc = np.mean(y_true[in_bin])
                bin_conf = np.mean(y_prob[in_bin])
                ece += (bin_size / n) * abs(bin_acc - bin_conf)

        return float(ece)

    @staticmethod
    def generate_reliability_data(y_true: np.ndarray, y_prob: np.ndarray, n_bins: int = 10) -> Dict[str, Any]:
        """Generate bin coordinates and statistics for reliability diagrams."""
        y_true = np.asarray(y_true).ravel()
        y_prob = np.asarray(y_prob).ravel()
        n = len(y_true)

        bin_boundaries = np.linspace(0.0, 1.0, n_bins + 1)
        confidences = []
        accuracies = []
        bin_counts = []

        for i in range(n_bins):
            bin_lower = bin_boundaries[i]
            bin_upper = bin_boundaries[i + 1]

            if i == n_bins - 1:
                in_bin = (y_prob >= bin_lower) & (y_prob <= bin_upper)
            else:
                in_bin = (y_prob >= bin_lower) & (y_prob < bin_upper)

            bin_size = int(np.sum(in_bin))
            bin_counts.append(bin_size)
            if bin_size > 0:
                confidences.append(float(np.mean(y_prob[in_bin])))
                accuracies.append(float(np.mean(y_true[in_bin])))
            else:
                confidences.append(float((bin_lower + bin_upper) / 2.0))
                accuracies.append(0.0)

        ece = RiskCalibrator.compute_ece(y_true, y_prob, n_bins)
        brier = float(np.mean((y_prob - y_true) ** 2))

        return {
            "bin_edges": bin_boundaries.tolist(),
            "confidences": confidences,
            "accuracies": accuracies,
            "bin_counts": bin_counts,
            "ece": ece,
            "brier_score": brier
        }
