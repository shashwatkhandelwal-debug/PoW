"""
Tests for Anomaly Detector and Probability Calibration.
Spec Reference: §6 ("Why the risk score needs calibration") & §7.4 Ablations.
"""

import pytest
import numpy as np
from src.worker.detector import AnomalyDetector
from src.worker.calibrator import RiskCalibrator


def test_anomaly_detector_training():
    """Verify IsolationForest trains and scores cleanly."""
    rng = np.random.RandomState(42)
    # Generate benign baseline feature vectors (low rate, low burstiness)
    X_train = rng.normal(loc=1.0, scale=0.2, size=(200, 7))

    detector = AnomalyDetector(n_estimators=50, random_state=42)
    detector.fit(X_train)
    assert detector.is_fitted is True

    # Test scoring
    X_test_normal = rng.normal(loc=1.0, scale=0.2, size=(10, 7))
    X_test_anomaly = rng.normal(loc=15.0, scale=3.0, size=(10, 7))  # High anomaly

    scores_normal = detector.score_raw(X_test_normal)
    scores_anomaly = detector.score_raw(X_test_anomaly)

    # Anomaly scores should be higher for anomalous vectors
    assert np.mean(scores_anomaly) > np.mean(scores_normal)


def test_calibrator_transforms_to_probabilities():
    """Verify calibrator outputs valid probabilities strictly in [0, 1]."""
    rng = np.random.RandomState(42)
    raw_scores = rng.normal(loc=0.0, scale=0.5, size=200)
    y_labels = (raw_scores > 0.1).astype(int)

    calibrator = RiskCalibrator(method="isotonic")
    calibrator.fit(raw_scores, y_labels)
    assert calibrator.is_fitted is True

    test_scores = np.array([-1.5, -0.5, 0.0, 0.5, 1.5])
    probs = calibrator.predict_proba(test_scores)

    assert len(probs) == len(test_scores)
    assert np.all(probs >= 0.0)
    assert np.all(probs <= 1.0)
    # Monotonicity check
    assert probs[-1] >= probs[0]


def test_calibrator_improves_ece():
    """Verify calibration lowers ECE relative to naive uncalibrated squashing."""
    rng = np.random.RandomState(42)
    raw_scores = rng.normal(loc=0.0, scale=1.0, size=500)
    # True relationship: sigmoid with noise
    true_prob = 1.0 / (1.0 + np.exp(-3.0 * raw_scores))
    y_true = rng.binomial(1, true_prob)

    # Split train/val
    raw_train, raw_val = raw_scores[:300], raw_scores[300:]
    y_train, y_val = y_true[:300], y_true[300:]

    # Naive min-max squashing (uncalibrated)
    naive_val_prob = (raw_val - raw_val.min()) / (raw_val.max() - raw_val.min() + 1e-6)
    ece_naive = RiskCalibrator.compute_ece(y_val, naive_val_prob, n_bins=10)

    # Calibrated
    calibrator = RiskCalibrator(method="sigmoid")
    calibrator.fit(raw_train, y_train)
    calib_val_prob = calibrator.predict_proba(raw_val)
    ece_calib = RiskCalibrator.compute_ece(y_val, calib_val_prob, n_bins=10)

    print(f"Naive ECE: {ece_naive:.4f}, Calibrated ECE: {ece_calib:.4f}")
    assert ece_calib <= ece_naive
