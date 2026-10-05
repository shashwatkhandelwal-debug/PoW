"""
Model Extraction Attacker & Defense Mitigations Evaluation.
Spec Reference: §7.3 The adaptive adversary & RQ3 The Adaptation Oracle.

Features:
1. Extraction Attacker:
   - Probes the gateway across feature space.
   - Observes returned difficulty d.
   - Trains surrogate model (RandomForest/MLP) to reconstruct decision boundary.
   - Measures surrogate fidelity (Spearman rank correlation and R^2 score).
2. Defense Mitigations:
   - Baseline: Unmitigated fine-grained difficulty (8+ tiers).
   - Mitigation 1: Coarse Quantization (3 coarse difficulty tiers: 2, 8, 16).
   - Mitigation 2: Randomized Jitter (difficulty ± 1-2 bits noise).
   - Mitigation 3: Adaptation Delay (difficulty updates batched every K requests).
"""

from typing import Dict, Any, List, Tuple
import numpy as np
import scipy.stats as stats
from sklearn.ensemble import RandomForestRegressor
from src.worker.detector import AnomalyDetector
from src.worker.calibrator import RiskCalibrator
from src.worker.controller import DifficultyMapper


class ExtractionAttacker:
    """Probes the adaptive PoW gateway to extract a surrogate model of the classifier."""

    def __init__(
        self,
        detector: AnomalyDetector,
        calibrator: RiskCalibrator,
        mapper: DifficultyMapper,
        seed: int = 42
    ):
        self.detector = detector
        self.calibrator = calibrator
        self.mapper = mapper
        self.rng = np.random.RandomState(seed)

    def query_oracle(
        self,
        X_probe: np.ndarray,
        mitigation: str = "none"  # "none", "quantization", "jitter", "delay"
    ) -> np.ndarray:
        """
        Query gateway with probe features and observe returned difficulty under mitigation policy.
        """
        raw_scores = self.detector.score_raw(X_probe)
        probs = self.calibrator.predict_proba(raw_scores)
        raw_diffs = np.array([self.mapper.derive_optimal_difficulty(p) for p in probs], dtype=float)

        if mitigation == "none":
            return raw_diffs

        elif mitigation == "quantization":
            # Coarse 3-tier quantization: low (2), mid (8), high (16)
            quantized = np.zeros_like(raw_diffs)
            quantized[raw_diffs < 6] = 2
            quantized[(raw_diffs >= 6) & (raw_diffs < 12)] = 8
            quantized[raw_diffs >= 12] = 16
            return quantized

        elif mitigation == "jitter":
            # Randomized jitter: add integer noise in [-2, +2]
            noise = self.rng.choice([-2, -1, 0, 1, 2], size=len(raw_diffs), p=[0.15, 0.2, 0.3, 0.2, 0.15])
            jittered = np.clip(raw_diffs + noise, 2, 18)
            return jittered

        elif mitigation == "delay":
            # Delayed adaptation: hold stale difficulty in batches of 10
            delayed = np.zeros_like(raw_diffs)
            batch_size = 10
            for i in range(0, len(raw_diffs), batch_size):
                chunk = raw_diffs[i:i + batch_size]
                stale_val = chunk[0]
                delayed[i:i + len(chunk)] = stale_val
            return delayed

        return raw_diffs

    def evaluate_extraction_curve(
        self,
        X_pool: np.ndarray,
        X_test: np.ndarray,
        query_budgets: List[int],
        mitigation: str = "none",
        n_trials: int = 20
    ) -> List[Dict[str, Any]]:
        """
        Train surrogate model on subset of queries and measure fidelity against true model.
        Runs multiple randomized trials (n_trials >= 20) per budget to compute mean and 95% CI.
        """
        true_raw_test = self.detector.score_raw(X_test)
        true_prob_test = self.calibrator.predict_proba(true_raw_test)

        curve_results = []

        for q in query_budgets:
            trial_spearmans = []
            trial_agreements = []

            for trial in range(n_trials):
                # Subsample probe points with trial seed
                trial_rng = np.random.RandomState(self.rng.randint(0, 100000) + trial)
                q_actual = min(q, len(X_pool))
                indices = trial_rng.choice(len(X_pool), size=q_actual, replace=False)
                X_train_probe = X_pool[indices]

                # Query oracle to get labels
                y_diff_observed = self.query_oracle(X_train_probe, mitigation=mitigation)

                # Fit surrogate regressor (Random Forest)
                surrogate = RandomForestRegressor(n_estimators=50, random_state=42 + trial)
                surrogate.fit(X_train_probe, y_diff_observed)

                # Predict on test holdout
                y_pred_surrogate = surrogate.predict(X_test)

                # Measure fidelity: Spearman rank correlation with true posterior probabilities
                spearman_corr, _ = stats.spearmanr(true_prob_test, y_pred_surrogate)
                if np.isnan(spearman_corr):
                    spearman_corr = 0.0
                trial_spearmans.append(spearman_corr)

                # Agreement on top-20% high risk classification
                top_true = true_prob_test >= np.percentile(true_prob_test, 80)
                top_surr = y_pred_surrogate >= np.percentile(y_pred_surrogate, 80)
                top_k_agreement = float(np.mean(top_true == top_surr))
                trial_agreements.append(top_k_agreement)

            mean_rho = float(np.mean(trial_spearmans))
            std_rho = float(np.std(trial_spearmans))
            ci_low = float(np.percentile(trial_spearmans, 2.5))
            ci_high = float(np.percentile(trial_spearmans, 97.5))

            curve_results.append({
                "budget": q,
                "mitigation": mitigation,
                "spearman_fidelity": mean_rho,
                "spearman_std": std_rho,
                "spearman_ci": [ci_low, ci_high],
                "top_k_agreement": float(np.mean(trial_agreements))
            })

        return curve_results

