"""
Adaptive Mimicry Attacker.
Spec Reference: §7.3 The adaptive adversary (C4: Mimicry attacker).
"""

from typing import Dict, Any, List, Tuple
import numpy as np
from src.worker.detector import AnomalyDetector
from src.worker.calibrator import RiskCalibrator
from src.worker.controller import DifficultyMapper


class MimicryAttacker:
    """Optimizes traffic parameters to evade risk escalation while maximizing throughput."""

    def __init__(
        self,
        detector: AnomalyDetector,
        calibrator: RiskCalibrator,
        mapper: DifficultyMapper,
        peak_rate: float = 30.0,
        seed: int = 42
    ):
        self.detector = detector
        self.calibrator = calibrator
        self.mapper = mapper
        self.peak_rate = peak_rate
        self.rng = np.random.RandomState(seed)

    def optimize_for_difficulty_threshold(
        self,
        d_target: int = 4
    ) -> Dict[str, Any]:
        """
        Search for knob setting θ* maximizing malicious throughput subject to difficulty <= d_target.
        Vectorized batch evaluation across search space for high performance.
        """
        # Dense multi-dimensional search grid
        rates = np.linspace(1.0, self.peak_rate, 35)
        jitters = np.linspace(0.1, 1.8, 10)
        mixes = np.linspace(0.0, 0.8, 10)
        cover_error_rates = np.linspace(0.02, 0.40, 8)
        hdr_entropies = [3.2, 3.6, 3.8]

        # Construct 5D grid: [rate, jitter, mix, cover_err, hdr]
        grid = np.array(np.meshgrid(rates, jitters, mixes, cover_error_rates, hdr_entropies)).T.reshape(-1, 5)
        rate_col = grid[:, 0]
        jitter_col = grid[:, 1]
        mix_col = grid[:, 2]
        err_col = grid[:, 3]
        hdr_col = grid[:, 4]

        # Feature vector matrix
        ia_mean = 1.0 / np.maximum(rate_col, 0.1)
        ia_var = (jitter_col * ia_mean) ** 2
        burstiness = ia_var / np.maximum(ia_mean ** 2, 1e-6)
        endpoint_entropy = 0.3 + mix_col * 1.8
        # Overall error rate is blended between exploit errors and cover traffic errors
        blended_error_rate = (1.0 - mix_col) * 0.70 + mix_col * err_col

        X_batch = np.column_stack([
            rate_col, ia_mean, ia_var, burstiness, endpoint_entropy, blended_error_rate, hdr_col
        ])

        # Batch scoring & calibration
        raw_scores = self.detector.score_raw(X_batch)
        probs = self.calibrator.predict_proba(raw_scores)

        # Batch optimal difficulty derivation
        diffs = np.array([self.mapper.derive_optimal_difficulty(p) for p in probs])

        # Solver cost: fast attacker CPU (0.8 us/hash = 0.0008 ms/hash = 8e-7 s/hash)
        t_solves = (2.0 ** diffs) * 8.0e-7
        raw_throughputs = 1.0 / ((1.0 / np.maximum(rate_col, 0.1)) + t_solves)
        # Malicious fraction of traffic = (1 - mix)
        malicious_throughputs = raw_throughputs * (1.0 - mix_col)

        # Mask points meeting difficulty constraint <= d_target
        valid_mask = (diffs <= d_target)

        if np.any(valid_mask):
            valid_indices = np.where(valid_mask)[0]
            best_idx = valid_indices[np.argmax(malicious_throughputs[valid_indices])]
        else:
            best_idx = int(np.argmin(diffs))

        best_theta = grid[best_idx]
        best_throughput = float(malicious_throughputs[best_idx])
        best_diff = int(diffs[best_idx])
        best_prob = float(probs[best_idx])

        evasion_cost_pct = float(max(0.0, (1.0 - (best_throughput / self.peak_rate)) * 100.0))

        return {
            "d_target": d_target,
            "optimal_theta": {
                "rate": float(best_theta[0]),
                "jitter": float(best_theta[1]),
                "endpoint_mix": float(best_theta[2]),
                "cover_error_rate": float(best_theta[3]),
                "header_entropy": float(best_theta[4])
            },
            "achieved_malicious_throughput": float(best_throughput),
            "assigned_difficulty": int(best_diff),
            "calibrated_prob": float(best_prob),
            "evasion_cost_percent": float(evasion_cost_pct)
        }


