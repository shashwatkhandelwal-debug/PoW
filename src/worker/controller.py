"""
Difficulty Controller & Economic Mapping.
Spec Reference: §6 System Design ("Why the difficulty mapping should be derived", "The controller (RQ2)").

Mathematical Derivation:
Given calibrated probability of malice p:
d*(p) = argmin_d [ p · B · rate(d) + (1 - p) · λ · τ_benign(d) ]
where:
- B = Attacker benefit per admitted request
- rate(d) = Attacker solve throughput rate at difficulty d: rate(d) = 1 / (t_base + 2^d * t_hash)
- λ = Trade-off weight converting benign latency into loss
- τ_benign(d) = Expected benign solve latency at difficulty d: τ(d) = 2^d * t_hash_benign

Controllers:
1. Naive Proportional Controller (Phase 4):
   Direct mapping d = d*(p_t) without damping/memory. Oscillates violently under delayed feedback Δt.
2. Damped Controller (Phase 5):
   EWMA smoothing, hysteresis thresholds, dwell time, and slew-rate limiting.
"""

from typing import Dict, Any, Optional, List
import numpy as np


class DifficultyMapper:
    """Derives optimal difficulty level d*(p) from economic loss formulation."""

    def __init__(
        self,
        attacker_benefit_B: float = 10.0,
        benign_loss_lambda: float = 500.0,
        min_difficulty: int = 2,
        max_difficulty: int = 18,
        t_hash_attacker: float = 1.0e-6,  # 1 microsecond per hash on fast attacker
        t_hash_benign: float = 4.0e-6     # 4 microseconds per hash on client
    ):
        self.B = attacker_benefit_B
        self.lambda_param = benign_loss_lambda
        self.min_d = min_difficulty
        self.max_d = max_difficulty
        self.t_hash_attacker = t_hash_attacker
        self.t_hash_benign = t_hash_benign

        # Pre-compute loss table across candidate difficulty levels d in [min_d, max_d]
        self.d_candidates = np.arange(self.min_d, self.max_d + 1)
        # Solve time: t_solve(d) = (2^d) * t_hash
        # Attacker throughput: 1 / (0.01 + (2^d) * t_hash_attacker)
        self.attacker_rates = np.array([
            1.0 / (0.01 + (2.0 ** d) * self.t_hash_attacker) for d in self.d_candidates
        ])
        # Benign latency loss: (2^d) * t_hash_benign
        self.benign_latencies = np.array([
            (2.0 ** d) * self.t_hash_benign for d in self.d_candidates
        ])

    def derive_optimal_difficulty(self, prob_malice: float) -> int:
        """
        Compute d*(p) = argmin_d [ p · B · rate(d) + (1 - p) · λ · τ_benign(d) ].
        """
        p = float(np.clip(prob_malice, 0.0, 1.0))
        # Total cost vector for candidate difficulties
        cost = p * self.B * self.attacker_rates + (1.0 - p) * self.lambda_param * self.benign_latencies
        optimal_idx = int(np.argmin(cost))
        return int(self.d_candidates[optimal_idx])


class NaiveController:
    """
    Undamped proportional controller.
    Directly applies instantaneous difficulty d = d*(p_t) with zero memory or damping.
    Exhibits limit-cycle oscillations when feedback is delayed by scoring lag Δt.
    """

    def __init__(self, mapper: Optional[DifficultyMapper] = None):
        self.mapper = mapper or DifficultyMapper()

    def update(self, client_key: str, prob_malice: float, current_time: float) -> int:
        """Directly map instantaneous risk score to optimal difficulty."""
        return self.mapper.derive_optimal_difficulty(prob_malice)


class DampedController:
    """
    Stabilized closed-loop controller with EWMA smoothing, hysteresis, dwell time, and slew limits.
    (Stub initialized here, executed in Phase 5).
    """

    def __init__(
        self,
        mapper: Optional[DifficultyMapper] = None,
        ewma_alpha: float = 0.25,
        hysteresis_up: float = 0.15,
        hysteresis_down: float = 0.20,
        dwell_time_seconds: float = 3.0,
        slew_limit: int = 1
    ):
        self.mapper = mapper or DifficultyMapper()
        self.ewma_alpha = ewma_alpha
        self.hysteresis_up = hysteresis_up
        self.hysteresis_down = hysteresis_down
        self.dwell_time = dwell_time_seconds
        self.slew_limit = slew_limit
        self.client_states: Dict[str, Dict[str, Any]] = {}

    def update(self, client_key: str, prob_malice: float, current_time: float) -> int:
        """To be executed and benchmarked in Phase 5."""
        if client_key not in self.client_states:
            init_d = self.mapper.derive_optimal_difficulty(prob_malice)
            self.client_states[client_key] = {
                "smoothed_p": prob_malice,
                "current_d": init_d,
                "last_change_time": current_time
            }
            return init_d

        state = self.client_states[client_key]
        # EWMA smoothing
        smoothed_p = self.ewma_alpha * prob_malice + (1.0 - self.ewma_alpha) * state["smoothed_p"]
        state["smoothed_p"] = smoothed_p

        target_d = self.mapper.derive_optimal_difficulty(smoothed_p)
        current_d = state["current_d"]

        # Check dwell time
        time_at_level = current_time - state["last_change_time"]
        if time_at_level < self.dwell_time:
            return current_d

        # Hysteresis check
        if target_d > current_d:
            if (prob_malice - smoothed_p) < -self.hysteresis_up:
                target_d = current_d
        elif target_d < current_d:
            if (smoothed_p - prob_malice) < -self.hysteresis_down:
                target_d = current_d

        # Slew-rate limit: max step change per interval
        if target_d > current_d:
            new_d = min(current_d + self.slew_limit, target_d)
        elif target_d < current_d:
            new_d = max(current_d - self.slew_limit, target_d)
        else:
            new_d = current_d

        if new_d != current_d:
            state["current_d"] = new_d
            state["last_change_time"] = current_time

        return state["current_d"]
