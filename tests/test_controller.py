"""
Tests for Closed-Loop Difficulty Controllers.
Spec Reference: §6 ("The controller", RQ2) & §7.4 Ablations.
"""

import pytest
import numpy as np
from src.worker.controller import DifficultyMapper, NaiveController, DampedController


def test_difficulty_mapper_derivation():
    """Verify that economic mapper strictly increases difficulty with risk probability p."""
    mapper = DifficultyMapper(attacker_benefit_B=10.0, benign_loss_lambda=500.0)

    d_low = mapper.derive_optimal_difficulty(0.01)   # Benign client
    d_mid = mapper.derive_optimal_difficulty(0.50)   # Ambiguous client
    d_high = mapper.derive_optimal_difficulty(0.99)  # Malicious client

    assert d_low <= d_mid <= d_high
    assert d_low == 2  # Lowest difficulty for legitimate users
    assert d_high >= 14  # High difficulty for attacks


def test_naive_controller_oscillation():
    """
    Verify that an undamped proportional controller with delayed feedback Δt
    oscillates between high and low difficulty.
    """
    mapper = DifficultyMapper()
    controller = NaiveController(mapper)

    history_d = []
    # Delay buffer: Δt = 3 steps
    # Attacker dynamics: if d is low (<=4), rate is 50. If d is high (>10), rate is 1.
    measured_rate = 50.0
    delay_buffer = [50.0, 50.0, 50.0]

    for step in range(30):
        # Delayed measurement
        rate_t = delay_buffer.pop(0)
        # Risk estimation from observed rate (threshold at 15 req/s)
        p_t = float(np.clip((rate_t - 5.0) / 30.0, 0.0, 1.0))
        d_t = controller.update("client-1", p_t, current_time=float(step))
        history_d.append(d_t)

        # Physical response: higher difficulty throttles attack rate immediately
        if d_t >= 10:
            actual_rate = 1.0  # severely throttled
        elif d_t <= 4:
            actual_rate = 50.0  # full speed attack
        else:
            actual_rate = 15.0

        delay_buffer.append(actual_rate)

    # Check for oscillations: alternating sign in first differences
    diffs = np.diff(history_d)
    nonzero_diffs = diffs[diffs != 0]
    sign_changes = np.sum(nonzero_diffs[:-1] * nonzero_diffs[1:] < 0)
    print(f"Naive Controller Difficulty History: {history_d}")
    print(f"Number of directional reversals: {sign_changes}")

    # Oscillating signal must exhibit multiple limit-cycle sign reversals
    assert sign_changes >= 4


def test_damped_controller_stability():
    """Verify that the damped controller suppresses oscillations and converges to stable equilibrium."""
    mapper = DifficultyMapper()
    controller = DampedController(
        mapper=mapper,
        ewma_alpha=0.2,
        hysteresis_up=0.1,
        hysteresis_down=0.15,
        dwell_time_seconds=2.0,
        slew_limit=1
    )

    history_d = []
    # Same delay setup (delay = 3 steps)
    delay_buffer = [50.0, 50.0, 50.0]

    for step in range(40):
        t = step * 0.5
        rate_t = delay_buffer.pop(0)
        p_t = float(np.clip((rate_t - 5.0) / 30.0, 0.0, 1.0))
        d_t = controller.update("client-1", p_t, current_time=t)
        history_d.append(d_t)

        if d_t >= 10:
            actual_rate = 1.0
        elif d_t <= 4:
            actual_rate = 50.0
        else:
            actual_rate = 15.0

        delay_buffer.append(actual_rate)

    # In the second half of the run (t >= 20 steps), difficulty should stabilize
    second_half_diffs = np.diff(history_d[20:])
    num_reversals_second_half = int(np.sum(second_half_diffs[second_half_diffs != 0][:-1] * second_half_diffs[second_half_diffs != 0][1:] < 0)) if len(second_half_diffs[second_half_diffs != 0]) > 1 else 0

    print(f"Damped Controller Difficulty History: {history_d}")
    print(f"Second half reversals: {num_reversals_second_half}")
    # Damped controller should settle with near zero reversals in steady state
    assert num_reversals_second_half <= 1


def test_slew_rate_limiting():
    """Verify slew rate limits difficulty step changes to <= 1 per update."""
    mapper = DifficultyMapper()
    controller = DampedController(mapper, slew_limit=1, dwell_time_seconds=0.0)

    # Extreme jump from p=0.0 to p=1.0
    d0 = controller.update("client-slew", 0.0, current_time=0.0)
    d1 = controller.update("client-slew", 1.0, current_time=1.0)

    # Step change must be bounded by slew_limit (1)
    assert abs(d1 - d0) <= 1
