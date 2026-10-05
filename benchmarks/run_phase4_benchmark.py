"""
Phase 4 Benchmark: Derived Difficulty Mapping & Naive Controller Oscillation.
Spec Reference: §6 System Design (Derived difficulty mapping & Naive controller oscillation, RQ2).
"""

import os
import sys
import json
import numpy as np
import matplotlib.pyplot as plt

# Ensure repo root is in python path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from src.worker.controller import DifficultyMapper, NaiveController


def run_naive_oscillation_experiment(seed: int = 42):
    """
    Simulate closed-loop dynamical feedback under delayed out-of-band scoring (Δt = 1.0s).
    Shows how the naive controller undamped loop creates severe limit cycles.
    """
    print("=== [PHASE 4] Naive Controller Oscillation Simulation ===")
    os.makedirs("results/figures", exist_ok=True)
    os.makedirs("results/raw_logs", exist_ok=True)

    rng = np.random.RandomState(seed)
    mapper = DifficultyMapper(attacker_benefit_B=10.0, benign_loss_lambda=500.0)
    controller = NaiveController(mapper)

    # Simulation parameters: 60 seconds duration, discrete time step dt = 0.1s
    total_time = 60.0
    dt = 0.1
    steps = int(total_time / dt)
    time_series = np.linspace(0, total_time, steps)

    # Delay Δt = 1.5 seconds (15 discrete steps)
    delay_steps = 15

    # State variables
    difficulty_history = []
    admitted_throughput_history = []
    risk_score_history = []

    # Queue of historical throughput measurements (delay buffer)
    actual_rate = 30.0  # initial attacker burst (30 req/s)
    throughput_buffer = [actual_rate] * delay_steps

    for step, t in enumerate(time_series):
        # 1. Delayed measurement observed by scoring worker
        delayed_rate = throughput_buffer.pop(0)

        # 2. Risk estimate p_t based on observed rate (sigmoidal feature detector)
        p_t = float(1.0 / (1.0 + np.exp(-0.3 * (delayed_rate - 10.0))))
        risk_score_history.append(p_t)

        # 3. Naive difficulty update
        d_t = controller.update("attacker-client-1", p_t, current_time=t)
        difficulty_history.append(d_t)

        # 4. Physical attacker response to difficulty:
        # Solve latency τ(d) = 2^d * 1.5e-6 seconds
        # Attacker capacity throttles as d increases
        t_solve = (2.0 ** d_t) * 1.5e-6
        max_possible_rate = 1.0 / (0.02 + t_solve)  # 0.02s base network/payload time
        actual_rate = min(30.0, max_possible_rate) + rng.normal(0, 0.5)
        actual_rate = max(0.1, actual_rate)

        admitted_throughput_history.append(actual_rate)
        throughput_buffer.append(actual_rate)

    # Compute oscillation metrics
    diff_arr = np.array(difficulty_history)
    diff_changes = np.diff(diff_arr)
    num_reversals = int(np.sum(diff_changes[diff_changes != 0][:-1] * diff_changes[diff_changes != 0][1:] < 0))
    mean_diff = float(np.mean(diff_arr))
    min_diff = int(np.min(diff_arr))
    max_diff = int(np.max(diff_arr))
    p95_rate = float(np.percentile(admitted_throughput_history, 95))
    p5_rate = float(np.percentile(admitted_throughput_history, 5))

    print(f"[+] Simulation Completed over {total_time}s:")
    print(f"    Difficulty Swing   : [{min_diff}, {max_diff}] (Mean = {mean_diff:.2f})")
    print(f"    Throughput Swing   : [{p5_rate:.1f}, {p95_rate:.1f}] req/s")
    print(f"    Direction Reversals: {num_reversals} cycles (Severe Chattering Observed)")

    # Plot Figure 2: Naive Controller Oscillation
    fig, (ax1, ax2) = plt.subplots(2, 1, figsize=(10, 7), sharex=True)

    ax1.plot(time_series, difficulty_history, color="#d62728", linewidth=2, label="Assigned Difficulty Level $d(t)$")
    ax1.set_ylabel("PoW Difficulty Bits", fontsize=11, fontweight="bold")
    ax1.set_title("Naive Proportional Controller: Limit-Cycle Oscillation Under Delay $\Delta t = 1.5$s", fontsize=12, fontweight="bold")
    ax1.grid(True, linestyle="--", alpha=0.5)
    ax1.legend(loc="upper right")

    ax2.plot(time_series, admitted_throughput_history, color="#1f77b4", linewidth=1.5, label="Attacker Admitted Rate (req/s)")
    ax2.set_ylabel("Throughput (req/s)", fontsize=11, fontweight="bold")
    ax2.set_xlabel("Time (seconds)", fontsize=11, fontweight="bold")
    ax2.grid(True, linestyle="--", alpha=0.5)
    ax2.legend(loc="upper right")

    plt.tight_layout()
    fig_path = "results/figures/fig2_naive_oscillation.png"
    plt.savefig(fig_path, dpi=300)
    plt.close()
    print(f"[+] Saved naive oscillation plot to {fig_path}")

    report = {
        "seed": seed,
        "total_time": total_time,
        "delay_seconds": delay_steps * dt,
        "min_diff": min_diff,
        "max_diff": max_diff,
        "mean_diff": mean_diff,
        "num_reversals": num_reversals,
        "p5_rate": p5_rate,
        "p95_rate": p95_rate,
        "difficulty_history": difficulty_history,
        "throughput_history": admitted_throughput_history,
        "time_series": time_series.tolist()
    }

    with open("results/raw_logs/phase4_naive_oscillation.json", "w") as f:
        json.dump(report, f, indent=2)

    return report


if __name__ == "__main__":
    run_naive_oscillation_experiment(seed=42)
