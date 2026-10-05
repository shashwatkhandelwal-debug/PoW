"""
Phase 5 Benchmark: Damped Controller & Scoring Lag (Δt) Stability Boundary Sweep.
Spec Reference: §6 System Design (Damped Controller, RQ2) & §7.4 Ablations.
"""

import os
import sys
import json
import numpy as np
import matplotlib.pyplot as plt

# Ensure repo root is in python path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from src.worker.controller import DifficultyMapper, NaiveController, DampedController


def simulate_closed_loop(controller, total_time=60.0, dt=0.1, delay_seconds=1.5, seed=42):
    """Simulate closed-loop dynamical feedback for a given controller."""
    rng = np.random.RandomState(seed)
    steps = int(total_time / dt)
    time_series = np.linspace(0, total_time, steps)
    delay_steps = max(1, int(delay_seconds / dt))

    difficulty_history = []
    throughput_history = []
    actual_rate = 30.0
    throughput_buffer = [actual_rate] * delay_steps

    for t in time_series:
        delayed_rate = throughput_buffer.pop(0)
        p_t = float(1.0 / (1.0 + np.exp(-0.3 * (delayed_rate - 10.0))))

        d_t = controller.update("attacker-1", p_t, current_time=t)
        difficulty_history.append(d_t)

        t_solve = (2.0 ** d_t) * 1.5e-6
        max_possible_rate = 1.0 / (0.02 + t_solve)
        actual_rate = min(30.0, max_possible_rate) + rng.normal(0, 0.3)
        actual_rate = max(0.1, actual_rate)

        throughput_history.append(actual_rate)
        throughput_buffer.append(actual_rate)

    diff_arr = np.array(difficulty_history)
    diff_changes = np.diff(diff_arr)
    nonzero_changes = diff_changes[diff_changes != 0]
    num_reversals = int(np.sum(nonzero_changes[:-1] * nonzero_changes[1:] < 0)) if len(nonzero_changes) > 1 else 0
    steady_state_var = float(np.var(diff_arr[int(len(diff_arr) * 0.5):]))

    return {
        "time_series": time_series,
        "difficulty": difficulty_history,
        "throughput": throughput_history,
        "reversals": num_reversals,
        "steady_state_variance": steady_state_var,
        "mean_diff": float(np.mean(diff_arr))
    }


def run_phase5_evaluation(seed: int = 42):
    print("=== [PHASE 5] Damped Controller & Stability Boundary Sweep ===")
    os.makedirs("results/figures", exist_ok=True)
    os.makedirs("results/raw_logs", exist_ok=True)

    mapper = DifficultyMapper()

    # 1. Before/After Comparison at Δt = 1.5s
    naive_ctrl = NaiveController(mapper)
    damped_ctrl = DampedController(
        mapper=mapper,
        ewma_alpha=0.15,
        hysteresis_up=0.10,
        hysteresis_down=0.15,
        dwell_time_seconds=3.0,
        slew_limit=1
    )

    naive_res = simulate_closed_loop(naive_ctrl, total_time=60.0, dt=0.1, delay_seconds=1.5, seed=seed)
    damped_res = simulate_closed_loop(damped_ctrl, total_time=60.0, dt=0.1, delay_seconds=1.5, seed=seed)

    print(f"Naive Controller Reversals  : {naive_res['reversals']} (Steady-state Var = {naive_res['steady_state_variance']:.2f})")
    print(f"Damped Controller Reversals : {damped_res['reversals']} (Steady-state Var = {damped_res['steady_state_variance']:.2f})")
    print(f"[+] Reversals reduced by {(1.0 - damped_res['reversals']/max(naive_res['reversals'], 1))*100.0:.1f}%")

    # 2. Scoring Lag Δt Sweep: {0.1, 0.5, 1.0, 2.0, 5.0, 10.0} s
    lag_candidates = [0.1, 0.5, 1.0, 1.5, 2.0, 3.0, 5.0, 8.0, 10.0]
    naive_lag_reversals = []
    damped_lag_reversals = []
    naive_lag_vars = []
    damped_lag_vars = []

    for lag in lag_candidates:
        n_ctrl = NaiveController(mapper)
        d_ctrl = DampedController(mapper, ewma_alpha=0.15, dwell_time_seconds=3.0, slew_limit=1)

        n_r = simulate_closed_loop(n_ctrl, total_time=60.0, dt=0.1, delay_seconds=lag, seed=seed)
        d_r = simulate_closed_loop(d_ctrl, total_time=60.0, dt=0.1, delay_seconds=lag, seed=seed)

        naive_lag_reversals.append(n_r["reversals"])
        damped_lag_reversals.append(d_r["reversals"])
        naive_lag_vars.append(n_r["steady_state_variance"])
        damped_lag_vars.append(d_r["steady_state_variance"])

    print("\n--- LAG (Delta t) STABILITY SWEEP ---")
    print(f"{'Lag Delta t (s)':<15} | {'Naive Reversals':<16} | {'Damped Reversals':<18} | {'Damped Steady Var':<18}")
    print("-" * 75)
    for i, lag in enumerate(lag_candidates):
        print(f"{lag:<15.1f} | {naive_lag_reversals[i]:<16} | {damped_lag_reversals[i]:<18} | {damped_lag_vars[i]:<18.3f}")

    # 3. Generate Publication Figure (Figure 2: Before/After & Stability Sweep)
    fig = plt.figure(figsize=(14, 8))
    gs = fig.add_gridspec(2, 2)

    # Panel A: Naive Controller Trajectory
    ax1 = fig.add_subplot(gs[0, 0])
    ax1.plot(naive_res["time_series"], naive_res["difficulty"], color="#d62728", lw=2, label="Naive $d(t)$")
    ax1.set_title(rf"A. Naive Controller ($\Delta t=1.5$s, Reversals={naive_res['reversals']})", fontweight="bold")
    ax1.set_ylabel("Difficulty Bits", fontweight="bold")
    ax1.set_ylim(10, 19)
    ax1.grid(True, linestyle="--", alpha=0.5)
    ax1.legend(loc="upper right")

    # Panel B: Damped Controller Trajectory
    ax2 = fig.add_subplot(gs[0, 1])
    ax2.plot(damped_res["time_series"], damped_res["difficulty"], color="#2ca02c", lw=2, label="Damped $d(t)$")
    ax2.set_title(rf"B. Damped Controller ($\Delta t=1.5$s, Reversals={damped_res['reversals']})", fontweight="bold")
    ax2.set_ylabel("Difficulty Bits", fontweight="bold")
    ax2.set_ylim(10, 19)
    ax2.grid(True, linestyle="--", alpha=0.5)
    ax2.legend(loc="upper right")

    # Panel C: Throughput Comparison
    ax3 = fig.add_subplot(gs[1, 0])
    ax3.plot(naive_res["time_series"], naive_res["throughput"], color="#d62728", alpha=0.7, lw=1.2, label="Naive Attacker Rate")
    ax3.plot(damped_res["time_series"], damped_res["throughput"], color="#2ca02c", lw=2.0, label="Damped Attacker Rate")
    ax3.set_title("C. Attacker Admitted Throughput Response", fontweight="bold")
    ax3.set_xlabel("Time (seconds)", fontweight="bold")
    ax3.set_ylabel("Throughput (req/s)", fontweight="bold")
    ax3.grid(True, linestyle="--", alpha=0.5)
    ax3.legend(loc="upper right")

    # Panel D: Stability Boundary Sweep vs Lag Δt
    ax4 = fig.add_subplot(gs[1, 1])
    ax4.plot(lag_candidates, naive_lag_reversals, "s--", color="#d62728", lw=2, label="Naive Controller")
    ax4.plot(lag_candidates, damped_lag_reversals, "o-", color="#2ca02c", lw=2, label="Damped Controller")
    ax4.axvline(x=5.0, color="gray", linestyle=":", label=r"Damping Stability Boundary ($\Delta t \approx 5$s)")
    ax4.set_title(r"D. Stability Boundary Sweep (Reversals vs Scoring Lag $\Delta t$)", fontweight="bold")
    ax4.set_xlabel(r"Scoring Lag $\Delta t$ (seconds)", fontweight="bold")
    ax4.set_ylabel("Directional Reversals", fontweight="bold")
    ax4.grid(True, linestyle="--", alpha=0.5)
    ax4.legend(loc="upper left")

    plt.tight_layout()
    fig_path = "results/figures/fig2_controller_comparison.png"
    plt.savefig(fig_path, dpi=300)
    plt.close()
    print(f"[+] Saved controller comparison and stability sweep figure to {fig_path}")

    report = {
        "seed": seed,
        "naive_1_5s": {"reversals": naive_res["reversals"], "steady_var": naive_res["steady_state_variance"]},
        "damped_1_5s": {"reversals": damped_res["reversals"], "steady_var": damped_res["steady_state_variance"]},
        "lag_sweep": {
            "lags": lag_candidates,
            "naive_reversals": naive_lag_reversals,
            "damped_reversals": damped_lag_reversals,
            "naive_vars": naive_lag_vars,
            "damped_vars": damped_lag_vars
        }
    }
    with open("results/raw_logs/phase5_damped_controller.json", "w") as f:
        json.dump(report, f, indent=2)

    return report


if __name__ == "__main__":
    run_phase5_evaluation(seed=42)
