"""
Phase 6 Benchmark: Adaptive Mimicry Adversary & Evasion-Cost Curve.
Spec Reference: §7.3 The adaptive adversary (C4: Mimicry attacker, evasion cost curve).
"""

import os
import sys
import json
import numpy as np
import matplotlib.pyplot as plt

# Ensure repo root is in python path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from src.worker.detector import AnomalyDetector
from src.worker.calibrator import RiskCalibrator
from src.worker.controller import DifficultyMapper
from src.traffic.adaptive_adversary.mimicry_attacker import MimicryAttacker
from benchmarks.run_phase3_benchmark import generate_synthetic_feature_dataset


def run_phase6_evaluation(seed: int = 42):
    print("=== [PHASE 6] Adaptive Mimicry Attacker & Evasion-Cost Evaluation ===")
    os.makedirs("results/figures", exist_ok=True)
    os.makedirs("results/raw_logs", exist_ok=True)

    # 1. Fit detector and calibrator
    X_train_benign, _ = generate_synthetic_feature_dataset(n_benign=500, n_attack=0, seed=seed)
    X_val_benign, X_val_attack = generate_synthetic_feature_dataset(n_benign=300, n_attack=300, seed=seed + 1)
    X_val = np.vstack([X_val_benign, X_val_attack])
    y_val = np.hstack([np.zeros(len(X_val_benign)), np.ones(len(X_val_attack))])

    detector = AnomalyDetector(n_estimators=100, random_state=seed)
    detector.fit(X_train_benign)

    raw_scores_val = detector.score_raw(X_val)
    calibrator = RiskCalibrator(method="isotonic")
    calibrator.fit(raw_scores_val, y_val)

    mapper = DifficultyMapper()
    peak_unconstrained_rate = 30.0  # 30 req/s unconstrained brute force capacity

    attacker = MimicryAttacker(
        detector=detector,
        calibrator=calibrator,
        mapper=mapper,
        peak_rate=peak_unconstrained_rate,
        seed=seed
    )

    # 2. Sweep target difficulty levels
    d_targets = [2, 4, 6, 8, 10, 12, 14, 16]
    results = []

    print("\n--- EVASION-COST SEARCH RESULTS ---")
    print(f"{'Target Diff':<12} | {'Optimal Rate (req/s)':<22} | {'Endpoint Mix':<15} | {'Malicious Thp':<16} | {'Evasion Cost (%)':<16}")
    print("-" * 90)

    for d_t in d_targets:
        res = attacker.optimize_for_difficulty_threshold(d_target=d_t)
        results.append(res)
        opt_th = res["optimal_theta"]
        print(f"{d_t:<12} | {opt_th['rate']:<22.2f} | {opt_th['endpoint_mix']:<15.2f} | {res['achieved_malicious_throughput']:<16.2f} | {res['evasion_cost_percent']:<16.1f}%")

    # 3. Generate Publication Figure (Evasion-Cost Curve)
    diffs = [r["d_target"] for r in results]
    throughputs = [r["achieved_malicious_throughput"] for r in results]
    evasion_costs = [r["evasion_cost_percent"] for r in results]

    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(12, 5))

    # Panel A: Achieved Malicious Throughput vs Difficulty Ceiling
    ax1.plot(diffs, throughputs, "o-", color="#1f77b4", lw=2.5, markersize=8)
    ax1.axhline(y=peak_unconstrained_rate, color="red", linestyle="--", label=f"Unconstrained Attack ({peak_unconstrained_rate:.0f} req/s)")
    ax1.set_title("A. Attacker Malicious Throughput vs Target Difficulty", fontweight="bold", fontsize=11)
    ax1.set_xlabel(r"Target Difficulty Level Ceiling $d_{\mathrm{target}}$", fontweight="bold")
    ax1.set_ylabel("Admitted Exploit Throughput (req/s)", fontweight="bold")
    ax1.grid(True, linestyle="--", alpha=0.5)
    ax1.legend(loc="lower right")

    # Panel B: Evasion Cost Curve (% Throughput Sacrificed)
    ax2.plot(diffs, evasion_costs, "s-", color="#d62728", lw=2.5, markersize=8)
    ax2.set_title("B. Evasion-Cost Curve (% Throughput Sacrificed)", fontweight="bold", fontsize=11)
    ax2.set_xlabel(r"Target Difficulty Level Ceiling $d_{\mathrm{target}}$", fontweight="bold")
    ax2.set_ylabel("Evasion Cost (% Throughput Lost)", fontweight="bold")
    ax2.set_ylim(0, 100)
    ax2.grid(True, linestyle="--", alpha=0.5)

    # Annotate key finding
    cost_at_d2 = evasion_costs[0]
    ax2.annotate(
        f"Staying at d=2 costs {cost_at_d2:.1f}% throughput",
        xy=(diffs[0], cost_at_d2),
        xytext=(diffs[0] + 1.5, cost_at_d2 - 12),
        arrowprops=dict(facecolor="black", shrink=0.08, width=1, headwidth=6),
        fontweight="bold"
    )

    plt.tight_layout()
    fig_path = "results/figures/fig_evasion_cost.png"
    plt.savefig(fig_path, dpi=300)
    plt.close()
    print(f"[+] Saved evasion cost curve to {fig_path}")

    report = {
        "seed": seed,
        "peak_unconstrained_rate": peak_unconstrained_rate,
        "evasion_curve": results
    }
    with open("results/raw_logs/phase6_mimicry_evasion.json", "w") as f:
        json.dump(report, f, indent=2)

    return report


if __name__ == "__main__":
    run_phase6_evaluation(seed=42)
