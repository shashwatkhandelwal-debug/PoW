"""
Phase 4 Sensitivity Sweep: Parameter Response of Difficulty Mapping d*(p).
Spec Reference: §6 System Design (Economic Loss Formulation & RQ2 Controller).

Analyzes the structural properties of:
    d*(p) = argmin_{d in [2..16]} [ p * B * rate(d) + (1 - p) * lambda * tau_benign(d) ]
across a 3x3 parameter grid:
    B in [1, 10, 100]
    lambda in [50, 500, 5000]

Outputs:
- JSON raw log: results/raw_logs/phase4_sensitivity.json
- Publication figure: results/figures/fig_difficulty_mapping_sensitivity.png
"""

import os
import sys
import json
import numpy as np
import matplotlib.pyplot as plt

# Ensure repo root is in python path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from src.worker.controller import DifficultyMapper


def run_phase4_sensitivity_sweep():
    print("=== [PHASE 4 SENSITIVITY] Parameter Sweep for Economic Difficulty Mapping d*(p) ===")
    os.makedirs("results/figures", exist_ok=True)
    os.makedirs("results/raw_logs", exist_ok=True)

    b_values = [1.0, 10.0, 100.0]
    lambda_values = [50.0, 500.0, 5000.0]
    p_grid = np.linspace(0.0, 1.0, 201)

    results = {}
    summary_table = []

    for b in b_values:
        for lam in lambda_values:
            key = f"B={int(b)}_lambda={int(lam)}"
            mapper = DifficultyMapper(
                attacker_benefit_B=b,
                benign_loss_lambda=lam,
                min_difficulty=2,
                max_difficulty=16,
                t_hash_attacker=1.0e-6,
                t_hash_benign=4.0e-6
            )

            d_curve = [mapper.derive_optimal_difficulty(p) for p in p_grid]
            unique_d = sorted(list(set(d_curve)))

            # Find switching thresholds where d transitions
            transitions = []
            for i in range(1, len(d_curve)):
                if d_curve[i] != d_curve[i-1]:
                    transitions.append({
                        "p_threshold": float(p_grid[i]),
                        "from_d": int(d_curve[i-1]),
                        "to_d": int(d_curve[i])
                    })

            results[key] = {
                "B": b,
                "lambda": lam,
                "p_grid": p_grid.tolist(),
                "d_curve": d_curve,
                "unique_difficulties": unique_d,
                "num_levels_used": len(unique_d),
                "is_bang_bang": len(unique_d) <= 3,
                "transitions": transitions
            }

            summary_table.append({
                "B": b,
                "lambda": lam,
                "B_over_lambda": b / lam,
                "num_levels": len(unique_d),
                "unique_d": unique_d,
                "bang_bang": len(unique_d) <= 3
            })

    # Save raw logs
    raw_log_path = "results/raw_logs/phase4_sensitivity.json"
    with open(raw_log_path, "w") as f:
        json.dump(results, f, indent=2)
    print(f"[+] Persisted sensitivity sweep dataset to {raw_log_path}")

    # Generate Publication Figure
    fig, axes = plt.subplots(1, 3, figsize=(16, 5), sharey=True)
    colors = {50.0: "#1f77b4", 500.0: "#ff7f0e", 5000.0: "#2ca02c"}
    linestyles = {50.0: "-", 500.0: "--", 5000.0: "-."}

    for idx, b in enumerate(b_values):
        ax = axes[idx]
        for lam in lambda_values:
            key = f"B={int(b)}_lambda={int(lam)}"
            data = results[key]
            ax.step(
                data["p_grid"],
                data["d_curve"],
                where="post",
                label=f"lambda = {int(lam)} (B/lambda = {b/lam:.4f})",
                color=colors[lam],
                linestyle=linestyles[lam],
                linewidth=2.2
            )

        ax.set_title(f"Attacker Benefit B = {int(b)}", fontsize=12, fontweight="bold")
        ax.set_xlabel("Calibrated Risk Probability p = P(Malice | x)", fontsize=10, fontweight="bold")
        if idx == 0:
            ax.set_ylabel("Optimal PoW Difficulty d*(p)", fontsize=11, fontweight="bold")
        ax.set_ylim(1.5, 16.5)
        ax.set_yticks(np.arange(2, 17, 2))
        ax.grid(True, linestyle=":", alpha=0.6)
        ax.legend(loc="upper left", fontsize=9)

    plt.suptitle(
        "Sensitivity Analysis: Step-Function & Bang-Bang Nature of d*(p) across (B, lambda)",
        fontsize=14,
        fontweight="bold",
        y=1.02
    )
    plt.tight_layout()
    fig_path = "results/figures/fig_difficulty_mapping_sensitivity.png"
    plt.savefig(fig_path, dpi=300, bbox_inches="tight")
    plt.close()
    print(f"[+] Generated sensitivity plot: {fig_path}")

    print("\n--- SENSITIVITY SWEEP SUMMARY MATRIX ---")
    print(f"{'B':<6} | {'Lambda':<8} | {'B/Lambda':<10} | {'Levels Used':<12} | {'Behavior':<14} | {'Difficulties Visited'}")
    print("-" * 80)
    for row in summary_table:
        behav = "Bang-Bang (2-3)" if row["bang_bang"] else "Multi-Step"
        print(f"{row['B']:<6.0f} | {row['lambda']:<8.0f} | {row['B_over_lambda']:<10.4f} | {row['num_levels']:<12} | {behav:<14} | {row['unique_d']}")

    return results


if __name__ == "__main__":
    run_phase4_sensitivity_sweep()
