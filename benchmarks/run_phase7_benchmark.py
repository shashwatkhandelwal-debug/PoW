"""
Phase 7 Benchmark: Model Extraction Oracle & Mitigation Evaluation.
Spec Reference: §7.3 The adaptive adversary & RQ3 The Adaptation Oracle.
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
from src.traffic.adaptive_adversary.extraction_attacker import ExtractionAttacker
from benchmarks.run_phase3_benchmark import generate_synthetic_feature_dataset


def run_phase7_evaluation(seed: int = 42):
    print("=== [PHASE 7] Model Extraction Oracle & Defense Mitigations Evaluation ===")
    os.makedirs("results/figures", exist_ok=True)
    os.makedirs("results/raw_logs", exist_ok=True)

    # 1. Fit ground truth detector & calibrator
    X_train_benign, _ = generate_synthetic_feature_dataset(n_benign=600, n_attack=0, seed=seed)
    X_val_benign, X_val_attack = generate_synthetic_feature_dataset(n_benign=300, n_attack=300, seed=seed + 1)
    X_val = np.vstack([X_val_benign, X_val_attack])
    y_val = np.hstack([np.zeros(len(X_val_benign)), np.ones(len(X_val_attack))])

    detector = AnomalyDetector(n_estimators=100, random_state=seed)
    detector.fit(X_train_benign)

    raw_scores_val = detector.score_raw(X_val)
    calibrator = RiskCalibrator(method="isotonic")
    calibrator.fit(raw_scores_val, y_val)

    mapper = DifficultyMapper()

    # Generate probe candidate pool (N=1000) and holdout test set (N=500)
    X_pool_b, X_pool_a = generate_synthetic_feature_dataset(n_benign=500, n_attack=500, seed=seed + 10)
    X_pool = np.vstack([X_pool_b, X_pool_a])

    X_test_b, X_test_a = generate_synthetic_feature_dataset(n_benign=250, n_attack=250, seed=seed + 20)
    X_test = np.vstack([X_test_b, X_test_a])

    attacker = ExtractionAttacker(detector, calibrator, mapper, seed=seed)

    query_budgets = [10, 20, 40, 80, 150, 300, 600, 1000]
    mitigations = ["none", "quantization", "jitter", "delay"]
    mitigation_labels = {
        "none": "Unmitigated (Continuous)",
        "quantization": "Coarse Quantization (3 Tiers)",
        "jitter": "Randomized Jitter (+/-2 bits)",
        "delay": "Adaptation Delay (K=10)"
    }

    all_results = {}

    print("\n--- MODEL EXTRACTION FIDELITY vs QUERY BUDGET ---")
    print(f"{'Queries':<10} | {'Unmitigated rho':<16} | {'Quantization rho':<18} | {'Jitter rho':<14} | {'Delay rho':<14}")
    print("-" * 80)

    for mit in mitigations:
        res = attacker.evaluate_extraction_curve(X_pool, X_test, query_budgets, mitigation=mit)
        all_results[mit] = res

    for i, q in enumerate(query_budgets):
        rho_none = all_results["none"][i]["spearman_fidelity"]
        rho_quant = all_results["quantization"][i]["spearman_fidelity"]
        rho_jit = all_results["jitter"][i]["spearman_fidelity"]
        rho_del = all_results["delay"][i]["spearman_fidelity"]
        print(f"{q:<10} | {rho_none:<16.3f} | {rho_quant:<18.3f} | {rho_jit:<14.3f} | {rho_del:<14.3f}")

    # 2. Defense Precision Penalty Measurement
    # Measure mean absolute error (MAE) in assigned difficulty introduced by each mitigation
    true_diff = attacker.query_oracle(X_test, mitigation="none")
    precision_penalties = {}
    for mit in mitigations:
        mit_diff = attacker.query_oracle(X_test, mitigation=mit)
        mae = float(np.mean(np.abs(mit_diff - true_diff)))
        precision_penalties[mit] = mae

    print("\n--- DEFENSE PRECISION PENALTY (MAE on Difficulty Assignment) ---")
    for mit, mae in precision_penalties.items():
        print(f"  {mitigation_labels[mit]:<32}: MAE = {mae:.2f} difficulty bits")

    # 3. Generate Publication Figure (Figure 4: Extraction Curves & Precision Trade-off)
    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(13, 5))

    colors = {"none": "#d62728", "quantization": "#1f77b4", "jitter": "#2ca02c", "delay": "#9467bd"}
    markers = {"none": "o-", "quantization": "s-", "jitter": "^-", "delay": "d-"}

    # Panel A: Surrogate Fidelity vs Query Budget
    for mit in mitigations:
        rhos = [r["spearman_fidelity"] for r in all_results[mit]]
        ax1.plot(query_budgets, rhos, markers[mit], color=colors[mit], lw=2.2, label=mitigation_labels[mit])

    ax1.set_xscale("log")
    ax1.set_title("A. Surrogate Model Extraction Fidelity (Spearman $\\rho$)", fontweight="bold", fontsize=11)
    ax1.set_xlabel("Adversary Query Budget (Log Scale)", fontweight="bold")
    ax1.set_ylabel("Surrogate Rank Correlation $\\rho$", fontweight="bold")
    ax1.set_ylim(-0.05, 1.05)
    ax1.grid(True, linestyle="--", alpha=0.5)
    ax1.legend(loc="lower right", frameon=True)

    # Panel B: Extraction Resistance vs Defense Precision Trade-off
    # X-axis: Defense Precision Error (MAE difficulty bits), Y-axis: Query Cost to Reach rho >= 0.70
    # Compute queries needed to reach rho >= 0.70
    queries_to_070 = []
    labels_list = []
    mae_list = []

    for mit in mitigations:
        rhos = np.array([r["spearman_fidelity"] for r in all_results[mit]])
        # Find first budget where rho >= 0.70 or max if never reached
        idx = np.where(rhos >= 0.70)[0]
        q_needed = query_budgets[idx[0]] if len(idx) > 0 else 1500
        queries_to_070.append(q_needed)
        labels_list.append(mitigation_labels[mit])
        mae_list.append(precision_penalties[mit])

    for i, mit in enumerate(mitigations):
        ax2.scatter(mae_list[i], queries_to_070[i], color=colors[mit], s=120, zorder=5, label=mitigation_labels[mit])
        ax2.annotate(
            f"{labels_list[i]}\n({queries_to_070[i]} probes, MAE={mae_list[i]:.2f})",
            xy=(mae_list[i], queries_to_070[i]),
            xytext=(mae_list[i] + 0.1, queries_to_070[i] * 0.9),
            fontsize=9
        )

    ax2.set_title("B. Precision vs Extraction Resistance Trade-Off", fontweight="bold", fontsize=11)
    ax2.set_xlabel("Defense Precision Penalty (MAE in Difficulty Bits)", fontweight="bold")
    ax2.set_ylabel(r"Probes Required to Extract Model ($\rho \geq 0.70$)", fontweight="bold")
    ax2.set_yscale("log")
    ax2.grid(True, linestyle="--", alpha=0.5)

    plt.tight_layout()
    fig_path = "results/figures/fig4_extraction_mitigations.png"
    plt.savefig(fig_path, dpi=300)
    plt.close()
    print(f"[+] Saved model extraction and mitigations figure to {fig_path}")

    report = {
        "seed": seed,
        "query_budgets": query_budgets,
        "mitigation_results": all_results,
        "precision_penalties_mae": precision_penalties
    }
    with open("results/raw_logs/phase7_extraction_mitigations.json", "w") as f:
        json.dump(report, f, indent=2)

    return report


if __name__ == "__main__":
    run_phase7_evaluation(seed=42)
