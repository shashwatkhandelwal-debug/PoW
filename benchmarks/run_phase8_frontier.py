"""
Phase 8 Benchmark: Full Pareto Frontier & Publication Artifacts Generation.
Spec Reference: §5 Metrics, §8 Results You Should Expect to Be Negative, §9 Reproducibility Package.
"""

import os
import sys
import json
import numpy as np

# Ensure repo root is in python path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from src.evaluation.ablations import AblationRunner
from src.evaluation.plot_generator import FigureGenerator


def run_phase8_frontier_benchmark(seed: int = 42):
    print("=== [PHASE 8] Executing Full Frontier Sweep & Generating Publication Figures ===")
    os.makedirs("results/figures", exist_ok=True)
    os.makedirs("results/raw_logs", exist_ok=True)

    ablation_runner = AblationRunner(seed=seed)
    frontier_data = ablation_runner.run_full_frontier_sweep(n_runs=10)

    # Save raw logs
    raw_log_path = "results/raw_logs/phase8_frontier_data.json"
    with open(raw_log_path, "w") as f:
        json.dump(frontier_data, f, indent=2)
    print(f"[+] Persisted full raw frontier dataset to {raw_log_path}")

    # Generate Frontier Plot
    fig_gen = FigureGenerator(raw_logs_dir="results/raw_logs", figures_dir="results/figures")
    fig_path = fig_gen.generate_frontier_plot(frontier_data, output_file="fig1_pareto_frontier.png")
    print(f"[+] Successfully generated Figure 1: {fig_path}")

    print("\n--- SUMMARY OF ALL ARMS ON THE FRONTIER ---")
    print(f"{'Defense Configuration Arm':<44} | {'ACA (Thr)':<10} | {'ACA (CPU)':<10} | {'LUT (p95 Low Phone)':<22}")
    print("-" * 95)
    for name, data in frontier_data.items():
        aca_thr = data.get("aca_throughput", data["aca"])
        aca_cpu = data.get("aca_cpu", data["aca"])
        print(f"{name:<44} | {aca_thr:<10.2f} | {aca_cpu:<10.2f} | {data['lut_low_p95_ms']:<22.4f} ms")

    return frontier_data


if __name__ == "__main__":
    run_phase8_frontier_benchmark(seed=42)
