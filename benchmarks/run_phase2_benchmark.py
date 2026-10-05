"""
Phase 2 Benchmark: Benign vs Attacker Traffic Analysis.
Spec Reference: §7.1 Data (Inter-arrival distribution comparison & Attacker load).
"""

import os
import sys
import json
import time
import asyncio
import numpy as np
import scipy.stats as stats
import matplotlib.pyplot as plt

# Ensure repo root is in python path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from src.traffic.benign_generator import BenignTrafficGenerator
from src.traffic.attack_generators.asyncio_attacker import AsyncIOAttacker
from src.evaluation.metrics import MetricsCalculator


def compare_interarrival_distributions(n_samples: int = 10000, seed: int = 42):
    """
    Generate and statistically compare Poisson vs Fitted Heavy-Tailed arrival processes.
    """
    print("=== [PHASE 2] Inter-Arrival Distribution Comparison ===")
    os.makedirs("results/figures", exist_ok=True)
    os.makedirs("results/raw_logs", exist_ok=True)

    poisson_gen = BenignTrafficGenerator(base_url="http://mock", distribution_type="poisson", seed=seed)
    fitted_gen = BenignTrafficGenerator(base_url="http://mock", distribution_type="fitted", seed=seed)

    poisson_samples = poisson_gen.generate_arrival_trace(n_samples)
    fitted_samples = fitted_gen.generate_arrival_trace(n_samples)

    # Compute descriptive statistics
    def calc_dist_metrics(samples):
        return {
            "mean": float(np.mean(samples)),
            "std": float(np.std(samples)),
            "cv": float(np.std(samples) / np.mean(samples)),  # Coefficient of variation
            "median": float(np.median(samples)),
            "p95": float(np.percentile(samples, 95)),
            "p99": float(np.percentile(samples, 99)),
            "skewness": float(stats.skew(samples)),
            "kurtosis": float(stats.kurtosis(samples))
        }

    poisson_stats = calc_dist_metrics(poisson_samples)
    fitted_stats = calc_dist_metrics(fitted_samples)

    print(f"Poisson Model (Exponential):")
    print(f"  Mean = {poisson_stats['mean']:.4f}s | Std = {poisson_stats['std']:.4f}s | CV = {poisson_stats['cv']:.3f} (Expected ~1.0)")
    print(f"  p95 = {poisson_stats['p95']:.4f}s | p99 = {poisson_stats['p99']:.4f}s | Skew = {poisson_stats['skewness']:.2f}")

    print(f"\nFitted Heavy-Tailed Model (Weibull shape=0.65):")
    print(f"  Mean = {fitted_stats['mean']:.4f}s | Std = {fitted_stats['std']:.4f}s | CV = {fitted_stats['cv']:.3f} (Bursty > 1.5)")
    print(f"  p95 = {fitted_stats['p95']:.4f}s | p99 = {fitted_stats['p99']:.4f}s | Skew = {fitted_stats['skewness']:.2f}")

    # Generate Figure: PDF / CDF comparison
    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(12, 5))

    # Plot 1: Log-Histogram / Density
    bins = np.linspace(0, 1.5, 60)
    ax1.hist(poisson_samples, bins=bins, density=True, alpha=0.6, label=f"Poisson (CV={poisson_stats['cv']:.2f})", color="#1f77b4")
    ax1.hist(fitted_samples, bins=bins, density=True, alpha=0.6, label=f"Fitted Heavy-Tailed (CV={fitted_stats['cv']:.2f})", color="#d62728")
    ax1.set_title("Inter-Arrival Time Density", fontsize=12, fontweight="bold")
    ax1.set_xlabel("Inter-Arrival Time (seconds)", fontsize=11)
    ax1.set_ylabel("Probability Density", fontsize=11)
    ax1.legend(loc="upper right", frameon=True)
    ax1.grid(True, linestyle="--", alpha=0.5)

    # Plot 2: Empirical CDF (log-scale x)
    sorted_poisson = np.sort(poisson_samples)
    sorted_fitted = np.sort(fitted_samples)
    y_vals = np.linspace(0, 1, len(poisson_samples))

    ax2.plot(sorted_poisson, y_vals, label="Poisson (Exponential)", color="#1f77b4", linewidth=2)
    ax2.plot(sorted_fitted, y_vals, label="Fitted Heavy-Tailed (Weibull)", color="#d62728", linewidth=2)
    ax2.set_xscale("log")
    ax2.set_title("Empirical CDF (Log Scale)", fontsize=12, fontweight="bold")
    ax2.set_xlabel("Inter-Arrival Time (seconds, log scale)", fontsize=11)
    ax2.set_ylabel("Cumulative Probability", fontsize=11)
    ax2.legend(loc="lower right", frameon=True)
    ax2.grid(True, linestyle="--", alpha=0.5)

    plt.tight_layout()
    plot_path = "results/figures/interarrival_distribution.png"
    plt.savefig(plot_path, dpi=300)
    plt.close()
    print(f"[+] Saved distribution comparison figure to {plot_path}")

    # Save raw log
    report = {
        "n_samples": n_samples,
        "seed": seed,
        "poisson_stats": poisson_stats,
        "fitted_stats": fitted_stats
    }
    with open("results/raw_logs/phase2_traffic_distributions.json", "w") as f:
        json.dump(report, f, indent=2)

    return report


async def run_attacker_test_campaign():
    """Run simulated AsyncIO attack campaign (credential stuffing)."""
    print("\n=== [PHASE 2] Executing Attacker Campaign ===")
    from httpx import AsyncClient, ASGITransport
    from src.middleware.server import app
    from src.client.client import PoWClient

    transport = ASGITransport(app=app)
    base_url = "http://testserver"

    client = PoWClient(base_url=base_url, client_key="attacker-bot-bench", device_class="laptop")
    client.http_client = AsyncClient(transport=transport, base_url=base_url)

    attacker = AsyncIOAttacker(base_url=base_url, attack_type="credential_stuffing", rotate_identity=False)
    results = await attacker.run_campaign(n_requests=50, custom_client=client)

    print(f"[+] Attacker Campaign Completed:")
    print(f"    Requests Attempted : {results['requests_attempted']}")
    print(f"    Admitted Requests  : {results['admitted_requests']}")
    print(f"    Challenges Solved  : {results['challenges_solved']}")
    print(f"    Total Solve CPU (s): {results['total_solve_cpu_seconds']:.4f}")
    print(f"    Throughput (req/s) : {results['throughput_req_per_sec']:.2f}")

    await client.close()
    return results


async def main():
    compare_interarrival_distributions(n_samples=10000, seed=42)
    await run_attacker_test_campaign()


if __name__ == "__main__":
    asyncio.run(main())
