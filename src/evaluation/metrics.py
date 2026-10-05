"""
Evaluation Metrics Computation (Spec §5).

Metrics:
1. Attacker Cost Amplification (ACA):
   ACA = (attacker CPU-seconds per admitted malicious request under defense D)
       ÷ (attacker CPU-seconds per admitted malicious request with no defense)
   Measured via `time.process_time()` / `resource.getrusage`.

2. Legitimate User Tax (LUT):
   LUT(c) = Added end-to-end latency for benign clients of device class c.
   Reported as full empirical distribution (p50, p95, p99, max) and CDF, stratified over:
   - Laptop
   - Mid-range phone
   - Low-end phone

3. Middleware Overhead:
   Latency added in request path (p50, p99, p99.9) comparing gateway with defense vs direct upstream.

4. Calibration Error:
   Expected Calibration Error (ECE) and Brier Score.

5. Surrogate Extraction Fidelity:
   Spearman rank correlation and agreement rate between true model and extracted surrogate.
"""

from typing import List, Dict, Any, Tuple
import numpy as np


class MetricsCalculator:
    """Calculates defensible systems and security metrics per spec §5."""

    @staticmethod
    def calculate_aca(
        attacker_cpu_sec_defense: float,
        admitted_requests_defense: int,
        attacker_cpu_sec_no_defense: float,
        admitted_requests_no_defense: int
    ) -> float:
        """
        Calculate Attacker Cost Amplification ratio (Throughput / End-to-End Latency basis).
        ACA = (Cost_defense / admitted_defense) / (Cost_no_defense / admitted_no_defense)
        """
        if admitted_requests_defense <= 0:
            # If 0 requests admitted, defense achieved maximum amplification (inf)
            return float("inf")
        if admitted_requests_no_defense <= 0:
            return 1.0

        cost_per_admitted_def = attacker_cpu_sec_defense / admitted_requests_defense
        cost_per_admitted_no_def = max(attacker_cpu_sec_no_defense / admitted_requests_no_defense, 1e-9)

        return float(cost_per_admitted_def / cost_per_admitted_no_def)

    @staticmethod
    def calculate_aca_cpu(
        cpu_solve_ms: float,
        cpu_net_baseline_ms: float = 0.045
    ) -> float:
        """
        Calculate Attacker Cost Amplification based strictly on Attacker Client Process CPU Time.
        Measured via time.process_time() / getrusage on client process:
        ACA_cpu = (cpu_net_baseline + cpu_solve) / cpu_net_baseline = 1.0 + (cpu_solve / cpu_net_baseline)
        """
        return float(1.0 + (cpu_solve_ms / max(cpu_net_baseline_ms, 1e-9)))

    @staticmethod
    def calculate_aca_throughput(
        solve_latency_ms: float,
        rtt_baseline_ms: float = 0.4912
    ) -> float:
        """
        Calculate Attacker Cost Amplification based on End-to-End Throughput / RTT.
        ACA_throughput = (rtt_baseline + solve_latency) / rtt_baseline = 1.0 + (solve_latency / rtt_baseline)
        """
        return float(1.0 + (solve_latency_ms / max(rtt_baseline_ms, 1e-9)))

    @staticmethod
    def calculate_latency_percentiles(latencies_ms: List[float]) -> Dict[str, float]:
        """Calculate p50, p90, p95, p99, p99.9, mean, std."""
        if not latencies_ms:
            return {"p50": 0.0, "p90": 0.0, "p95": 0.0, "p99": 0.0, "p99.9": 0.0, "mean": 0.0, "std": 0.0}
        arr = np.array(latencies_ms)
        return {
            "p50": float(np.percentile(arr, 50)),
            "p90": float(np.percentile(arr, 90)),
            "p95": float(np.percentile(arr, 95)),
            "p99": float(np.percentile(arr, 99)),
            "p99.9": float(np.percentile(arr, 99.9)),
            "mean": float(np.mean(arr)),
            "std": float(np.std(arr)),
            "min": float(np.min(arr)),
            "max": float(np.max(arr)),
            "count": int(len(arr))
        }

    @staticmethod
    def calculate_lut_percentiles(
        latencies_with_defense_ms: List[float],
        baseline_latencies_ms: List[float]
    ) -> Dict[str, float]:
        """
        Calculate Legitimate User Tax (LUT): added latency percentiles.
        """
        def_p = MetricsCalculator.calculate_latency_percentiles(latencies_with_defense_ms)
        base_p = MetricsCalculator.calculate_latency_percentiles(baseline_latencies_ms)

        return {
            "p50_tax_ms": max(0.0, def_p["p50"] - base_p["p50"]),
            "p95_tax_ms": max(0.0, def_p["p95"] - base_p["p95"]),
            "p99_tax_ms": max(0.0, def_p["p99"] - base_p["p99"]),
            "def_p50": def_p["p50"],
            "def_p95": def_p["p95"],
            "def_p99": def_p["p99"],
            "base_p50": base_p["p50"],
            "base_p95": base_p["p95"],
            "base_p99": base_p["p99"]
        }

    @staticmethod
    def bootstrap_ci(data: List[float], statistic_fn=np.median, n_resamples: int = 1000, ci: float = 0.95, random_seed: int = 42) -> Tuple[float, float, float]:
        """Compute bootstrap confidence interval."""
        if not data:
            return 0.0, 0.0, 0.0
        rng = np.random.RandomState(random_seed)
        arr = np.array(data)
        point_estimate = float(statistic_fn(arr))
        boot_stats = []
        n = len(arr)
        for _ in range(n_resamples):
            sample = rng.choice(arr, size=n, replace=True)
            boot_stats.append(statistic_fn(sample))
        lower_pct = (1.0 - ci) / 2.0 * 100.0
        upper_pct = (1.0 + ci) / 2.0 * 100.0
        low = float(np.percentile(boot_stats, lower_pct))
        high = float(np.percentile(boot_stats, upper_pct))
        return point_estimate, low, high
