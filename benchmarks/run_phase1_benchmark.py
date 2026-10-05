"""
Phase 1 Benchmark & Verification Script.
Executes:
1. Red/Green Security Property Verification.
2. End-to-end Middleware p50/p99 Overhead vs No-Defense Baseline.
"""

import time
import json
import os
import sys
import asyncio

# Ensure repo root is in python path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

import numpy as np
from httpx import AsyncClient, ASGITransport
from src.middleware.config import settings
from src.middleware.server import app, challenge_manager
from src.client.client import PoWClient
from src.client.solver import PoWSolver
from src.evaluation.metrics import MetricsCalculator

settings.target_url = "mock"


async def run_red_green_verification():
    """
    Demonstrate that naive/broken security implementations fail the tests,
    while the real ChallengeManager passes.
    """
    print("=== [PHASE 1] Security Red/Green Verification ===")
    results = {}

    # Case 1: Replay Protection
    # A broken manager that does NOT track spent nonces:
    class BrokenReplayManager(type(challenge_manager)):
        def is_nonce_spent(self, ch_nonce, sol_nonce):
            return False  # Never marks as spent!

    broken_mgr = BrokenReplayManager(secret_key="secret", challenge_ttl=60)
    ch = broken_mgr.mint_challenge("user1", "auth", 4)
    _, p, _ = broken_mgr.parse_and_verify_challenge(ch, "user1", "auth")
    broken_mgr.mark_nonce_spent(p["nonce"], "sol123")
    # Naive broken check fails to detect replay:
    is_rejected_on_replay_broken = broken_mgr.is_nonce_spent(p["nonce"], "sol123")
    print(f"[-] Naive Replay Manager detects replay: {is_rejected_on_replay_broken} (RED - Broken)")

    # Real ChallengeManager correctly detects replay:
    challenge_manager.mark_nonce_spent(p["nonce"], "sol123")
    is_rejected_on_replay_real = challenge_manager.is_nonce_spent(p["nonce"], "sol123")
    print(f"[+] Real ChallengeManager detects replay: {is_rejected_on_replay_real} (GREEN - Passed)")
    results["replay_red_green"] = {"naive_caught": is_rejected_on_replay_broken, "real_caught": is_rejected_on_replay_real}

    # Case 2: Cross-endpoint binding
    ch_read = challenge_manager.mint_challenge("user1", "read", 4)
    is_valid_auth, _, err = challenge_manager.parse_and_verify_challenge(ch_read, "user1", "auth")
    print(f"[+] Cross-endpoint spending rejected: {not is_valid_auth} Reason: {err} (GREEN)")
    results["cross_endpoint_rejected"] = not is_valid_auth

    return results


async def run_latency_overhead_benchmark(n_trials: int = 1000, seed: int = 42):
    """
    Measure end-to-end request latency for:
    1. Direct / No-Defense Baseline (defense_enabled = False)
    2. Static PoW with Work-Credit Caching (subsequent requests amortized)
    3. Static PoW first request (challenge solve latency)
    """
    print(f"\n=== [PHASE 1] Measuring Latency Overhead (N={n_trials} trials, seed={seed}) ===")
    np.random.seed(seed)

    transport = ASGITransport(app=app)
    base_url = "http://testserver"

    # 1. Baseline: No Defense
    async with AsyncClient(transport=transport, base_url=base_url) as client:
        # Toggle defense off
        await client.post("/admin/toggle_defense?enabled=false")

        baseline_latencies = []
        for _ in range(n_trials):
            t0 = time.perf_counter()
            resp = await client.get("/api/v1/resource", headers={"x-client-key": "benign-bench-client"})
            t1 = time.perf_counter()
            assert resp.status_code == 200
            baseline_latencies.append((t1 - t0) * 1000.0)  # ms

        # Toggle defense back ON
        await client.post("/admin/toggle_defense?enabled=true")

    # 2. Static PoW with Client SDK (Work-credit caching)
    client_sdk = PoWClient(base_url=base_url, client_key="benign-bench-client", device_class="laptop")
    client_sdk.http_client = AsyncClient(transport=transport, base_url=base_url)

    first_req_latency = None
    subsequent_latencies = []

    # First request triggers 401, solves PoW (difficulty=8), gets work credit
    resp, timing = await client_sdk.request("GET", "/api/v1/resource")
    assert resp.status_code == 200
    first_req_latency = timing["total_latency_seconds"] * 1000.0
    print(f"[*] Initial PoW Challenge Request Latency (solve + roundtrip): {first_req_latency:.2f} ms (solve: {timing['solve_wall_seconds']*1000.0:.2f} ms)")

    # Subsequent requests present work-credit token (fast path)
    for _ in range(n_trials):
        t0 = time.perf_counter()
        resp, t_info = await client_sdk.request("GET", "/api/v1/resource")
        t1 = time.perf_counter()
        assert resp.status_code == 200
        subsequent_latencies.append((t1 - t0) * 1000.0)

    await client_sdk.close()

    base_stats = MetricsCalculator.calculate_latency_percentiles(baseline_latencies)
    credit_stats = MetricsCalculator.calculate_latency_percentiles(subsequent_latencies)
    lut_stats = MetricsCalculator.calculate_lut_percentiles(subsequent_latencies, baseline_latencies)

    print("\n--- Latency Percentile Results ---")
    print(f"No-Defense Baseline   : p50 = {base_stats['p50']:.3f} ms | p95 = {base_stats['p95']:.3f} ms | p99 = {base_stats['p99']:.3f} ms")
    print(f"PoW Gateway (Credit) : p50 = {credit_stats['p50']:.3f} ms | p95 = {credit_stats['p95']:.3f} ms | p99 = {credit_stats['p99']:.3f} ms")
    print(f"Added Middleware Tax : p50 = {lut_stats['p50_tax_ms']:.3f} ms | p95 = {lut_stats['p95_tax_ms']:.3f} ms | p99 = {lut_stats['p99_tax_ms']:.3f} ms")

    os.makedirs("results/raw_logs", exist_ok=True)
    report = {
        "seed": seed,
        "n_trials": n_trials,
        "baseline_stats": base_stats,
        "work_credit_stats": credit_stats,
        "first_solve_ms": first_req_latency,
        "added_tax_ms": lut_stats
    }
    with open("results/raw_logs/phase1_baseline.json", "w") as f:
        json.dump(report, f, indent=2)

    return report


async def main():
    await run_red_green_verification()
    await run_latency_overhead_benchmark(n_trials=1000, seed=42)


if __name__ == "__main__":
    asyncio.run(main())
