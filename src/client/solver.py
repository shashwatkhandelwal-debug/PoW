"""
Client-side Proof of Work Solver & Hardware Device Profiling.
Spec Reference: §5 Metrics (LUT stratification) & §6 ("Why Argon2id and not just SHA-256", RQ4).

Supports:
1. Fast SHA-256 and Argon2id hash puzzle solving.
2. Device-class throttling profiles:
   - "laptop": 1.0x (full native rate)
   - "mid_phone": 0.35x compute factor
   - "low_phone": 0.08x compute factor
3. Exact CPU-seconds profiling (via process time / resource metrics).
"""

import hashlib
import time
import os
from typing import Tuple, Optional
import argon2
from src.middleware.pow_verifier import PoWVerifier


class PoWSolver:
    """Solves PoW challenges with device-class execution profiles."""

    def __init__(self, device_class: str = "laptop"):
        self.device_class = device_class
        # Hardware throughput calibration factor relative to native workstation
        self.throttle_factors = {
            "laptop": 1.0,
            "mid_phone": 0.35,
            "low_phone": 0.08
        }
        self.speed_factor = self.throttle_factors.get(device_class, 1.0)

    def solve_sha256(self, challenge_str: str, difficulty_bits: int, max_iterations: int = 100_000_000) -> Tuple[Optional[str], float, float, int]:
        """
        Solve SHA-256 challenge.
        Find nonce s.t. SHA256(challenge_str + nonce) has >= difficulty_bits leading zeros.
        Returns: (solution_nonce, wall_clock_seconds, cpu_seconds, hashes_evaluated)
        """
        if difficulty_bits <= 0:
            return "0", 0.0, 0.0, 0

        t0_wall = time.perf_counter()
        t0_cpu = time.process_time()

        prefix_bytes = challenge_str.encode("utf-8")
        target_bits = difficulty_bits

        nonce_num = 0
        found_nonce = None

        # Pre-compute byte mask matching for speed
        while nonce_num < max_iterations:
            nonce_str = str(nonce_num)
            digest = hashlib.sha256(prefix_bytes + nonce_str.encode("ascii")).digest()

            # Fast check
            zeros = PoWVerifier._count_leading_zero_bits(digest)
            if zeros >= target_bits:
                found_nonce = nonce_str
                break
            nonce_num += 1

        t1_wall = time.perf_counter()
        t1_cpu = time.process_time()

        raw_wall = t1_wall - t0_wall
        raw_cpu = t1_cpu - t0_cpu
        hashes = nonce_num + 1

        # Apply device-class hardware scaling to wall-clock time
        effective_wall = raw_wall / self.speed_factor
        effective_cpu = raw_cpu / self.speed_factor

        return found_nonce, effective_wall, effective_cpu, hashes

    def solve_argon2id(
        self,
        challenge_str: str,
        difficulty_bits: int,
        time_cost: int = 1,
        memory_cost_kib: int = 16384,
        parallelism: int = 1,
        max_iterations: int = 100_000
    ) -> Tuple[Optional[str], float, float, int]:
        """
        Solve Argon2id challenge.
        Returns: (solution_nonce, wall_clock_seconds, cpu_seconds, hashes_evaluated)
        """
        if difficulty_bits <= 0:
            return "0", 0.0, 0.0, 0

        t0_wall = time.perf_counter()
        t0_cpu = time.process_time()

        salt = hashlib.sha256(challenge_str.encode("utf-8")).digest()[:16]
        found_nonce = None
        nonce_num = 0

        while nonce_num < max_iterations:
            nonce_str = str(nonce_num)
            raw_hash = argon2.low_level.hash_secret_raw(
                secret=nonce_str.encode("utf-8"),
                salt=salt,
                time_cost=time_cost,
                memory_cost=memory_cost_kib,
                parallelism=parallelism,
                hash_len=32,
                type=argon2.low_level.Type.ID
            )
            zeros = PoWVerifier._count_leading_zero_bits(raw_hash)
            if zeros >= difficulty_bits:
                found_nonce = nonce_str
                break
            nonce_num += 1

        t1_wall = time.perf_counter()
        t1_cpu = time.process_time()

        raw_wall = t1_wall - t0_wall
        raw_cpu = t1_cpu - t0_cpu
        hashes = nonce_num + 1

        effective_wall = raw_wall / self.speed_factor
        effective_cpu = raw_cpu / self.speed_factor

        return found_nonce, effective_wall, effective_cpu, hashes
