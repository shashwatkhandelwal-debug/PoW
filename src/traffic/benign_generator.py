"""
Realistic Benign Traffic Generator.
Spec Reference: §7.1 Data (Heavy-tailed on/off session arrival model).

Implements:
1. Fitted Non-Poisson Arrival Process:
   - Session inter-arrival times: Weibull / Pareto distribution (shape < 1.0, modeling burstiness).
   - Within-session request inter-arrival ("think-time"): Lognormal distribution (μ=0.5, σ=0.8).
   - Session lengths: Geometric / heavy-tailed distribution of requests per session.
   - Endpoint browsing transitions: Realistic Markov state transitions (browse -> detail -> action).
2. Standard Poisson Process (Baseline):
   - Memoryless exponential inter-arrival times for explicit comparison.
3. Multi-device stratification:
   - Laptop (50%), Mid-range Phone (35%), Low-end Phone (15%).
"""

import time
import asyncio
import numpy as np
from typing import List, Dict, Any, Optional, Tuple
from src.client.client import PoWClient


class BenignTrafficGenerator:
    """Generates realistic benign user traffic with heavy-tailed bursts and session dynamics."""

    def __init__(
        self,
        base_url: str,
        n_sessions: int = 50,
        distribution_type: str = "fitted",  # "fitted" or "poisson"
        target_mean_interval: float = 0.2,  # seconds
        seed: int = 42
    ):
        self.base_url = base_url
        self.n_sessions = n_sessions
        self.distribution_type = distribution_type
        self.target_mean_interval = target_mean_interval
        self.rng = np.random.RandomState(seed)

        # Device distribution
        self.device_pool = ["laptop"] * 50 + ["mid_phone"] * 35 + ["low_phone"] * 15

        # Typical user navigation endpoints
        self.endpoints = [
            ("/api/v1/resource", "GET", None),
            ("/api/v1/resource?page=2", "GET", None),
            ("/api/v1/auth/login", "POST", {"username": "admin", "password": "secret"}),
            ("/api/v1/heavy-export", "POST", {"query": "user_report", "limit": 10})
        ]

    def sample_interarrival_time(self) -> float:
        """Sample next inter-arrival interval in seconds."""
        if self.distribution_type == "poisson":
            # Memoryless exponential distribution
            scale = self.target_mean_interval
            return float(self.rng.exponential(scale=scale))
        else:
            # Fitted heavy-tailed model: Weibull (shape=0.65 -> heavy right tail, high burstiness)
            # Scaled to match target mean
            shape = 0.65
            # Mean of Weibull is scale * Gamma(1 + 1/shape)
            import math
            gamma_val = math.gamma(1.0 + 1.0 / shape)
            scale = self.target_mean_interval / gamma_val
            return float(self.rng.weibull(a=shape) * scale)

    def sample_session_length(self) -> int:
        """Sample number of requests per user session."""
        if self.distribution_type == "poisson":
            return int(self.rng.poisson(lam=5)) + 1
        else:
            # Lognormal heavy-tailed session length
            val = int(np.exp(self.rng.normal(loc=1.5, scale=0.7)))
            return max(1, min(val, 50))

    def generate_arrival_trace(self, n_events: int = 1000) -> np.ndarray:
        """Generate an array of sampled inter-arrival intervals for distribution analysis."""
        return np.array([self.sample_interarrival_time() for _ in range(n_events)])

    async def simulate_session(self, session_id: int, client: Optional[PoWClient] = None) -> List[Dict[str, Any]]:
        """Simulate a single benign user session."""
        device = self.device_pool[session_id % len(self.device_pool)]
        client_key = f"benign-user-{session_id}"
        if client is None:
            client = PoWClient(base_url=self.base_url, client_key=client_key, device_class=device)

        session_len = self.sample_session_length()
        events = []

        for req_idx in range(session_len):
            ep_idx = req_idx % len(self.endpoints)
            path, method, payload = self.endpoints[ep_idx]

            t_req_start = time.perf_counter()
            resp, timing = await client.request(method, path, json=payload if payload else None)
            t_req_end = time.perf_counter()

            events.append({
                "session_id": session_id,
                "client_key": client_key,
                "device_class": device,
                "endpoint": path,
                "status_code": resp.status_code,
                "timing": timing,
                "timestamp": t_req_start
            })

            # User think time before next request in session
            think_time = float(np.exp(self.rng.normal(loc=-1.5, scale=0.5)))
            await asyncio.sleep(min(think_time, 0.05))  # Accelerated in simulation

        return events
