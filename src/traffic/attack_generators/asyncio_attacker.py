"""
Hand-rolled AsyncIO Attack Generator.
Spec Reference: §4 Threat Model & §7.2 Cross-generator generalization (Stack A).

Features:
1. High-throughput attack families:
   - "credential_stuffing": Automated brute-force credential stuffing on /api/v1/auth/login.
   - "scraping": Aggressive recursive resource extraction on /api/v1/resource.
   - "dos": Computationally expensive queries on /api/v1/heavy-export.
2. Identity rotation modeling:
   - Fixed identity (persistent client key) vs Rotating identity (new client key per N requests).
3. Accurate CPU-second cost instrumentation:
   - Measures exact user + system CPU seconds consumed by solver and networking.
"""

import time
import asyncio
import secrets
from typing import Dict, Any, List, Optional
import httpx
from src.client.client import PoWClient
from src.client.solver import PoWSolver


class AsyncIOAttacker:
    """High-throughput async attacker instrumented for exact CPU-second cost tracking."""

    def __init__(
        self,
        base_url: str,
        attack_type: str = "credential_stuffing",
        attacker_device: str = "laptop",
        concurrency: int = 5,
        rotate_identity: bool = False,
        requests_per_identity: int = 1,
        solve_pow: bool = True,
        seed: int = 42
    ):
        self.base_url = base_url
        self.attack_type = attack_type
        self.attacker_device = attacker_device
        self.concurrency = concurrency
        self.rotate_identity = rotate_identity
        self.requests_per_identity = requests_per_identity
        self.solve_pow = solve_pow
        self.seed = seed

    def _get_target_request_details(self, req_idx: int) -> tuple[str, str, Optional[dict]]:
        """Generate payload for attack family."""
        if self.attack_type == "credential_stuffing":
            return "/api/v1/auth/login", "POST", {
                "username": f"user_{req_idx % 1000}",
                "password": f"pwd_guess_{secrets.token_hex(4)}"
            }
        elif self.attack_type == "dos":
            return "/api/v1/heavy-export", "POST", {
                "query": f"SELECT * FROM large_table WHERE data='{secrets.token_hex(8)}'",
                "limit": 10000
            }
        else:  # "scraping"
            return f"/api/v1/resource?record_id={req_idx}", "GET", None

    async def run_campaign(
        self,
        n_requests: int = 100,
        custom_client: Optional[PoWClient] = None
    ) -> Dict[str, Any]:
        """
        Execute attack campaign and record admitted requests, rejected requests,
        solve CPU-seconds, and throughput metrics.
        """
        t0_wall = time.perf_counter()
        t0_cpu = time.process_time()

        admitted_count = 0
        rejected_count = 0
        challenges_encountered = 0
        total_solve_wall = 0.0
        total_solve_cpu = 0.0

        current_identity_idx = 0
        client_key = f"attacker-bot-{current_identity_idx}"

        if custom_client is not None:
            client = custom_client
        else:
            client = PoWClient(
                base_url=self.base_url,
                client_key=client_key,
                device_class=self.attacker_device
            )

        for i in range(n_requests):
            if self.rotate_identity and (i > 0) and (i % self.requests_per_identity == 0):
                current_identity_idx += 1
                client_key = f"attacker-bot-rot-{current_identity_idx}"
                client.client_key = client_key
                client.work_credit_tokens.clear()

            path, method, payload = self._get_target_request_details(i)

            resp, timing = await client.request(method, path, json=payload if payload else None)

            if timing["challenge_solved"]:
                challenges_encountered += 1
                total_solve_wall += timing["solve_wall_seconds"]
                total_solve_cpu += timing["solve_cpu_seconds"]

            if resp.status_code == 200 or (self.attack_type == "credential_stuffing" and resp.status_code == 401 and "error" not in resp.json()):
                admitted_count += 1
            else:
                if resp.status_code in (401, 403, 429):
                    rejected_count += 1
                else:
                    admitted_count += 1

        t1_wall = time.perf_counter()
        t1_cpu = time.process_time()

        total_wall_time = t1_wall - t0_wall
        total_cpu_consumed = t1_cpu - t0_cpu + total_solve_cpu

        return {
            "attack_type": self.attack_type,
            "rotate_identity": self.rotate_identity,
            "requests_attempted": n_requests,
            "admitted_requests": admitted_count,
            "rejected_requests": rejected_count,
            "challenges_solved": challenges_encountered,
            "total_solve_wall_seconds": total_solve_wall,
            "total_solve_cpu_seconds": total_solve_cpu,
            "total_campaign_cpu_seconds": total_cpu_consumed,
            "total_wall_seconds": total_wall_time,
            "throughput_req_per_sec": float(admitted_count / max(total_wall_time, 1e-6))
        }
