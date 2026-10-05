"""
HTTP Client with Autonomous PoW Handling & Credit Token Caching.
Spec Reference: §6 System Design (Work-credit tokens, client flow).
"""

from typing import Optional, Dict, Any, Tuple
import time
import httpx
from src.client.solver import PoWSolver


class PoWClient:
    """HTTP client that automatically resolves PoW challenges and caches work credits."""

    def __init__(self, base_url: str, client_key: Optional[str] = None, device_class: str = "laptop"):
        self.base_url = base_url.rstrip("/")
        self.client_key = client_key or "test-client-1"
        self.solver = PoWSolver(device_class=device_class)
        self.work_credit_tokens: Dict[str, str] = {}  # {endpoint_class: token}
        self.http_client = httpx.AsyncClient(timeout=10.0)

        # Performance tracking metrics
        self.total_solve_time = 0.0
        self.total_solve_cpu = 0.0
        self.total_challenges_solved = 0
        self.requests_sent = 0

    def _get_endpoint_class(self, path: str) -> str:
        if "/auth/" in path or "/login" in path:
            return "auth"
        elif "/export" in path or "/heavy" in path:
            return "export"
        elif "/resource" in path:
            return "read"
        return "default"

    async def request(self, method: str, path: str, headers: Optional[Dict[str, str]] = None, **kwargs) -> Tuple[httpx.Response, Dict[str, Any]]:
        """
        Execute request with automatic challenge-response resolution and credit caching.
        Returns: (Response, timing_metrics_dict)
        """
        self.requests_sent += 1
        url = f"{self.base_url}{path}" if path.startswith("/") else f"{self.base_url}/{path}"
        req_headers = dict(headers or {})
        req_headers["x-client-key"] = self.client_key

        ep_class = self._get_endpoint_class(path)
        if ep_class in self.work_credit_tokens:
            req_headers["x-work-credit"] = self.work_credit_tokens[ep_class]

        t0_e2e = time.perf_counter()
        resp = await self.http_client.request(method, url, headers=req_headers, **kwargs)

        solve_wall = 0.0
        solve_cpu = 0.0
        challenge_solved = False

        # If PoW challenge required (401 with challenge header)
        if resp.status_code == 401 and "x-pow-challenge" in resp.headers:
            challenge_str = resp.headers["x-pow-challenge"]
            diff_bits = int(resp.headers.get("x-pow-difficulty", "8"))
            algo = resp.headers.get("x-pow-algorithm", "sha256")

            if algo == "argon2id":
                nonce, s_wall, s_cpu, _ = self.solver.solve_argon2id(challenge_str, diff_bits)
            else:
                nonce, s_wall, s_cpu, _ = self.solver.solve_sha256(challenge_str, diff_bits)

            solve_wall = s_wall
            solve_cpu = s_cpu
            self.total_solve_time += s_wall
            self.total_solve_cpu += s_cpu
            self.total_challenges_solved += 1
            challenge_solved = True

            # Retry with solution headers
            req_headers["x-pow-challenge"] = challenge_str
            req_headers["x-pow-solution"] = nonce or "0"

            resp = await self.http_client.request(method, url, headers=req_headers, **kwargs)

            # Store granted work credit
            if "x-work-credit" in resp.headers:
                self.work_credit_tokens[ep_class] = resp.headers["x-work-credit"]

        t1_e2e = time.perf_counter()
        total_latency = t1_e2e - t0_e2e

        timing = {
            "total_latency_seconds": total_latency,
            "solve_wall_seconds": solve_wall,
            "solve_cpu_seconds": solve_cpu,
            "challenge_solved": challenge_solved,
            "status_code": resp.status_code
        }
        return resp, timing

    async def close(self):
        await self.http_client.aclose()
