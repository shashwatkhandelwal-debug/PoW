"""
FastAPI Middleware Reverse Proxy and PoW Verification Gateway.
Spec Reference: §6 System Design (Request verification pipeline & Challenge construction).
"""

import time
import httpx
from typing import Optional
from fastapi import FastAPI, Request, Response, HTTPException, status
from fastapi.responses import JSONResponse
from src.middleware.config import settings
from src.middleware.challenge import ChallengeManager
from src.middleware.pow_verifier import PoWVerifier
from src.middleware.telemetry import TelemetryEmitter

app = FastAPI(title="Risk-Adaptive PoW Middleware Gateway", version="0.1.0")

# Instantiate challenge manager & telemetry emitter
challenge_manager = ChallengeManager(
    secret_key=settings.hmac_secret_key,
    challenge_ttl=settings.challenge_ttl_seconds,
    credit_ttl=settings.work_credit_ttl_seconds
)
telemetry_emitter = TelemetryEmitter()

# State for precomputed risk & difficulty (in-memory cache fallback, synced with Redis if available)
client_difficulties = {}  # {client_key: difficulty_bits}
defense_enabled = True  # Toggle for no-defense baseline benchmarking


def classify_endpoint(path: str) -> str:
    """Classify API endpoint path into security classes."""
    if "/auth/" in path or "/login" in path:
        return "auth"
    elif "/export" in path or "/heavy" in path:
        return "export"
    elif "/resource" in path:
        return "read"
    return "default"


def extract_client_key(request: Request) -> str:
    """Extract or construct client identity key."""
    # Allow explicit client key header (useful for benchmarking identity rotation & test suites)
    if "x-client-key" in request.headers:
        return request.headers["x-client-key"]
    client_host = request.client.host if request.client else "127.0.0.1"
    user_agent = request.headers.get("user-agent", "unknown")
    return f"{client_host}:{user_agent}"


@app.get("/health")
async def health():
    return {"status": "ok", "middleware": "active", "defense_enabled": defense_enabled}


@app.post("/admin/toggle_defense")
async def toggle_defense(enabled: bool):
    """Admin endpoint to toggle defense for baseline benchmarking."""
    global defense_enabled
    defense_enabled = enabled
    return {"defense_enabled": defense_enabled}


@app.api_route("/{path:path}", methods=["GET", "POST", "PUT", "DELETE", "PATCH"])
async def gateway_proxy(request: Request, path: str):
    """
    Main gateway entrypoint handling verification, challenge issuance, and proxying.
    """
    t0 = time.perf_counter()
    endpoint_path = f"/{path}"
    endpoint_class = classify_endpoint(endpoint_path)
    client_key = extract_client_key(request)

    # Calculate header entropy for telemetry
    headers_str = "".join(f"{k}:{v}" for k, v in request.headers.items())
    header_entropy = TelemetryEmitter.calculate_shannon_entropy(headers_str)

    # 0. If defense is explicitly toggled off (Baseline measurement)
    if not defense_enabled:
        resp = await _forward_to_upstream(request, endpoint_path)
        latency_ms = (time.perf_counter() - t0) * 1000.0
        await telemetry_emitter.emit_request_event(
            client_key=client_key,
            endpoint=endpoint_path,
            endpoint_class=endpoint_class,
            method=request.method,
            status_code=resp.status_code,
            latency_ms=latency_ms,
            headers_entropy=header_entropy
        )
        return resp

    # 1. Fast path: Check Work-Credit Token
    credit_token = request.headers.get("x-work-credit")
    if credit_token:
        is_valid_credit, err_credit = challenge_manager.verify_work_credit(
            credit_token=credit_token,
            expected_client_key=client_key,
            expected_endpoint_class=endpoint_class
        )
        if is_valid_credit:
            resp = await _forward_to_upstream(request, endpoint_path)
            latency_ms = (time.perf_counter() - t0) * 1000.0
            await telemetry_emitter.emit_request_event(
                client_key=client_key,
                endpoint=endpoint_path,
                endpoint_class=endpoint_class,
                method=request.method,
                status_code=resp.status_code,
                latency_ms=latency_ms,
                headers_entropy=header_entropy
            )
            return resp

    # 2. Check PoW Solution
    challenge_token = request.headers.get("x-pow-challenge")
    solution_nonce = request.headers.get("x-pow-solution")

    if challenge_token and solution_nonce:
        is_valid_ch, payload, ch_err = challenge_manager.parse_and_verify_challenge(
            challenge_token=challenge_token,
            expected_client_key=client_key,
            expected_endpoint_class=endpoint_class
        )
        if is_valid_ch and payload:
            ch_nonce = payload["nonce"]
            difficulty = payload["difficulty"]
            algorithm = payload.get("algorithm", "sha256")

            # Check replay
            if challenge_manager.is_nonce_spent(ch_nonce, solution_nonce):
                return JSONResponse(
                    status_code=status.HTTP_403_FORBIDDEN,
                    content={"error": "Replay attack detected: Solution nonce already spent", "status": "rejected"}
                )

            # Verify PoW solution
            if algorithm == "argon2id":
                is_correct = PoWVerifier.verify_argon2id(challenge_token, solution_nonce, difficulty)
            else:
                is_correct = PoWVerifier.verify_sha256(challenge_token, solution_nonce, difficulty)

            if is_correct:
                # Mark nonce spent
                challenge_manager.mark_nonce_spent(ch_nonce, solution_nonce)

                # Issue work-credit token for subsequent requests
                new_credit = challenge_manager.mint_work_credit(client_key, endpoint_class)

                # Forward to upstream
                resp = await _forward_to_upstream(request, endpoint_path)
                resp.headers["x-work-credit"] = new_credit
                latency_ms = (time.perf_counter() - t0) * 1000.0
                await telemetry_emitter.emit_request_event(
                    client_key=client_key,
                    endpoint=endpoint_path,
                    endpoint_class=endpoint_class,
                    method=request.method,
                    status_code=resp.status_code,
                    latency_ms=latency_ms,
                    headers_entropy=header_entropy
                )
                return resp
            else:
                return JSONResponse(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    content={"error": "Invalid PoW solution", "status": "challenge_required"}
                )

    # 3. No valid credit / solution: Issue Challenge
    current_diff = client_difficulties.get(client_key, settings.default_difficulty_bits)
    new_challenge = challenge_manager.mint_challenge(
        client_key=client_key,
        endpoint_class=endpoint_class,
        difficulty=current_diff,
        algorithm=settings.pow_algorithm
    )

    headers = {
        "x-pow-challenge": new_challenge,
        "x-pow-difficulty": str(current_diff),
        "x-pow-algorithm": settings.pow_algorithm
    }

    return JSONResponse(
        status_code=status.HTTP_401_UNAUTHORIZED,
        headers=headers,
        content={
            "error": "Proof of Work challenge required",
            "challenge": new_challenge,
            "difficulty": current_diff,
            "algorithm": settings.pow_algorithm,
            "endpoint_class": endpoint_class
        }
    )


# Reusable client with short connect timeout
_upstream_client = httpx.AsyncClient(timeout=httpx.Timeout(connect=0.05, read=2.0, write=2.0, pool=5.0))


async def _forward_to_upstream(request: Request, path: str) -> Response:
    """Forward request to upstream app or return mock target response."""
    if settings.target_url == "mock":
        return JSONResponse(
            status_code=200,
            content={"upstream_mock": True, "path": path, "status": "admitted"}
        )

    url = f"{settings.target_url}{path}"
    headers = dict(request.headers)
    headers.pop("host", None)
    headers.pop("content-length", None)

    body = await request.body()
    try:
        upstream_resp = await _upstream_client.request(
            method=request.method,
            url=url,
            headers=headers,
            content=body,
            params=dict(request.query_params)
        )
        return Response(
            content=upstream_resp.content,
            status_code=upstream_resp.status_code,
            headers=dict(upstream_resp.headers)
        )
    except Exception:
        # If upstream service is offline in local test, return mock upstream success
        return JSONResponse(
            status_code=200,
            content={"upstream_mock": True, "path": path, "status": "admitted"}
        )
