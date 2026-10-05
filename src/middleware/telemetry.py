"""
Non-blocking Redis Telemetry Stream Emitter.
Spec Reference: §6 System Design (XADD telemetry, asynchronous out-of-band scoring).

Responsibilities:
1. Extract request metadata (client identity, endpoint, timestamp, payload size, headers).
2. Append request event records to the Redis telemetry stream (`XADD stream:telemetry`).
3. Ensure telemetry emission adds minimal overhead (< 0.2ms) and does not block the hot request path.
"""

from typing import Any, Dict, Optional
import time
import math


class TelemetryEmitter:
    """Emits request telemetry events asynchronously to Redis Stream or in-memory ring buffer."""

    def __init__(self, redis_client: Optional[Any] = None, stream_key: str = "stream:telemetry"):
        self.redis = redis_client
        self.stream_key = stream_key
        # In-memory buffer for local testing or when Redis is disabled
        self.local_buffer = []

    @staticmethod
    def calculate_shannon_entropy(text: str) -> float:
        """Compute Shannon entropy of a string (e.g. headers or paths)."""
        if not text:
            return 0.0
        prob = [float(text.count(c)) / len(text) for c in dict.fromkeys(list(text))]
        return -sum([p * math.log(p) / math.log(2.0) for p in prob if p > 0.0])

    async def emit_request_event(
        self,
        client_key: str,
        endpoint: str,
        endpoint_class: str,
        method: str,
        status_code: int,
        latency_ms: float,
        headers_entropy: float,
        timestamp: Optional[float] = None
    ) -> None:
        """Publish structured telemetry event."""
        if timestamp is None:
            timestamp = time.time()

        event_data = {
            "client_key": str(client_key),
            "endpoint": str(endpoint),
            "endpoint_class": str(endpoint_class),
            "method": str(method),
            "status_code": str(status_code),
            "latency_ms": f"{latency_ms:.3f}",
            "headers_entropy": f"{headers_entropy:.4f}",
            "timestamp": f"{timestamp:.6f}"
        }

        if self.redis is not None:
            try:
                await self.redis.xadd(self.stream_key, event_data, maxlen=50000, approximate=True)
            except Exception:
                self.local_buffer.append(event_data)
        else:
            self.local_buffer.append(event_data)
