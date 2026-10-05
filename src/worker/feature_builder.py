"""
Sliding Window Feature Extraction & Aggregation.
Spec Reference: §6 System Design & §7.2 Leakage Audit.

Calculates behavioral features per client identity over sliding time windows:
1. Request Rate (req/s over active window).
2. Inter-arrival Mean (seconds).
3. Inter-arrival Variance (seconds^2).
4. Burstiness Index (variance / mean of arrival counts).
5. Endpoint Entropy (Shannon entropy of requested endpoints).
6. Error Rate (fraction of 4xx/5xx responses).
7. Header Shannon Entropy.
"""

from typing import Dict, List, Any, Optional
import math
import numpy as np


class FeatureBuilder:
    """Extracts statistical and information-theoretic features from sliding event windows."""

    def __init__(self, window_duration_seconds: float = 60.0):
        self.window_duration = window_duration_seconds
        # In-memory buffer per client identity: {client_key: [event1, event2, ...]}
        self.client_buffers: Dict[str, List[Dict[str, Any]]] = {}

    def add_event(self, client_key: str, event: Dict[str, Any]) -> None:
        """Append event to client buffer and prune expired entries."""
        if client_key not in self.client_buffers:
            self.client_buffers[client_key] = []

        now = float(event.get("timestamp", 0.0))
        self.client_buffers[client_key].append(event)

        # Prune events outside window
        cutoff = now - self.window_duration
        self.client_buffers[client_key] = [
            e for e in self.client_buffers[client_key] if float(e.get("timestamp", 0.0)) >= cutoff
        ]

    def compute_features(self, client_key: str, current_time: Optional[float] = None) -> np.ndarray:
        """
        Compute 7-dimensional feature vector for given client key over active window.
        Returns: np.ndarray of shape (7,)
        [rate, interarrival_mean, interarrival_var, burstiness, endpoint_entropy, error_rate, header_entropy]
        """
        events = self.client_buffers.get(client_key, [])
        if not events:
            # Return neutral baseline vector for unseen client
            return np.array([0.0, 1.0, 0.0, 0.0, 0.0, 0.0, 3.5], dtype=np.float64)

        if current_time is None:
            current_time = float(events[-1].get("timestamp", 0.0))

        cutoff = current_time - self.window_duration
        window_events = [e for e in events if float(e.get("timestamp", 0.0)) >= cutoff]
        n_events = len(window_events)

        if n_events == 0:
            return np.array([0.0, 1.0, 0.0, 0.0, 0.0, 0.0, 3.5], dtype=np.float64)

        timestamps = [float(e["timestamp"]) for e in window_events]
        time_span = max(timestamps[-1] - timestamps[0], 0.01) if n_events > 1 else self.window_duration

        # 1. Request rate (req/s)
        rate = n_events / max(time_span, 1.0)

        # 2 & 3. Inter-arrival mean and variance
        if n_events > 1:
            diffs = np.diff(timestamps)
            ia_mean = float(np.mean(diffs))
            ia_var = float(np.var(diffs))
        else:
            ia_mean = 1.0
            ia_var = 0.0

        # 4. Burstiness (Dispersion index = Var(diffs) / Mean(diffs)^2)
        burstiness = float(ia_var / max(ia_mean ** 2, 1e-6))

        # 5. Endpoint access entropy
        endpoints = [str(e.get("endpoint", "/")) for e in window_events]
        endpoint_counts = {}
        for ep in endpoints:
            endpoint_counts[ep] = endpoint_counts.get(ep, 0) + 1
        entropy = 0.0
        for cnt in endpoint_counts.values():
            p = cnt / n_events
            entropy -= p * math.log2(p)

        # 6. Error rate (fraction of 4xx/5xx)
        error_count = sum(1 for e in window_events if int(e.get("status_code", 200)) >= 400)
        error_rate = error_count / n_events

        # 7. Header entropy
        header_entropies = [float(e.get("headers_entropy", 3.5)) for e in window_events]
        mean_header_entropy = float(np.mean(header_entropies))

        return np.array([
            rate,
            ia_mean,
            ia_var,
            burstiness,
            entropy,
            error_rate,
            mean_header_entropy
        ], dtype=np.float64)
