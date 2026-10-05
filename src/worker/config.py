"""
Worker Configuration Settings.
Spec Reference: §6 System Design (Async scorer worker, controller parameters, scoring lag Δt).

Provides configuration for:
- Redis connection & stream consumer group settings.
- Rolling window duration (seconds) and update cadence.
- Scoring lag ablation settings (Δt ∈ {0.1, 1.0, 10.0} s).
- Anomaly detector hyper-parameters (IsolationForest contamination, n_estimators).
- Calibrator settings (Platt scaling / Isotonic regression).
- Difficulty controller tuning (loss parameters B, λ; hysteresis thresholds, dwell time, EWMA alpha).
"""

from pydantic_settings import BaseSettings


class WorkerSettings(BaseSettings):
    redis_host: str = "localhost"
    redis_port: int = 6379
    redis_db: int = 0

    # Stream consumer settings
    stream_key: str = "stream:telemetry"
    consumer_group: str = "group:scorers"
    consumer_name: str = "worker-1"
    batch_size: int = 100
    block_ms: int = 1000

    # Sliding window & Scoring lag Δt
    window_duration_seconds: float = 60.0
    scoring_lag_seconds: float = 0.5  # Δt tunable: 0.1, 1.0, 10.0

    # Anomaly detector & Calibrator
    isolation_forest_estimators: int = 100
    contamination: float = 0.05
    calibrator_method: str = "isotonic"  # "isotonic" or "sigmoid" (Platt)

    # Economic difficulty derivation (B, λ)
    attacker_benefit_B: float = 10.0
    benign_latency_penalty_lambda: float = 1.0

    # Controller parameters (Damped)
    ewma_alpha: float = 0.3
    hysteresis_delta_up: float = 0.15
    hysteresis_delta_down: float = 0.20
    min_dwell_time_seconds: float = 5.0
    slew_rate_limit: int = 1  # max difficulty step per interval

    class Config:
        env_file = ".env"
        extra = "ignore"


worker_settings = WorkerSettings()
