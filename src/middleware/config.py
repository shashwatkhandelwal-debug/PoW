"""
Middleware Configuration Settings.
Spec Reference: §6 System Design (Challenge construction, Redis telemetry, Out-of-band scoring).

Provides runtime configuration for:
- Redis connection parameters.
- Target upstream service URL.
- HMAC secret key for signing stateless challenges and work credits.
- Challenge and work-credit TTLs.
- Default difficulty and endpoint class mappings.
"""

from pydantic_settings import BaseSettings


class MiddlewareSettings(BaseSettings):
    redis_host: str = "localhost"
    redis_port: int = 6379
    redis_db: int = 0
    target_url: str = "http://localhost:8000"
    middleware_port: int = 8080

    # Cryptographic keys
    hmac_secret_key: str = "default-insecure-secret-key-replace-in-env"

    # Challenge & Credit parameters
    challenge_ttl_seconds: int = 60
    work_credit_ttl_seconds: int = 300
    default_difficulty_bits: int = 8
    pow_algorithm: str = "sha256"  # "sha256" or "argon2id"

    # Redis keys & Stream names
    telemetry_stream_key: str = "stream:telemetry"
    replay_set_key_prefix: str = "pow:spent:"
    risk_key_prefix: str = "risk:"
    difficulty_key_prefix: str = "diff:"

    class Config:
        env_file = ".env"
        extra = "ignore"


settings = MiddlewareSettings()
