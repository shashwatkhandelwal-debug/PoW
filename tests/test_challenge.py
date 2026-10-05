"""
Tests for Stateless HMAC Challenge, Replay Protection, and Work Credits.
Spec Reference: §6 System Design (Challenge construction).

Validates:
1. Replay attack rejection (nonce cannot be spent twice).
2. Cross-endpoint token rejection (class binding).
3. Tamper detection (modified payload or signature rejected).
4. Expiration TTL (stale challenges rejected).
5. Work-credit validity and fast-path bypass.
6. IPv6 client key serialization and parsing.
"""

import time
import pytest
from src.middleware.challenge import ChallengeManager
from src.middleware.pow_verifier import PoWVerifier
from src.client.solver import PoWSolver


@pytest.fixture
def manager():
    return ChallengeManager(secret_key="test-secret-key-12345", challenge_ttl=5, credit_ttl=10)


def test_replay_protection_rejects_reused_nonce(manager):
    """Prove replay cache rejects a previously spent solution nonce."""
    client_key = "client-alpha"
    endpoint_class = "auth"
    difficulty = 4

    challenge = manager.mint_challenge(client_key, endpoint_class, difficulty)
    is_valid, payload, _ = manager.parse_and_verify_challenge(challenge, client_key, endpoint_class)
    assert is_valid is True
    assert payload is not None

    ch_nonce = payload["nonce"]
    solver = PoWSolver(device_class="laptop")
    sol_nonce, _, _, _ = solver.solve_sha256(challenge, difficulty)
    assert sol_nonce is not None

    # First use: should NOT be spent
    assert manager.is_nonce_spent(ch_nonce, sol_nonce) is False

    # Mark spent
    manager.mark_nonce_spent(ch_nonce, sol_nonce)

    # Second use (replay attempt): MUST be recognized as spent
    assert manager.is_nonce_spent(ch_nonce, sol_nonce) is True


def test_cross_endpoint_token_rejected(manager):
    """Prove token minted for one endpoint_class is rejected on another."""
    client_key = "client-alpha"
    challenge_read = manager.mint_challenge(client_key, endpoint_class="read", difficulty=4)

    # Attempt to spend "read" challenge on "auth" endpoint
    is_valid, payload, err = manager.parse_and_verify_challenge(challenge_read, client_key, expected_endpoint_class="auth")
    assert is_valid is False
    assert "Endpoint class mismatch" in err


def test_tampered_challenge_rejected(manager):
    """Prove tampered HMAC signature or payload fails verification."""
    client_key = "client-alpha"
    challenge = manager.mint_challenge(client_key, "read", difficulty=4)

    parts = challenge.split(".")
    payload_b64, sig = parts[0], parts[1]

    # Tamper 1: Tampered signature
    tampered_sig = ("0" if sig[0] != "0" else "1") + sig[1:]
    is_valid, _, err = manager.parse_and_verify_challenge(f"{payload_b64}.{tampered_sig}", client_key, "read")
    assert is_valid is False
    assert "Invalid HMAC signature" in err

    # Tamper 2: Modified payload
    is_valid2, _, err2 = manager.parse_and_verify_challenge(f"dGFtcGVyZWQ.{sig}", client_key, "read")
    assert is_valid2 is False


def test_expired_challenge_rejected(manager):
    """Prove challenges past TTL are rejected."""
    client_key = "client-alpha"
    challenge = manager.mint_challenge(client_key, "read", difficulty=4)

    # Simulate verification 10 seconds later (TTL is 5s)
    future_time = time.time() + 10.0
    is_valid, _, err = manager.parse_and_verify_challenge(challenge, client_key, "read", now=future_time)
    assert is_valid is False
    assert "Challenge expired" in err


def test_work_credit_session_validity(manager):
    """Prove valid work credit bypasses PoW solve and respects endpoint binding."""
    client_key = "client-alpha"
    credit = manager.mint_work_credit(client_key, "read")

    # Valid on matching endpoint
    is_valid, err = manager.verify_work_credit(credit, client_key, "read")
    assert is_valid is True
    assert err is None

    # Rejected on different endpoint
    is_valid_diff, err_diff = manager.verify_work_credit(credit, client_key, "auth")
    assert is_valid_diff is False
    assert "Endpoint class mismatch" in err_diff

    # Rejected on different client
    is_valid_client, err_client = manager.verify_work_credit(credit, "client-beta", "read")
    assert is_valid_client is False
    assert "Client key mismatch" in err_client


def test_ipv6_client_key_serialization(manager):
    """Prove challenges correctly serialize and parse IPv6 client keys containing colons."""
    ipv6_client = "2001:0db8:85a3:0000:0000:8a2e:0370:7334"
    challenge = manager.mint_challenge(ipv6_client, "read", difficulty=6)

    is_valid, payload, err = manager.parse_and_verify_challenge(challenge, ipv6_client, "read")
    assert is_valid is True
    assert payload["client_key"] == ipv6_client
    assert err is None
