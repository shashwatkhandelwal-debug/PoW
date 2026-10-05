"""
Tests for Proof-of-Work Verification and Solver (SHA-256 and Argon2id).
Spec Reference: §6 System Design & RQ4 Hardware Equity.
"""

import time
import pytest
from src.middleware.pow_verifier import PoWVerifier
from src.client.solver import PoWSolver


def test_sha256_valid_solution():
    """Verify solver produces valid SHA-256 solution satisfying target difficulty."""
    solver = PoWSolver(device_class="laptop")
    challenge = "test_challenge_data_string_12345"
    difficulty = 10  # 10 leading zero bits

    nonce, wall_time, cpu_time, hashes = solver.solve_sha256(challenge, difficulty)
    assert nonce is not None
    assert hashes > 0

    # Verify with PoWVerifier
    is_valid = PoWVerifier.verify_sha256(challenge, nonce, difficulty)
    assert is_valid is True


def test_sha256_invalid_solution_rejected():
    """Verify invalid nonce is rejected by PoWVerifier."""
    challenge = "test_challenge_data_string_12345"
    difficulty = 16

    # Fake nonce that is almost certainly not a valid 16-bit solution
    fake_nonce = "definitely_invalid_nonce_999999"
    # Even if by extreme fluke it matched, verify_sha256 on a higher difficulty will fail
    is_valid = PoWVerifier.verify_sha256(challenge, fake_nonce, difficulty_bits=32)
    assert is_valid is False


def test_argon2id_solution():
    """Verify Argon2id solver and verifier round-trip."""
    solver = PoWSolver(device_class="laptop")
    challenge = "argon2_test_challenge_abc"
    difficulty = 2  # Low difficulty for fast test execution

    nonce, wall_time, cpu_time, hashes = solver.solve_argon2id(
        challenge,
        difficulty_bits=difficulty,
        time_cost=1,
        memory_cost_kib=1024,
        parallelism=1
    )
    assert nonce is not None

    is_valid = PoWVerifier.verify_argon2id(
        challenge,
        nonce,
        difficulty_bits=difficulty,
        time_cost=1,
        memory_cost_kib=1024,
        parallelism=1
    )
    assert is_valid is True
