"""
Proof-of-Work Verification Module.
Spec Reference: §6 System Design & RQ4 Hardware Equity (SHA-256 vs Argon2id).

Responsibilities:
1. Verify SHA-256 PoW solutions:
   Checks whether SHA256(challenge_str || solution_nonce) has the required leading zero bits.
2. Verify Argon2id PoW solutions:
   Checks whether Argon2id(challenge_str, salt=nonce, time_cost, memory_cost, parallelism) satisfies target constraint.
3. Track and measure server-side verification CPU time and latency budget.
"""

import hashlib
import time
from typing import Tuple, Optional
import argon2


class PoWVerifier:
    """Verifies Proof of Work solutions for SHA-256 and Argon2id."""

    @staticmethod
    def _count_leading_zero_bits(hash_bytes: bytes) -> int:
        """Count the number of leading zero bits in a byte string."""
        total_zero_bits = 0
        for byte in hash_bytes:
            if byte == 0:
                total_zero_bits += 8
            else:
                # Count leading zeros in this non-zero byte
                total_zero_bits += (8 - byte.bit_length())
                break
        return total_zero_bits

    @staticmethod
    def verify_sha256(challenge_str: str, solution_nonce: str, difficulty_bits: int) -> bool:
        """
        Verify that SHA256(challenge_str + solution_nonce) has >= difficulty_bits leading zero bits.
        """
        if difficulty_bits <= 0:
            return True
        data = (challenge_str + solution_nonce).encode("utf-8")
        digest = hashlib.sha256(data).digest()
        leading_zeros = PoWVerifier._count_leading_zero_bits(digest)
        return leading_zeros >= difficulty_bits

    @staticmethod
    def verify_argon2id(
        challenge_str: str,
        solution_nonce: str,
        difficulty_bits: int,
        time_cost: int = 1,
        memory_cost_kib: int = 16384,
        parallelism: int = 1
    ) -> bool:
        """
        Verify Argon2id memory-hard proof of work.
        Uses raw Argon2id hash output and checks leading zero bits.
        """
        if difficulty_bits <= 0:
            return True
        salt = hashlib.sha256(challenge_str.encode("utf-8")).digest()[:16]
        # Generate raw argon2id hash
        raw_hash = argon2.low_level.hash_secret_raw(
            secret=solution_nonce.encode("utf-8"),
            salt=salt,
            time_cost=time_cost,
            memory_cost=memory_cost_kib,
            parallelism=parallelism,
            hash_len=32,
            type=argon2.low_level.Type.ID
        )
        leading_zeros = PoWVerifier._count_leading_zero_bits(raw_hash)
        return leading_zeros >= difficulty_bits
