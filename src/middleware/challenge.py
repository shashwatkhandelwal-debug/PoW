"""
Stateless HMAC Challenge and Work-Credit Token Management.
Spec Reference: §6 System Design (Challenge construction: stateless, server-authenticated, endpoint-bound).

Serialization Format (Delimitation Hardening):
Challenge Token: <base64url(json_payload)>.<hmac_sha256_hex_signature>
Work-Credit Token: <base64url(json_payload)>.<hmac_sha256_hex_signature>

Security Properties:
1. Stateless server authentication: Server secret HMAC prevents forging/tampering.
2. Endpoint binding: Tokens minted for "read" cannot be spent on "login" or "export".
3. Expiration TTL: Stale challenges rejected.
4. Replay protection: Spent nonces cached with TTL.
5. Work-credit tokens: Allow benign sessions to amortize proof over session TTL.
"""

import hmac
import hashlib
import json
import base64
import time
import secrets
from typing import Optional, Tuple, Dict, Any, Set


class ChallengeManager:
    """Manages stateless PoW challenges, replay prevention, and work credit tokens."""

    def __init__(self, secret_key: str, challenge_ttl: int = 60, credit_ttl: int = 300):
        self.secret_key = secret_key.encode("utf-8")
        self.challenge_ttl = challenge_ttl
        self.credit_ttl = credit_ttl
        # Local replay cache fallback (set of spent solution identifiers: (challenge_nonce, solution_nonce))
        self._spent_nonces: Dict[str, float] = {}

    def _sign(self, data_bytes: bytes) -> str:
        """Compute HMAC-SHA256 hex signature."""
        return hmac.new(self.secret_key, data_bytes, hashlib.sha256).hexdigest()

    def _verify_sig(self, data_bytes: bytes, signature_hex: str) -> bool:
        """Constant-time HMAC comparison."""
        expected_sig = self._sign(data_bytes)
        return hmac.compare_digest(expected_sig, signature_hex)

    def _cleanup_expired_spent_nonces(self, now: float) -> None:
        """Prune expired nonces from memory replay cache."""
        expired = [k for k, exp in self._spent_nonces.items() if exp < now]
        for k in expired:
            del self._spent_nonces[k]

    def mint_challenge(
        self,
        client_key: str,
        endpoint_class: str,
        difficulty: int,
        algorithm: str = "sha256"
    ) -> str:
        """
        Create a tamper-evident, HMAC-signed stateless challenge token.
        """
        payload = {
            "client_key": client_key,
            "endpoint_class": endpoint_class,
            "difficulty": int(difficulty),
            "algorithm": algorithm,
            "issued_at": time.time(),
            "nonce": secrets.token_hex(16)
        }
        json_bytes = json.dumps(payload, separators=(',', ':'), sort_keys=True).encode("utf-8")
        b64_payload = base64.urlsafe_b64encode(json_bytes).decode("ascii")
        sig = self._sign(b64_payload.encode("ascii"))
        return f"{b64_payload}.{sig}"

    def parse_and_verify_challenge(
        self,
        challenge_token: str,
        expected_client_key: str,
        expected_endpoint_class: str,
        now: Optional[float] = None
    ) -> Tuple[bool, Optional[Dict[str, Any]], Optional[str]]:
        """
        Verify HMAC signature, timestamp TTL, client_key, and endpoint_class.
        Returns: (is_valid, parsed_payload, error_reason)
        """
        if now is None:
            now = time.time()

        if not challenge_token or "." not in challenge_token:
            return False, None, "Malformed challenge token structure"

        parts = challenge_token.split(".", 1)
        b64_payload, signature_hex = parts[0], parts[1]

        # 1. Verify HMAC signature
        if not self._verify_sig(b64_payload.encode("ascii"), signature_hex):
            return False, None, "Invalid HMAC signature (tampered challenge)"

        # 2. Decode and parse JSON payload
        try:
            json_bytes = base64.urlsafe_b64decode(b64_payload.encode("ascii"))
            payload = json.loads(json_bytes.decode("utf-8"))
        except Exception:
            return False, None, "Invalid payload encoding or JSON syntax"

        # 3. Verify TTL
        issued_at = payload.get("issued_at", 0.0)
        if (now - issued_at) > self.challenge_ttl:
            return False, payload, "Challenge expired (TTL exceeded)"
        if issued_at > (now + 10.0):  # Future timestamp tolerance
            return False, payload, "Challenge timestamp from future"

        # 4. Verify client_key binding
        if payload.get("client_key") != expected_client_key:
            return False, payload, "Client key mismatch (token not issued for this client)"

        # 5. Verify endpoint_class binding
        if payload.get("endpoint_class") != expected_endpoint_class:
            return False, payload, f"Endpoint class mismatch: expected '{expected_endpoint_class}', got '{payload.get('endpoint_class')}'"

        return True, payload, None

    def is_nonce_spent(self, challenge_nonce: str, solution_nonce: str) -> bool:
        """Check whether the (challenge_nonce, solution_nonce) pair was already spent."""
        now = time.time()
        self._cleanup_expired_spent_nonces(now)
        key = f"{challenge_nonce}:{solution_nonce}"
        return key in self._spent_nonces

    def mark_nonce_spent(self, challenge_nonce: str, solution_nonce: str, ttl_seconds: Optional[int] = None) -> None:
        """Record nonce as spent with expiration."""
        if ttl_seconds is None:
            ttl_seconds = self.challenge_ttl * 2
        now = time.time()
        key = f"{challenge_nonce}:{solution_nonce}"
        self._spent_nonces[key] = now + ttl_seconds

    def mint_work_credit(self, client_key: str, endpoint_class: str) -> str:
        """
        Mint an HMAC-signed work-credit session token.
        """
        payload = {
            "type": "work_credit",
            "client_key": client_key,
            "endpoint_class": endpoint_class,
            "issued_at": time.time(),
            "nonce": secrets.token_hex(16)
        }
        json_bytes = json.dumps(payload, separators=(',', ':'), sort_keys=True).encode("utf-8")
        b64_payload = base64.urlsafe_b64encode(json_bytes).decode("ascii")
        sig = self._sign(b64_payload.encode("ascii"))
        return f"{b64_payload}.{sig}"

    def verify_work_credit(
        self,
        credit_token: str,
        expected_client_key: str,
        expected_endpoint_class: str,
        now: Optional[float] = None
    ) -> Tuple[bool, Optional[str]]:
        """
        Verify work-credit validity, timestamp TTL, and client/endpoint bindings.
        Returns: (is_valid, error_reason)
        """
        if now is None:
            now = time.time()

        if not credit_token or "." not in credit_token:
            return False, "Malformed credit token structure"

        parts = credit_token.split(".", 1)
        b64_payload, signature_hex = parts[0], parts[1]

        # 1. Verify HMAC signature
        if not self._verify_sig(b64_payload.encode("ascii"), signature_hex):
            return False, "Invalid work-credit HMAC signature"

        # 2. Decode payload
        try:
            json_bytes = base64.urlsafe_b64decode(b64_payload.encode("ascii"))
            payload = json.loads(json_bytes.decode("utf-8"))
        except Exception:
            return False, "Invalid payload encoding or JSON syntax"

        if payload.get("type") != "work_credit":
            return False, "Token is not a work-credit token"

        # 3. Check TTL
        issued_at = payload.get("issued_at", 0.0)
        if (now - issued_at) > self.credit_ttl:
            return False, "Work-credit token expired"

        # 4. Check client binding
        if payload.get("client_key") != expected_client_key:
            return False, "Client key mismatch on work-credit"

        # 5. Check endpoint binding
        if payload.get("endpoint_class") != expected_endpoint_class:
            return False, f"Endpoint class mismatch on work-credit: expected {expected_endpoint_class}"

        return True, None
