"""
Proof of Work utility using PBKDF2-SHA512.

The PoW requires finding nonces where PBKDF2(challenge, nonce) produces
output with a zero first byte. Each work unit requires finding one such nonce.
All valid nonces are concatenated into a solution for server verification.
"""

import hashlib
import secrets

EASY = 2  # Around 0.25s
NORMAL = 8  # Around 1s
HARD = 32  # Around 4s


def generate_challenge() -> bytes:
    """Generate a random 8-byte challenge."""
    return secrets.token_bytes(8)


def verify_pow(challenge: bytes, solution: bytes, work: int = NORMAL) -> None:
    """Verify a Proof of Work solution.

    Args:
        challenge: 8-byte server-provided challenge
        solution: Concatenated 8-byte nonces (8 * work bytes)
        work: Number of work units expected

    Raises:
        ValueError: If the solution is invalid
    """
    if len(challenge) != 8:
        raise ValueError("Invalid challenge length")

    if len(solution) != 8 * work:
        raise ValueError("Invalid solution length")

    # Verify each work unit - check that PBKDF2 output starts with 0x00
    for i in range(work):
        nonce = solution[i * 8 : (i + 1) * 8]
        # Require first byte of PBKDF2-SHA512 to be zero
        result = hashlib.pbkdf2_hmac("sha512", challenge, nonce, 128, 2)
        if result[0] or result[1] & 0x07:
            raise ValueError("Invalid PoW solution")
