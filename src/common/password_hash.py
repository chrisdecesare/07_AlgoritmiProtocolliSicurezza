"""
hpwd = H(password ∥ saltM), salt casuale a 32 byte per ogni credenziale
(§2.2.5).

Attenzione: hpwd resta plaintext-equivalent, cioè chi ruba il database
dell'IdP può rispondere a qualsiasi challenge futura senza conoscere la
password vera — il salt blocca solo il precalcolo (rainbow table), non
un furto diretto del DB. Non è un bug qui: il documento accetta questo
costo esplicitamente (§2.2.5), quindi non ho aggiunto un PBKDF2 di
fantasia per "sistemarlo" di nascosto.
"""
from __future__ import annotations

import os

from src.common.hashing import sha256

SALT_LENGTH_BYTES = 32


def generate_salt() -> bytes:
    """saltM: casuale, 32 byte, univoco per credenziale."""
    return os.urandom(SALT_LENGTH_BYTES)


def hash_password(password: str, salt: bytes) -> bytes:
    """hpwd = H(password ∥ saltM) — §2.2.5."""
    return sha256(password.encode("utf-8"), salt)
