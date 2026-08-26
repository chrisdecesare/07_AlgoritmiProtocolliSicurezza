"""
SHA-256 condiviso da tutto il prototipo (è l'hash usato ovunque nel
documento: OAEP §2.2.1, firme §2.2.2, autenticazione §2.2.5).

Accetta più pezzi di byte e li concatena da solo, così una chiamata come
sha256(n1, hpwd) si legge esattamente come la formula H(n1 ∥ hpwd) invece
di doverla scrivere a mano ogni volta.
"""
from __future__ import annotations

from cryptography.hazmat.primitives import hashes


def sha256(*chunks: bytes) -> bytes:
    """H(chunks[0] ∥ chunks[1] ∥ ...) con SHA-256."""
    digest = hashes.Hash(hashes.SHA256())
    for chunk in chunks:
        digest.update(chunk)
    return digest.finalize()
