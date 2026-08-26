"""
RSA hash-and-sign (PKCS#1 v1.5 + SHA-256), lo schema di firma che usa
tutto il documento (§2.2.2, slide 05_Public_Key). Lo usano l'IdP per i
token, il Ballot Server per ricevute e teste del BB, i commissari per
manifest e attestati — tutti richiamano queste due funzioni.
"""
from __future__ import annotations

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey, RSAPublicKey


def sign(private_key: RSAPrivateKey, message: bytes) -> bytes:
    """σ = Sign_sk(message): RSA hash-and-sign con SHA-256."""
    return private_key.sign(message, padding.PKCS1v15(), hashes.SHA256())


def verify(public_key: RSAPublicKey, message: bytes, signature: bytes) -> bool:
    """Verifica di una firma RSA hash-and-sign; non solleva mai, restituisce bool."""
    try:
        public_key.verify(signature, message, padding.PKCS1v15(), hashes.SHA256())
        return True
    except InvalidSignature:
        return False
