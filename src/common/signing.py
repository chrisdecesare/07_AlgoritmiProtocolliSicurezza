"""
RSA hash-and-sign (PKCS#1 v1.5 + SHA-256), lo schema di firma che usa
tutto il documento (§2.2.2, slide 05_Public_Key). Lo usano l'IdP per i
token, il Ballot Server per ricevute e teste del BB, i commissari per
manifest e attestati — tutti richiamano queste due funzioni.

Ogni chiamante passa già un digest SHA-256 pre-calcolato con
`common.hashing.sha256(...)` (è così che il documento scrive le firme,
es. σ_token = Sign_skIdP(H(token_id ∥ pk_voter))): il parametro
`digest` qui sotto è quel valore, non il messaggio in chiaro. Per
questo si usa `utils.Prehashed(hashes.SHA256())` invece di
`hashes.SHA256()` — altrimenti `cryptography` hasherebbe di nuovo il
digest già calcolato, producendo silenziosamente una firma su
SHA256(SHA256(...)) invece che su SHA256(...).
"""
from __future__ import annotations

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, utils
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey, RSAPublicKey

_ALGORITHM = utils.Prehashed(hashes.SHA256())


def sign(private_key: RSAPrivateKey, digest: bytes) -> bytes:
    """σ = Sign_sk(digest): RSA hash-and-sign su un digest SHA-256 già calcolato."""
    return private_key.sign(digest, padding.PKCS1v15(), _ALGORITHM)


def verify(public_key: RSAPublicKey, digest: bytes, signature: bytes) -> bool:
    """Verifica di una firma RSA hash-and-sign; non solleva mai, restituisce bool."""
    try:
        public_key.verify(signature, digest, padding.PKCS1v15(), _ALGORITHM)
        return True
    except InvalidSignature:
        return False
