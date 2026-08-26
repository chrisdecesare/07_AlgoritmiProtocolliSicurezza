"""
Generazione chiavi RSA condivisa da tutti gli attori.

Modulo 2048 / e=65537: il documento lo richiede solo per le chiavi
dell'elettore (§2.5.2), l'ho esteso a tutti per non avere due convenzioni
diverse in giro per il prototipo.
"""
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey, RSAPublicKey

RSA_PUBLIC_EXPONENT = 65537
RSA_KEY_SIZE_BITS = 2048


def generate_rsa_keypair() -> RSAPrivateKey:
    """Genera una nuova coppia di chiavi RSA (privata, pubblica derivabile)."""
    return rsa.generate_private_key(
        public_exponent=RSA_PUBLIC_EXPONENT,
        key_size=RSA_KEY_SIZE_BITS,
    )


def public_key_der(public_key: RSAPublicKey) -> bytes:
    """Codifica DER (SubjectPublicKeyInfo): serve quando una chiave pubblica
    deve entrare come byte in un hash o una firma, es. H(token_id ∥ pk_voter)."""
    return public_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
