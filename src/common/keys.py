"""
Helper di generazione chiavi RSA condiviso da tutti gli attori del sistema.

Parametri fissati a modulo 2048 bit / e=65537, coerentemente con la scelta
adottata in 07_APS_1 §2.5.2 per le chiavi dell'elettore, ed estesa qui a
tutti gli attori per uniformità del prototipo (non è una prescrizione del
documento per CA/IdP/BS, ma una scelta di coerenza interna del prototipo,
motivata nella relazione).
"""
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey

RSA_PUBLIC_EXPONENT = 65537
RSA_KEY_SIZE_BITS = 2048


def generate_rsa_keypair() -> RSAPrivateKey:
    """Genera una nuova coppia di chiavi RSA (privata, pubblica derivabile)."""
    return rsa.generate_private_key(
        public_exponent=RSA_PUBLIC_EXPONENT,
        key_size=RSA_KEY_SIZE_BITS,
    )
