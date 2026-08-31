"""
Schema di secret sharing di Shamir su Z_p (§2.2.3, §2.4.1): la chiave
privata di decifratura sk_BS non esiste mai per intero se non nelle due
finestre di cerimonia (generazione, ricostruzione, §2.2.4/§2.8.1) — il
resto del tempo esistono solo le n = 5 share, di cui ne bastano t = 3
per ricostruire.

Perché si condivide l'esponente d e non i fattori (p, q) del modulo N:
la spiegazione è nel documento (§2.2.3) — condividere modulo φ(N) non è
praticabile né matematicamente né in termini di sicurezza; va condiviso
l'intero d su un campo Z_p con p primo pubblico maggiore di d.

Come si ottiene p: invece di reimplementare Miller-Rabin in Python puro
(una prova con `dh.generate_parameters` per un primo "safe" di ~2100
bit ha impiegato quasi due minuti — troppo anche per un test), si
sfrutta la generazione di chiavi RSA della libreria `cryptography`
(backend OpenSSL, sotto il secondo anche per moduli grandi): si genera
una chiave RSA usa-e-getta da 6144 bit e si preleva uno dei due fattori
primi, ciascuno garantito primo da OpenSSL e lungo 3072 bit — ben sopra
i 2048 bit di qualunque `d` di una chiave elettorale, che per
costruzione è minore del modulo N (anch'esso a 2048 bit, §2.2.1). La
chiave RSA generata per l'occasione non serve ad altro e viene scartata
subito dopo.
"""
from __future__ import annotations

import secrets
from dataclasses import dataclass
from functools import lru_cache
from typing import Sequence

from cryptography.hazmat.primitives.asymmetric import rsa

SHAMIR_THRESHOLD = 3   # t, §2.2.3
SHAMIR_TOTAL_SHARES = 5   # n, §2.2.3
_PRIME_SOURCE_KEY_SIZE_BITS = 6144  # -> fattori primi da 3072 bit, pubblico dell'elezione


@lru_cache(maxsize=1)
def shamir_prime() -> int:
    """p pubblico, primo, > 2048 bit — garantito maggiore di qualunque
    esponente privato `d` di una chiave RSA-2048 (§2.2.3). Calcolato una
    sola volta e cache-ato: è un parametro pubblico dell'elezione
    (pubblicato nel manifest, §2.4.3), non un segreto."""
    throwaway_key = rsa.generate_private_key(public_exponent=65537, key_size=_PRIME_SOURCE_KEY_SIZE_BITS)
    return throwaway_key.private_numbers().p


@dataclass(frozen=True)
class Share:
    """Una quota S_i = g(i) del segreto, i in [1, n] (§2.2.3). L'indice
    identifica il commissario che la detiene."""

    index: int
    value: int


def split_secret(
    secret: int,
    threshold: int = SHAMIR_THRESHOLD,
    total_shares: int = SHAMIR_TOTAL_SHARES,
    prime: int | None = None,
) -> tuple[Share, ...]:
    """Share_{t,n}(secret): genera coefficienti casuali a_1..a_{t-1} e
    valuta g(x) = secret + a_1*x + ... + a_{t-1}*x^{t-1} mod p in
    x = 1, ..., n (§2.2.3: per (3,5) il polinomio ha grado t-1=2, qui
    generalizzato a t/n arbitrari — il progetto usa sempre (3,5))."""
    prime = prime if prime is not None else shamir_prime()
    if not (0 <= secret < prime):
        raise ValueError("il segreto deve essere in [0, p)")
    if threshold < 1 or total_shares < threshold:
        raise ValueError("serve 1 <= threshold <= total_shares")

    coefficients = [secret] + [secrets.randbelow(prime) for _ in range(threshold - 1)]

    def evaluate(x: int) -> int:
        result = 0
        for coefficient in reversed(coefficients):
            result = (result * x + coefficient) % prime
        return result

    return tuple(Share(index=i, value=evaluate(i)) for i in range(1, total_shares + 1))


def reconstruct_secret(shares: Sequence[Share], prime: int | None = None) -> int:
    """Recon({s_j1, ..., s_jt}) -> secret, via interpolazione di
    Lagrange su Z_p valutata in x=0 (§2.8.1, passo 2).

    Con meno share del necessario non solleva un errore: restituisce un
    valore qualunque, sbagliato — è la proprietà stessa dello schema di
    Shamir (nessuna informazione trapela sotto soglia), non un bug qui.
    """
    prime = prime if prime is not None else shamir_prime()
    if len(shares) == 0:
        raise ValueError("serve almeno una share per ricostruire")
    if len({share.index for share in shares}) != len(shares):
        raise ValueError("indici di share duplicati")

    secret = 0
    for j, share_j in enumerate(shares):
        numerator, denominator = 1, 1
        for m, share_m in enumerate(shares):
            if m == j:
                continue
            numerator = (numerator * (-share_m.index)) % prime
            denominator = (denominator * (share_j.index - share_m.index)) % prime
        lagrange_coefficient = (numerator * pow(denominator, -1, prime)) % prime
        secret = (secret + share_j.value * lagrange_coefficient) % prime
    return secret
