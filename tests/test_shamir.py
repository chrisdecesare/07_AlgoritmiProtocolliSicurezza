"""
Test dello schema di Shamir (3,5) su Z_p (§2.2.3, §2.8.1): ogni
combinazione di t=3 share ricostruisce lo stesso segreto; meno di t
share non trapelano nulla di utile.
"""
import itertools

import pytest

from src.commission.shamir import (
    SHAMIR_THRESHOLD,
    SHAMIR_TOTAL_SHARES,
    Share,
    reconstruct_secret,
    shamir_prime,
    split_secret,
)


def test_shamir_prime_is_public_and_large_enough():
    prime = shamir_prime()
    # deve superare comodamente i 2048 bit di qualunque d di una chiave elettorale RSA-2048
    assert prime.bit_length() > 2048
    assert prime % 2 == 1


def test_every_threshold_combination_reconstructs_the_secret():
    prime = shamir_prime()
    secret = 123456789012345678901234567890123456789 % prime
    shares = split_secret(secret, prime=prime)

    assert len(shares) == SHAMIR_TOTAL_SHARES
    for combo in itertools.combinations(shares, SHAMIR_THRESHOLD):
        assert reconstruct_secret(combo, prime) == secret


def test_below_threshold_does_not_reconstruct_the_secret():
    prime = shamir_prime()
    secret = 42
    shares = split_secret(secret, prime=prime)

    for combo in itertools.combinations(shares, SHAMIR_THRESHOLD - 1):
        assert reconstruct_secret(combo, prime) != secret


def test_larger_than_threshold_subsets_also_reconstruct():
    prime = shamir_prime()
    secret = 7
    shares = split_secret(secret, prime=prime)

    assert reconstruct_secret(shares, prime) == secret  # tutte e 5


def test_secret_out_of_range_is_rejected():
    prime = shamir_prime()
    with pytest.raises(ValueError):
        split_secret(prime, prime=prime)  # >= p, fuori da Z_p
    with pytest.raises(ValueError):
        split_secret(-1, prime=prime)


def test_duplicate_share_indices_are_rejected():
    prime = shamir_prime()
    duplicated = (Share(index=1, value=10), Share(index=1, value=20), Share(index=2, value=30))
    with pytest.raises(ValueError):
        reconstruct_secret(duplicated, prime)


def test_threshold_cannot_exceed_total_shares():
    with pytest.raises(ValueError):
        split_secret(1, threshold=6, total_shares=5, prime=shamir_prime())
