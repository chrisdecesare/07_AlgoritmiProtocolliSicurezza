"""
Test della decifratura RSA-OAEP a (N, d) noti (§2.8.2), usata dalla
Commissione dopo la ricostruzione di Shamir — qui isolata da Shamir,
contro chiavi RSA generate normalmente.
"""
import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding

from src.common.keys import generate_rsa_keypair
from src.common.rsa_raw import OaepDecodingError, raw_rsa_oaep_decrypt

_OAEP = padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None)


def _n_d(private_key):
    numbers = private_key.private_numbers()
    return numbers.public_numbers.n, numbers.d


def test_round_trip_matches_cryptography_encrypt():
    key = generate_rsa_keypair()
    n, d = _n_d(key)
    for message in (b"hello world", b"\x00\x01YES", b"x" * 190):
        ciphertext = key.public_key().encrypt(message, _OAEP)
        assert raw_rsa_oaep_decrypt(ciphertext, n, d) == message


def test_tampered_ciphertext_is_rejected():
    key = generate_rsa_keypair()
    n, d = _n_d(key)
    ciphertext = bytearray(key.public_key().encrypt(b"secret vote", _OAEP))
    ciphertext[10] ^= 0xFF
    with pytest.raises(OaepDecodingError):
        raw_rsa_oaep_decrypt(bytes(ciphertext), n, d)


def test_wrong_exponent_is_rejected():
    """Simula una `d` ricostruita male (es. share insufficienti): non deve decodificare per sbaglio."""
    key = generate_rsa_keypair()
    n, d = _n_d(key)
    ciphertext = key.public_key().encrypt(b"secret vote", _OAEP)
    with pytest.raises(OaepDecodingError):
        raw_rsa_oaep_decrypt(ciphertext, n, d + 2)


def test_wrong_ciphertext_length_is_rejected():
    key = generate_rsa_keypair()
    n, d = _n_d(key)
    with pytest.raises(OaepDecodingError):
        raw_rsa_oaep_decrypt(b"\x00" * 10, n, d)
