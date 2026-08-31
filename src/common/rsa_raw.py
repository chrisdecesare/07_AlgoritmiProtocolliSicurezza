"""
RSA-OAEP a modulo/esponente noti (N, d), senza passare da un oggetto
RSAPrivateKey di `cryptography` — che richiederebbe anche i fattori
primi (p, q), mai ricostruiti in questo protocollo: si condivide e
ricostruisce solo l'esponente privato d (§2.2.3, §2.8.1), non la
fattorizzazione di N. Serve alla Commissione per decifrare le schede
con la sola d ricostruita via Shamir (§2.8.2).

Implementa RFC 8017 (PKCS#1 v2.2), §7.1.2 (RSAES-OAEP-DECRYPT) e
Appendice B.2.1 (MGF1), con SHA-256 sia come hash interno sia come hash
della mask generation function e label vuota — esattamente i parametri
che `cryptography` usa cifrando con
`padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None)`,
quindi un ciphertext prodotto da quella chiamata (lato client, §2.6) è
decifrabile qui con la sola coppia (N, d).
"""
from __future__ import annotations

import hmac

from src.common.hashing import sha256

HASH_LENGTH_BYTES = 32  # SHA-256


class OaepDecodingError(Exception):
    """Decifratura o padding OAEP non validi: chiave sbagliata (d non
    ricostruita correttamente) e ciphertext manomesso producono lo
    stesso errore, di proposito — un messaggio più preciso aprirebbe un
    oracolo di padding (Manger's attack)."""


def _mgf1(seed: bytes, mask_length: int) -> bytes:
    """MGF1 con SHA-256 (RFC 8017, Appendice B.2.1)."""
    output = bytearray()
    counter = 0
    while len(output) < mask_length:
        output.extend(sha256(seed, counter.to_bytes(4, "big")))
        counter += 1
    return bytes(output[:mask_length])


def _xor_bytes(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))


def raw_rsa_oaep_decrypt(ciphertext: bytes, modulus_n: int, exponent_d: int) -> bytes:
    """RSADP + EME-OAEP-DECODE (RFC 8017 §7.1.2), label vuota."""
    modulus_byte_length = (modulus_n.bit_length() + 7) // 8
    if len(ciphertext) != modulus_byte_length:
        raise OaepDecodingError("lunghezza del ciphertext incoerente con il modulo")
    if modulus_byte_length < 2 * HASH_LENGTH_BYTES + 2:
        raise OaepDecodingError("modulo troppo piccolo per OAEP con SHA-256")

    ciphertext_int = int.from_bytes(ciphertext, "big")
    if ciphertext_int >= modulus_n:
        raise OaepDecodingError("ciphertext non valido: >= modulo")

    message_int = pow(ciphertext_int, exponent_d, modulus_n)
    encoded_message = message_int.to_bytes(modulus_byte_length, "big")

    label_hash = sha256(b"")
    masked_seed = encoded_message[1 : 1 + HASH_LENGTH_BYTES]
    masked_data_block = encoded_message[1 + HASH_LENGTH_BYTES :]

    seed_mask = _mgf1(masked_data_block, HASH_LENGTH_BYTES)
    seed = _xor_bytes(masked_seed, seed_mask)
    data_block_mask = _mgf1(seed, modulus_byte_length - HASH_LENGTH_BYTES - 1)
    data_block = _xor_bytes(masked_data_block, data_block_mask)

    found_label_hash = data_block[:HASH_LENGTH_BYTES]
    rest = data_block[HASH_LENGTH_BYTES:]
    separator_index = rest.find(b"\x01")

    # I quattro controlli sono valutati tutti, sempre, prima di combinarli:
    # un `and` a corto circuito interromperebbe prima i ciphertext che
    # falliscono subito (es. leading byte sbagliato) rispetto a quelli che
    # falliscono solo sull'ultimo controllo, riaprendo lato timing lo
    # stesso oracolo di padding che il messaggio di errore generico voleva
    # evitare (Manger's attack). Il confronto dell'hash del label usa
    # `hmac.compare_digest`, non `==`, per lo stesso motivo.
    # Residuo non eliminato: la scansione del separatore (`rest.find` e lo
    # slice fino a `separator_index`) resta a tempo variabile in funzione
    # di dove si trova lo 0x01 — un decode davvero costante richiederebbe
    # una scansione byte-a-byte con maschere bit a bit, fuori scopo per
    # questo prototipo.
    leading_byte_ok = encoded_message[0] == 0
    label_hash_ok = hmac.compare_digest(found_label_hash, label_hash)
    separator_found = separator_index != -1
    padding_all_zero = all(b == 0 for b in rest[: separator_index if separator_found else 0])

    if not (leading_byte_ok & label_hash_ok & separator_found & padding_all_zero):
        raise OaepDecodingError("padding OAEP non valido")

    return rest[separator_index + 1 :]
