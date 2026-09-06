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
    oracolo di padding."""


def _mgf1(seed: bytes, mask_length: int) -> bytes:
    """MGF1 con SHA-256 """
    output = bytearray()
    counter = 0
    while len(output) < mask_length:
        output.extend(sha256(seed, counter.to_bytes(4, "big")))
        counter += 1
    return bytes(output[:mask_length])


def _xor_bytes(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))


def raw_rsa_oaep_decrypt(ciphertext: bytes, modulus_n: int, exponent_d: int) -> bytes:
    # Per OAEP, il ciphertext deve avere esattamente questa lunghezza.
    modulus_byte_length = (modulus_n.bit_length() + 7) // 8

    # Un ciphertext RSA-OAEP deve avere la stessa lunghezza, in byte, del modulo RSA.
    if len(ciphertext) != modulus_byte_length:
        raise OaepDecodingError("lunghezza del ciphertext incoerente con il modulo")

    # Con SHA-256 OAEP richiede almeno:
    #   1 byte iniziale + 2 * 32 byte di hash + 1 byte separatore.
    # Se il modulo è più piccolo, non c'è spazio sufficiente per il formato OAEP. Infatti mi dava errore prima
    if modulus_byte_length < 2 * HASH_LENGTH_BYTES + 2:
        raise OaepDecodingError("modulo troppo piccolo per OAEP con SHA-256")

    # Interpreta il ciphertext come un intero per poter applicare
    # l'operazione RSA di decifratura: c^d mod n.
    ciphertext_int = int.from_bytes(ciphertext, "big")

    # deve rappresentare un intero compreso
    # nell'intervallo [0, n-1]. Un valore >= n non è un elemento valido
    # del modulo RSA.
    if ciphertext_int >= modulus_n:
        raise OaepDecodingError("ciphertext non valido: >= modulo")

    # Esegue la decifratura RSA "raw", senza ancora rimuovere il padding OAEP.
    # Il risultato è l'intero rappresentato dal DATI CODIFICATI
    # m + PADDING
    message_int = pow(ciphertext_int, exponent_d, modulus_n)

    # Converte il risultato RSA in esattamente k byte, dove k è la lunghezza
    # del modulo. Gli eventuali zeri iniziali devono essere preservati perché
    # fanno parte della struttura OAEP.
    encoded_message = message_int.to_bytes(modulus_byte_length, "big")

    # OAEP usa come hash della label la SHA-256 della label vuota.
    # In questo caso la label non è stata fornita, quindi viene usata b"".
    label_hash = sha256(b"")




    #STRUTTURA del blocco OAEP che tiene la maschera quindi
    #DATI = 0x00 || maskedSeed || masked DB
    # maskedSeed ha la lunghezza dell'hash (32 byte
    masked_seed = encoded_message[1: 1 + HASH_LENGTH_BYTES]
    # Tutti i byte rimanenti dopo maskedSeed costituiscono maskedDB.
    masked_data_block = encoded_message[1 + HASH_LENGTH_BYTES:]


    #devo ricavare il maskedSeed e quindi uso mgf1 che avevamo scritto
    seed_mask = _mgf1(masked_data_block, HASH_LENGTH_BYTES)


    # il modo per avere il seed non mascherato è con una XOR
    # seed = maskedSee XOR seedMask
    seed = _xor_bytes(masked_seed, seed_mask)

    # Genera la maschera necessaria per recuperare il data block.
    # La lunghezza del data block è k - hLen - 1.
    data_block_mask = _mgf1(seed, modulus_byte_length - HASH_LENGTH_BYTES - 1)

    # Genera la maschera necessaria per recuperare il data block.
    # La lunghezza del data block è k - hLen - 1.
    data_block = _xor_bytes(masked_data_block, data_block_mask)




    # Il data block OAEP ha questa struttura:
    #
    #   DB = lHash || PS || 0x01 || M
    #
    # dove:
    #   lHash = hash della label
    #   PS    = sequenza di byte 0x00
    #   0x01  = separatore
    #   M     = messaggio originale
    #
    # Estrae quindi i primi HASH_LENGTH_BYTES che devono contenere l'hash
    # della label.
    found_label_hash = data_block[:HASH_LENGTH_BYTES]

    #il resto è tutto padding con un separatore 0x01 e poi il messaggio alla fine
    rest = data_block[HASH_LENGTH_BYTES:]

    # voglio trovare il primo byte 0x01 e prima di esso c'è un byte 0x00
    separator_index = rest.find(b"\x01")
    # Esegue i quattro controlli di validità del padding OAEP.
    #
    # Non viene usato `and` perché `and` in Python è short-circuit:
    # se il primo controllo fallisse, i successivi non verrebbero valutati.
    # Valutare tutti i controlli evita di introdurre una differenza di timing
    # facilmente osservabile tra diversi tipi di ciphertext non validi.
    #
    # 1. Il primo byte dell'Encoded Message deve essere 0x00.
    leading_byte_ok = encoded_message[0] == 0

    # 2. L'hash della label estratto dal ciphertext deve coincidere con
    #    SHA-256 della label attesa. compare_digest evita il confronto
    #    non constant-time tipico di `==`.
    label_hash_ok = hmac.compare_digest(found_label_hash, label_hash)

    # 3. Deve esistere il separatore 0x01 che delimita il padding dal messaggio.
    separator_found = separator_index != -1

    # 4. Tutti i byte compresi tra l'inizio di `rest` e il separatore
    #    devono essere 0x00. Se il separatore non è stato trovato,
    #    il controllo viene eseguito su una sequenza vuota e fallirà
    #    comunque grazie a `separator_found`.
    padding_all_zero = all(
        b == 0
        for b in rest[: separator_index if separator_found else 0]
    )

    # Tutti i controlli devono essere contemporaneamente validi.
    # L'operatore bitwise `&` forza la valutazione di tutte le condizioni,
    # evitando lo short-circuit dell'operatore logico `and`.
    #
    # Se anche un solo controllo fallisce, il ciphertext viene rifiutato
    # con un errore generico, senza distinguere quale parte del padding
    # OAEP fosse errata.
    if not (leading_byte_ok & label_hash_ok & separator_found & padding_all_zero):
        raise OaepDecodingError("padding OAEP non valido")

    # Il separatore 0x01 non fa parte del messaggio.
    # Restituisce quindi tutto ciò che viene dopo il separatore:
    #
    #   DB = lHash || PS || 0x01 || M
    #                    ^       ^
    #                    |       +-- inizio del messaggio
    #                    +---------- separatore da scartare
    return rest[separator_index + 1:]
