"""
Codifica canonica della scheda di voto (§2.2.1, §2.6): il plaintext OAEP
è election_id ∥ head_ref ∥ vote_plain, con vote_plain a lunghezza fissa
di un solo byte — niente canali laterali di lunghezza fra Sì e No
(§2.2.1: "spazio dei messaggi... codificato in forma canonica di
lunghezza fissa").

Il formato usa un prefisso di lunghezza per election_id (variabile, ma
nota) seguito da head_ref a lunghezza fissa (32 byte, un digest
SHA-256) e un singolo byte di voto — non un semplice ∥ fra i tre campi,
perché senza delimitatori a lunghezza nota il decoder della Commissione
(§2.8.2) non saprebbe dove finisce election_id e comincia head_ref.
"""
from __future__ import annotations

HEAD_REF_LENGTH_BYTES = 32  # digest SHA-256 della testa del BB

VOTE_YES = b"\x01"
VOTE_NO = b"\x00"
_VALID_VOTES = (VOTE_YES, VOTE_NO)


class BallotDecodingError(Exception):
    """Il plaintext decifrato non rispetta il formato canonico atteso (§2.6)."""


def pack_ballot_plaintext(election_id: str, head_ref: bytes, vote: bytes) -> bytes:
    """election_id ∥ head_ref ∥ vote_plain, pronto per RSA-OAEP (§2.6, passo 4)."""
    if vote not in _VALID_VOTES:
        raise ValueError(f"voto non valido: {vote!r}, atteso {VOTE_YES!r} o {VOTE_NO!r}")
    if len(head_ref) != HEAD_REF_LENGTH_BYTES:
        raise ValueError(f"head_ref deve essere lungo {HEAD_REF_LENGTH_BYTES} byte")

    election_id_bytes = election_id.encode("utf-8")
    if len(election_id_bytes) > 0xFFFF:
        raise ValueError("election_id troppo lungo per il prefisso a 2 byte")

    return len(election_id_bytes).to_bytes(2, "big") + election_id_bytes + head_ref + vote


def unpack_ballot_plaintext(plaintext: bytes) -> tuple[str, bytes, bytes]:
    """Inversa di `pack_ballot_plaintext`, usata dalla Commissione dopo
    la decifratura (§2.8.2, passo 1). Solleva `BallotDecodingError` se
    la struttura non torna: un plaintext OAEP valido ma non prodotto da
    questa codifica non deve mai passare silenziosamente come un voto."""
    try:
        election_id_length = int.from_bytes(plaintext[:2], "big")
        offset = 2
        election_id = plaintext[offset : offset + election_id_length].decode("utf-8")
        offset += election_id_length
        head_ref = plaintext[offset : offset + HEAD_REF_LENGTH_BYTES]
        offset += HEAD_REF_LENGTH_BYTES
        vote = plaintext[offset:]
    except UnicodeDecodeError as exc:
        raise BallotDecodingError(f"plaintext malformato: {exc}") from exc

    if len(head_ref) != HEAD_REF_LENGTH_BYTES or vote not in _VALID_VOTES:
        raise BallotDecodingError("plaintext non rispetta il formato canonico atteso")
    return election_id, head_ref, vote
