"""
Commissione di scrutinio — cerimonia di generazione/condivisione della
chiave di decifratura (§2.2.4, §2.4.1) e scrutinio a urne chiuse
(§2.8.1, §2.8.2).

La chiave sk_BS = (N, d) non esiste mai per intero in questo modulo se
non per la durata di una singola chiamata: `generate_and_share_decryption_key`
la genera, la condivide con Shamir e restituisce solo N e le share, mai
`d`; `run_scrutiny` ricostruisce `d` da >= t share solo dentro la
funzione, lo usa per decifrare e lo lascia uscire dallo scope subito
dopo (nessuna cache, nessun attributo di istanza che lo conservi) — è
il modo più diretto in Python di rappresentare "la chiave ricostruita
esiste in memoria volatile solo per il tempo strettamente necessario"
(§2.8.1, passo 3), senza un vero ambiente air-gapped a disposizione.
"""
from __future__ import annotations

import secrets
from dataclasses import dataclass
from typing import Sequence

from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey, RSAPublicKey

from src.bulletin_board.bulletin_board import BulletinBoardEntry
from src.commission.shamir import (
    SHAMIR_THRESHOLD,
    SHAMIR_TOTAL_SHARES,
    Share,
    reconstruct_secret,
    shamir_prime,
    split_secret,
)
from src.common.ballot_encoding import BallotDecodingError, unpack_ballot_plaintext
from src.common.hashing import sha256
from src.common.keys import RSA_KEY_SIZE_BITS, RSA_PUBLIC_EXPONENT, public_key_der
from src.common.rsa_raw import OaepDecodingError, raw_rsa_oaep_decrypt
from src.common.signing import sign, verify


@dataclass(frozen=True)
class ElectionDecryptionKey:
    """Output pubblico della cerimonia di setup (§2.4.1): pk_BS, il
    modulo N (serve alla Commissione per decifrare — non è segreto, è
    metà della chiave pubblica) e le n share. Mai `d`."""

    public_key: RSAPublicKey
    modulus_n: int
    prime: int
    shares: tuple[Share, ...]


def generate_and_share_decryption_key(
    threshold: int = SHAMIR_THRESHOLD, total_shares: int = SHAMIR_TOTAL_SHARES
) -> ElectionDecryptionKey:
    """Cerimonia di generazione (§2.2.4, §2.4.1): genera (pk_BS, sk_BS),
    condivide subito d con Shamir e non restituisce mai sk_BS né d in
    forma integra — solo `public_key`/`modulus_n`/`shares` escono dallo
    scope di questa funzione, la rappresentazione più fedele possibile
    in Python di "sk_BS in forma integra ... viene distrutta prima
    della fine della cerimonia" (passo 5 di §2.4.1) senza un vero
    dispositivo air-gapped."""
    private_key: RSAPrivateKey = rsa.generate_private_key(
        public_exponent=RSA_PUBLIC_EXPONENT, key_size=RSA_KEY_SIZE_BITS
    )
    prime = shamir_prime()
    private_numbers = private_key.private_numbers()
    shares = split_secret(private_numbers.d, threshold, total_shares, prime)
    return ElectionDecryptionKey(
        public_key=private_key.public_key(),
        modulus_n=private_numbers.public_numbers.n,
        prime=prime,
        shares=shares,
    )


def reconstruct_decryption_exponent(shares: Sequence[Share], prime: int) -> int:
    """Cerimonia di ricostruzione (§2.8.1, passi 1-2): interpolazione di
    Lagrange su Z_p. Con meno di t share il risultato è un valore
    qualunque e sbagliato, non un errore — proprietà stessa dello schema
    (sotto soglia, nessuna informazione trapela)."""
    return reconstruct_secret(shares, prime)


class TallyIntegrityError(Exception):
    """Un'entry del BB decifra a un plaintext incoerente col formato
    canonico o con l'election_id atteso (§2.8.2, passi 1-2)."""


@dataclass(frozen=True)
class TallyBundle:
    """tally_bundle di §2.8.2. Le firme dei commissari partecipanti sono
    tenute a parte (`sign_tally_bundle`/`verify_tally_bundle`) invece che
    incorporate qui, per poter contare quante e quali firme coprono lo
    stesso bundle senza doverlo ricostruire da zero."""

    election_id: str
    head_final: bytes
    total_decrypted: int
    decrypted_votes: tuple[bytes, ...]  # mescolata, NESSUN riferimento a IDseq o pk_voter
    tally: dict[bytes, int]  # {VOTE_YES: a, VOTE_NO: b}

    def signed_payload(self) -> bytes:
        votes_blob = b"".join(self.decrypted_votes)
        tally_blob = b",".join(f"{vote.hex()}:{count}".encode() for vote, count in sorted(self.tally.items()))
        return sha256(
            self.election_id.encode(),
            b"|",
            self.head_final,
            b"|",
            self.total_decrypted.to_bytes(8, "big"),
            b"|",
            votes_blob,
            b"|",
            tally_blob,
        )


def run_scrutiny(
    election_id: str,
    head_final: bytes,
    entries: Sequence[BulletinBoardEntry],
    reconstruction_shares: Sequence[Share],
    prime: int,
    modulus_n: int,
) -> TallyBundle:
    """§2.8.2: ricostruisce d, decifra ogni entry del BB in ordine di
    IDseq, controlla la coerenza (election_id, voto canonico), conta,
    mescola e restituisce il tally bundle. `d` esiste solo nello scope
    di questa funzione."""
    exponent_d = reconstruct_decryption_exponent(reconstruction_shares, prime)

    decrypted_votes: list[bytes] = []
    tally: dict[bytes, int] = {}
    for entry in sorted(entries, key=lambda e: e.id_seq):
        try:
            plaintext = raw_rsa_oaep_decrypt(entry.ciphertext, modulus_n, exponent_d)
            decoded_election_id, _head_ref, vote = unpack_ballot_plaintext(plaintext)
        except (OaepDecodingError, BallotDecodingError) as exc:
            raise TallyIntegrityError(
                f"entry {entry.id_seq}: scheda non decifrabile o non conforme al formato canonico ({exc})"
            ) from exc
        if decoded_election_id != election_id:
            raise TallyIntegrityError(
                f"entry {entry.id_seq}: election_id nel plaintext ({decoded_election_id!r}) non corrisponde"
            )

        decrypted_votes.append(vote)
        tally[vote] = tally.get(vote, 0) + 1

    shuffled_votes = list(decrypted_votes)
    secrets.SystemRandom().shuffle(shuffled_votes)  # §2.8.2: "la Commissione mescola L"

    return TallyBundle(
        election_id=election_id,
        head_final=head_final,
        total_decrypted=len(decrypted_votes),
        decrypted_votes=tuple(shuffled_votes),
        tally=tally,
    )


def sign_tally_bundle(bundle: TallyBundle, commissioner_signing_keys: Sequence[RSAPrivateKey]) -> tuple[bytes, ...]:
    """Firme persistenti dei commissari partecipanti su σ_tally (§2.8.2)."""
    payload = bundle.signed_payload()
    return tuple(sign(key, payload) for key in commissioner_signing_keys)


def verify_tally_bundle(
    bundle: TallyBundle,
    commissioner_public_keys: Sequence[RSAPublicKey],
    signatures: Sequence[bytes],
    threshold: int = SHAMIR_THRESHOLD,
) -> bool:
    """V.2 punto 8: almeno `threshold` firme valide di commissari
    DISTINTI sul bundle, fra le coppie (chiave, firma) fornite nello
    stesso ordine. La deduplicazione per chiave pubblica conta: senza,
    la stessa coppia (chiave, firma) ripetuta più volte nelle liste
    (es. da chi assembla le liste, non da un verificatore che le legge
    dal manifest già deduplicate) supererebbe la soglia con meno di
    `threshold` commissari realmente distinti — vanificando (3,5)."""
    payload = bundle.signed_payload()
    seen_keys: set[bytes] = set()
    valid_count = 0
    for public_key, signature in zip(commissioner_public_keys, signatures):
        fingerprint = public_key_der(public_key)
        if fingerprint in seen_keys:
            continue
        if verify(public_key, payload, signature):
            seen_keys.add(fingerprint)
            valid_count += 1
    return valid_count >= threshold
