"""
Client dell'elettore — §2.5.2 (generazione locale della coppia di
chiavi) e §2.6 (espressione del voto).

Il client è honest-by-assumption (§2.3, F.6), purtroppo non possiamo gestire la situazione
in cui l'utente vende il proprio voto quidni compromesso (§3.7).

Non fa nulla di rete: le funzioni prendono in input ciò che
normalmente arriverebbe da IdP/BS (head_ref, token) e restituiscono un
oggetto pronto per essere "inviato" — la spedizione stessa è simulata
nei demo/test con una chiamata diretta a `BallotServer.submit_ballot`.
"""
from __future__ import annotations

from dataclasses import dataclass

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey, RSAPublicKey

from src.common.ballot_encoding import VOTE_NO, VOTE_YES, pack_ballot_plaintext
from src.common.hashing import sha256
from src.common.keys import generate_rsa_keypair
from src.common.signing import sign
from src.idp.identity_provider import IssuedToken

_OAEP_PADDING = padding.OAEP(
    mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None
)


@dataclass(frozen=True)
class Ballot:
    """M_vote (§2.6, passo 6): tutto ciò che il Ballot Server riceve per una scheda."""

    token_id: bytes
    token_signature: bytes  # σ_token
    voter_public_key: RSAPublicKey
    ciphertext: bytes  # C
    head_ref: bytes
    voter_signature: bytes  # σ_voter


def generate_voter_keypair() -> RSAPrivateKey:
    """(pk_voter, sk_voter) ← Gen(1^n): coppia ad hoc per questa sola
    elezione (§2.5.2), mai persistita né riusata (forward unlinkability
    fra elezioni)."""
    return generate_rsa_keypair()


def encode_vote(prefer_yes: bool) -> bytes:
    """v ∈ {YES, NO} nella codifica canonica a lunghezza fissa (§2.2.1)."""
    return VOTE_YES if prefer_yes else VOTE_NO


def encrypt_ballot(bs_encryption_public_key: RSAPublicKey, election_id: str, head_ref: bytes, vote: bytes) -> bytes:
    """C = Enc^OAEP_pkBS(election_id ∥ head_ref ∥ vote_plain; r_enc)
    (§2.6, passo 4). La randomness r_enc è generata internamente da
    `cryptography` ad ogni chiamata e non è mai esposta qui: comodo per
    la segretezza, ma rende impossibile riprodurre con questa API la
    vendita del voto via ritenzione di r_enc descritta in T.3 — un
    limite del prototipo, non una mitigazione aggiuntiva intenzionale."""
    plaintext = pack_ballot_plaintext(election_id, head_ref, vote)
    return bs_encryption_public_key.encrypt(plaintext, _OAEP_PADDING)


def sign_ballot(voter_private_key: RSAPrivateKey, ciphertext: bytes, token_id: bytes, head_ref: bytes) -> bytes:
    """σ_voter = Sign_skvoter(H(C ∥ token_id ∥ head_ref)) (§2.2.2, §2.6 passo 5)."""
    digest = sha256(ciphertext, token_id, head_ref)
    return sign(voter_private_key, digest)


def cast_vote(
    token: IssuedToken,
    voter_private_key: RSAPrivateKey,
    bs_encryption_public_key: RSAPublicKey,
    election_id: str,
    head_ref: bytes,
    prefer_yes: bool,
) -> Ballot:
    """Passi 1-6 di §2.6: dalla preferenza al pacchetto M_vote pronto
    per il Ballot Server. `token` è quanto restituito da
    `IdentityProvider.issue_token` in Fase 1; `voter_private_key` deve
    essere la chiave la cui pubblica è già in `token.voter_public_key`,
    altrimenti il BS rifiuterà σ_token al passo 2 di §2.7."""
    vote = encode_vote(prefer_yes)
    ciphertext = encrypt_ballot(bs_encryption_public_key, election_id, head_ref, vote)
    voter_signature = sign_ballot(voter_private_key, ciphertext, token.token_id, head_ref)
    return Ballot(
        token_id=token.token_id,
        token_signature=token.signature,
        voter_public_key=voter_private_key.public_key(),
        ciphertext=ciphertext,
        head_ref=head_ref,
        voter_signature=voter_signature,
    )
