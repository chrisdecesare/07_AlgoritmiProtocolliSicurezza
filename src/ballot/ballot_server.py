"""
Ballot Server — Fase 2 del protocollo (§2.6-§2.7) più la parte BS della
chiusura urne (§2.8, passi 1, 4-5).

Riceve M_vote, esegue i controlli di §2.7 in ordine fermandosi al primo
fallimento (finestra temporale, validità del token, unicità, integrità
del pacchetto, coerenza della testa), poi accoda sul Bulletin Board e
restituisce una ricevuta firmata. Non conosce mai la matricola
dell'elettore (separazione IdP/BS, §2.3) — solo pk_voter e token_id,
che da soli non rivelano l'identità reale.

Sulla "coerenza della testa" (§2.7, passo 5): il documento lascia la
finestra di tolleranza come parametro dichiarato nel manifest, non
derivabile analiticamente. Qui la implemento come una finestra di teste
"recenti" di dimensione fissa (`HEAD_REFERENCE_TOLERANCE`): head_ref è
accettato se compare fra le ultime N teste emesse, non solo l'ultima —
altrimenti due elettori che leggono head_ref quasi in contemporanea e
inviano schede in ordine diverso da come le hanno lette si
bloccherebbero a vicenda per un semplice interleaving, non per un
attacco.
"""
from __future__ import annotations

from collections import deque
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Callable

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey, RSAPublicKey

from src.bulletin_board.bulletin_board import BulletinBoard
from src.common.hashing import sha256
from src.common.signing import sign, verify
from src.idp.identity_provider import IssuedToken, verify_token_as_ballot_server
from src.voter.client import Ballot

HEAD_REFERENCE_TOLERANCE = 5  # teste "recenti" ancora accettate come head_ref (§2.7, passo 5)


class VotingClosedError(Exception):
    """L'elezione non è (più, o ancora) aperta (§2.7, passo 1)."""


class InvalidTokenError(Exception):
    """σ_token non valida rispetto a pkIdP/PKI (§2.7, passo 2)."""


class DuplicateBallotError(Exception):
    """token_id già presente nella tabella Used (§2.7, passo 3; I.2)."""


class InvalidBallotSignatureError(Exception):
    """σ_voter non valida rispetto a pk_voter (§2.7, passo 4; I.3)."""


class StaleHeadReferenceError(Exception):
    """head_ref non fra le teste recenti accettate (§2.7, passo 5)."""


@dataclass(frozen=True)
class Receipt:
    """receipt_i = Sign_skBS-srv(H(C ∥ IDseq)) (§2.7, passo 8)."""

    id_seq: int
    head: bytes
    signature: bytes

    def signed_payload(self, ciphertext: bytes) -> bytes:
        return sha256(ciphertext, self.id_seq.to_bytes(8, "big"))


@dataclass(frozen=True)
class SignedHeadSnapshot:
    """(head_k, σhead,k) pubblicati periodicamente (§2.7.1) per rendere
    verificabile l'append-only a chi archivia; la stessa struttura serve
    per la testa finale di §2.8, passi 4-5."""

    index: int
    head: bytes
    timestamp: datetime
    signature: bytes

    def signed_payload(self) -> bytes:
        return sha256(self.index.to_bytes(8, "big", signed=True), self.head, self.timestamp.isoformat().encode())


def _default_clock() -> datetime:
    return datetime.now(timezone.utc)


class BallotServer:
    def __init__(
        self,
        election_id: str,
        genesis_head: bytes,
        signing_key: RSAPrivateKey,
        signing_public_key: RSAPublicKey,
        idp_certificate: x509.Certificate,
        ca_certificate: x509.Certificate,
        voting_opens_at: datetime,
        voting_closes_at: datetime,
        crl: x509.CertificateRevocationList | None = None,
        clock: Callable[[], datetime] = _default_clock,
    ):
        self._election_id = election_id
        self._signing_key = signing_key
        self._signing_public_key = signing_public_key
        self._idp_certificate = idp_certificate
        self._ca_certificate = ca_certificate
        self._crl = crl
        self._voting_opens_at = voting_opens_at
        self._voting_closes_at = voting_closes_at
        self._clock = clock

        self._bulletin_board = BulletinBoard(genesis_head)
        self._used_tokens: set[bytes] = set()
        self._recent_heads: deque[bytes] = deque([genesis_head], maxlen=HEAD_REFERENCE_TOLERANCE)
        self._closed = False

    @property
    def signing_public_key(self) -> RSAPublicKey:
        return self._signing_public_key

    @property
    def bulletin_board(self) -> BulletinBoard:
        """Lettura pubblica (§2.3: "leggibile da tutti"); la scrittura
        passa solo da `submit_ballot`."""
        return self._bulletin_board

    def current_head_reference(self) -> bytes:
        """head_ref che un elettore dovrebbe leggere ora (§2.6, passo 3)."""
        return self._bulletin_board.current_head

    def submit_ballot(self, ballot: Ballot) -> Receipt:
        """I passi 1-8 di §2.7, in ordine, fermandosi al primo fallimento."""
        now = self._clock()

        # Passo 1 — finestra temporale.
        if self._closed or not (self._voting_opens_at <= now <= self._voting_closes_at):
            raise VotingClosedError(f"le urne non sono aperte all'istante {now.isoformat()}")

        # Passo 2 — validità del token: parte dal certificato dell'IdP,
        # non da una pkIdP di cui fidarsi sulla parola (§2.4.2).
        token = IssuedToken(
            token_id=ballot.token_id, signature=ballot.token_signature, voter_public_key=ballot.voter_public_key
        )
        if not verify_token_as_ballot_server(token, self._idp_certificate, self._ca_certificate, self._crl, now):
            raise InvalidTokenError("σ_token non valida, o certificato IdP non valido/scaduto/revocato")

        # Passo 3 — unicità: anti-replay su token_id (I.2).
        if ballot.token_id in self._used_tokens:
            raise DuplicateBallotError(f"token_id {ballot.token_id.hex()} già usato")

        # Passo 4 — integrità del pacchetto: σ_voter su H(C ∥ token_id ∥ head_ref).
        digest = sha256(ballot.ciphertext, ballot.token_id, ballot.head_ref)
        if not verify(ballot.voter_public_key, digest, ballot.voter_signature):
            raise InvalidBallotSignatureError("σ_voter non valida rispetto a pk_voter")

        # Passo 5 — coerenza della testa: head_ref dev'essere una testa
        # effettivamente pubblicata di recente.
        if ballot.head_ref not in self._recent_heads:
            raise StaleHeadReferenceError(
                "head_ref non è fra le teste recenti del Bulletin Board: rileggerla e ripetere l'invio"
            )

        # Passi 6-7 — append: nuova testa, tabella Used, entry sul BB.
        entry = self._bulletin_board.append(
            ciphertext=ballot.ciphertext,
            voter_public_key=ballot.voter_public_key,
            token_id=ballot.token_id,
            token_signature=ballot.token_signature,
            head_ref=ballot.head_ref,
            voter_signature=ballot.voter_signature,
        )
        self._used_tokens.add(ballot.token_id)
        self._recent_heads.append(entry.head)

        # Passo 8 — ricevuta.
        signature = sign(self._signing_key, sha256(ballot.ciphertext, entry.id_seq.to_bytes(8, "big")))
        return Receipt(id_seq=entry.id_seq, head=entry.head, signature=signature)

    def publish_signed_head(self, index: int) -> SignedHeadSnapshot:
        """(head_k, σhead,k) di §2.7.1: pubblicazione periodica per
        l'archiviazione indipendente da parte degli osservatori."""
        timestamp = self._clock()
        head = self._bulletin_board.current_head
        payload = sha256(index.to_bytes(8, "big", signed=True), head, timestamp.isoformat().encode())
        signature = sign(self._signing_key, payload)
        return SignedHeadSnapshot(index=index, head=head, timestamp=timestamp, signature=signature)

    def close_voting(self, final_index: int) -> SignedHeadSnapshot:
        """§2.8, passi 1, 4-5: smette di accettare schede e firma la
        testa finale head_final, immutabile da questo momento in poi."""
        if self._closed:
            raise VotingClosedError("le urne sono già chiuse")
        self._closed = True
        return self.publish_signed_head(index=final_index)


def verify_receipt(receipt: Receipt, bs_signing_public_key: RSAPublicKey, ciphertext: bytes) -> bool:
    """Verifica V.1 (§3.5.1, punti 3-4): chiunque abbia la ricevuta e il
    proprio ciphertext può controllarla con la sola pk_BS-srv pubblica."""
    return verify(bs_signing_public_key, receipt.signed_payload(ciphertext), receipt.signature)


def verify_signed_head(snapshot: SignedHeadSnapshot, bs_signing_public_key: RSAPublicKey) -> bool:
    """Verifica di una testa periodica (o finale) archiviata da un
    osservatore indipendente (§2.7.1, §2.8)."""
    return verify(bs_signing_public_key, snapshot.signed_payload(), snapshot.signature)
