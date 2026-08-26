"""
Identity Provider — Fase 1 del protocollo (§2.5) più la parte IdP della
chiusura urne (§2.8, passi 2-3).

In breve: l'IdP tiene (saltM, hpwd), manda una nonce fresca n1 e accetta
come risposta H(n1 ∥ hpwd) — challenge-response, §2.5.1. Dopo 3 fallimenti
di fila scatta un backoff esponenziale. Autenticato l'elettore, riceve
pk_voter, controlla che non abbia già un token per questa elezione (I.2),
genera token_id, firma σ_token = Sign_skIdP(H(token_id ∥ pk_voter)) e
registra tutto in Issued — mai esposta all'esterno (§3.3.2: "C.2 dipende
dal solo IdP"). A urne chiuse pubblica la lista firmata di chi ha
ricevuto un token (mitiga il ballot stuffing, T.6) e poi distrugge
Issued con una dichiarazione firmata.

Nota su hpwd: resta plaintext-equivalent per costruzione (§2.2.5) — non
è un bug, è il costo che il documento accetta per quello schema, e non
l'ho "corretto" di nascosto con qualcos'altro.

Due cose che questo modulo NON fa, apposta: non genera pk_voter/sk_voter
(tocca al client dell'elettore, l'IdP non deve mai vederle prima del
dovuto — §2.5.2); e non impedisce a un IdP disonesto di emettere token
per astenuti (ballot stuffing, T.6) — il documento lo dichiara rilevabile
solo a posteriori, non prevenibile dal codice di un IdP che ha già deciso
di barare.
"""
from __future__ import annotations

import os
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from hmac import compare_digest
from typing import Callable

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey, RSAPublicKey

from src.ca.root_ca import verify_certificate_with_crl
from src.common.hashing import sha256
from src.common.keys import public_key_der
from src.common.password_hash import generate_salt, hash_password
from src.common.signing import sign, verify

NONCE_LENGTH_BYTES = 16   # 128 bit, come n1 in §2.5.1
TOKEN_ID_LENGTH_BYTES = 16  # 128 bit, come token_id in §2.5.3
MAX_FAILED_ATTEMPTS = 3   # k=3, §2.5.1 "Tentativi e backoff"
BACKOFF_BASE_SECONDS = 2  # base della crescita esponenziale del blocco


class AuthenticationError(Exception):
    """Errore nel flusso di autenticazione (matricola ignota, sessione assente, credenziali errate)."""


class RateLimitedError(Exception):
    """La matricola è temporaneamente bloccata dopo troppi tentativi falliti (§2.5.1)."""


class TokenAlreadyIssuedError(Exception):
    """Violazione di I.2: un token è già stato emesso per questa matricola in questa elezione."""


class ElectionClosedError(Exception):
    """La tabella Issued è già stata distrutta (§2.8, passo 3): l'elezione è chiusa."""


@dataclass(frozen=True)
class _StudentRecord:
    matricola: str
    salt: bytes
    password_hash: bytes  # hpwd = H(password || salt)


@dataclass(frozen=True)
class _PendingChallenge:
    nonce: bytes  # n1


@dataclass(frozen=True)
class _IssuedRecord:
    """Una riga della tabella Issued (§2.5.3): mai esposta pubblicamente."""

    token_id: bytes
    voter_public_key: RSAPublicKey
    timestamp: datetime


@dataclass(frozen=True)
class IssuedToken:
    """(token_id, σ_token) restituiti all'elettore al termine di §2.5.3."""

    token_id: bytes
    signature: bytes
    voter_public_key: RSAPublicKey


@dataclass(frozen=True)
class SignedParticipantList:
    """Lista firmata delle matricole con token emesso (§2.8, passo 2)."""

    election_id: str
    matricole: tuple[str, ...]
    signature: bytes

    def signed_payload(self) -> bytes:
        return sha256(self.election_id.encode(), b"|", b",".join(m.encode() for m in self.matricole))


@dataclass(frozen=True)
class SignedDestructionStatement:
    """Dichiarazione firmata di avvenuta distruzione di Issued (§2.8, passo 3)."""

    timestamp: datetime
    signature: bytes

    def signed_payload(self) -> bytes:
        return sha256(f"Issued table destroyed at {self.timestamp.isoformat()}".encode())


def _default_clock() -> datetime:
    return datetime.now(timezone.utc)


class IdentityProvider:
    """
    IdP onesto: implementa §2.5 e la parte IdP di §2.8.

    `clock` è iniettabile così nei test posso simulare il passare del
    tempo per il backoff senza dover davvero aspettare secondi veri.
    """

    def __init__(
        self,
        election_id: str,
        signing_key: RSAPrivateKey,
        signing_public_key: RSAPublicKey,
        clock: Callable[[], datetime] = _default_clock,
    ):
        """`signing_key`/`signing_public_key` sono skIdP/pkIdP, la coppia
        dedicata all'elezione e certificata dalla CA (§2.4.2). Questa
        classe non le genera né le certifica, le riceve già pronte."""
        self._election_id = election_id
        self._signing_key = signing_key
        self._signing_public_key = signing_public_key
        self._clock = clock

        self._students: dict[str, _StudentRecord] = {}
        self._pending_challenges: dict[str, _PendingChallenge] = {}
        self._authenticated: set[str] = set()
        self._failed_attempts: dict[str, int] = {}
        self._blocked_until: dict[str, datetime] = {}
        self._issued: dict[str, _IssuedRecord] = {}
        self._issued_destroyed = False

    @property
    def signing_public_key(self) -> RSAPublicKey:
        """pkIdP — pubblicata nel manifest (§2.4.3), usabile da chiunque per verificare."""
        return self._signing_public_key

    # ------------------------------------------------------------------ #
    # Registro elettorale (assunzione F.6, §2.3): fuori scope del
    # protocollo, qui simulato come semplice enrollment.
    # ------------------------------------------------------------------ #

    def enroll_student(self, matricola: str, password: str) -> None:
        """Simula il caricamento del registro elettorale: genera saltM e
        salva hpwd = H(password ∥ saltM). Il documento dà questo passo
        per corretto e completo (F.6), non lo verifica il protocollo."""
        salt = generate_salt()
        self._students[matricola] = _StudentRecord(
            matricola=matricola, salt=salt, password_hash=hash_password(password, salt)
        )

    # ------------------------------------------------------------------ #
    # §2.5.1 — Authentication ceremony challenge-response
    # ------------------------------------------------------------------ #

    def start_authentication(self, matricola: str) -> tuple[bytes, bytes]:
        """Passi 1-3 di §2.5.1: l'elettore manda la matricola, l'IdP
        recupera (saltM, hpwd) e genera n1, restituendo (saltM, n1)."""
        self._raise_if_blocked(matricola)
        record = self._students.get(matricola)
        if record is None:
            raise AuthenticationError(f"matricola '{matricola}' non presente nel registro elettorale")

        nonce = os.urandom(NONCE_LENGTH_BYTES)
        self._pending_challenges[matricola] = _PendingChallenge(nonce=nonce)
        return record.salt, nonce

    def verify_authentication(self, matricola: str, response: bytes) -> bool:
        """
        Passi 4-6 di §2.5.1: confronto response con H(n1 ∥ hpwd), a tempo
        costante (`hmac.compare_digest`) per evitare il classico timing
        attack da confronto byte-a-byte (il caso Xbox 360 delle slide).

        La sessione viene consumata al primo tentativo, riuscito o no: n1
        è usa e getta, quindi anche un tentativo fallito non lascia una
        nonce riciclabile per un replay.
        """
        self._raise_if_blocked(matricola)
        challenge = self._pending_challenges.pop(matricola, None)
        if challenge is None:
            raise AuthenticationError(
                f"nessuna sessione di autenticazione in corso per '{matricola}' "
                f"(scaduta, mai iniziata, o già consumata)"
            )

        record = self._students[matricola]
        expected = sha256(challenge.nonce, record.password_hash)
        if not compare_digest(expected, response):
            self._register_failed_attempt(matricola)
            return False

        self._failed_attempts.pop(matricola, None)
        self._authenticated.add(matricola)
        return True

    def _raise_if_blocked(self, matricola: str) -> None:
        blocked_until = self._blocked_until.get(matricola)
        if blocked_until is not None and self._clock() < blocked_until:
            raise RateLimitedError(
                f"matricola '{matricola}' bloccata per troppi tentativi falliti "
                f"fino a {blocked_until.isoformat()} (§2.5.1, backoff esponenziale)"
            )

    def _register_failed_attempt(self, matricola: str) -> None:
        attempts = self._failed_attempts.get(matricola, 0) + 1
        self._failed_attempts[matricola] = attempts
        if attempts >= MAX_FAILED_ATTEMPTS:
            exponent = attempts - MAX_FAILED_ATTEMPTS
            delay = timedelta(seconds=BACKOFF_BASE_SECONDS * (2**exponent))
            self._blocked_until[matricola] = self._clock() + delay

    # ------------------------------------------------------------------ #
    # §2.5.3 — Emissione del token di voto
    # ------------------------------------------------------------------ #

    def issue_token(self, matricola: str, voter_public_key: RSAPublicKey) -> IssuedToken:
        """I 6 passi di §2.5.3. Richiede un'autenticazione appena riuscita
        per la stessa matricola (I.1); l'autorizzazione è usa e getta,
        questa chiamata la consuma."""
        if self._issued_destroyed:
            raise ElectionClosedError("Issued è già stata distrutta: le urne sono chiuse")

        if matricola not in self._authenticated:
            raise AuthenticationError(
                f"'{matricola}' non ha un'autenticazione valida in corso: "
                f"eseguire prima start_authentication + verify_authentication (I.1)"
            )

        # Passo 2 di §2.5.3 — unicità (I.2): un solo token per matricola.
        if matricola in self._issued:
            raise TokenAlreadyIssuedError(
                f"un token è già stato emesso per '{matricola}' in questa elezione (I.2)"
            )

        # Passo 3 — token_id casuale fresco a 128 bit, senza informazione su M.
        token_id = os.urandom(TOKEN_ID_LENGTH_BYTES)

        # Passo 4 — σ_token = Sign_skIdP(H(token_id ∥ pk_voter)).
        digest = sha256(token_id, public_key_der(voter_public_key))
        signature = sign(self._signing_key, digest)

        # Passo 5 — Issued[M] = (token_id, pk_voter, timestamp); mai esposta.
        self._issued[matricola] = _IssuedRecord(
            token_id=token_id, voter_public_key=voter_public_key, timestamp=self._clock()
        )
        self._authenticated.discard(matricola)  # l'autorizzazione era single-use

        # Passo 6 — restituzione all'elettore.
        return IssuedToken(token_id=token_id, signature=signature, voter_public_key=voter_public_key)

    def verify_token(self, token: IssuedToken) -> bool:
        """Verifica σ_token con pkIdP — comoda per i test perché usa la
        pkIdP di questa istanza; il BS reale userebbe la sua, presa dal
        manifest (§2.7, passo 2)."""
        digest = sha256(token.token_id, public_key_der(token.voter_public_key))
        return verify(self._signing_public_key, digest, token.signature)

    # ------------------------------------------------------------------ #
    # §2.8, passi 2-3 — chiusura urne
    # ------------------------------------------------------------------ #

    def close_and_publish_participants(self) -> SignedParticipantList:
        """Passo 2 di §2.8: pubblica firmata la lista di chi ha ricevuto
        un token — mitiga il ballot stuffing (T.6), perché anche un
        astenuto può controllare di non comparirci."""
        matricole = tuple(sorted(self._issued.keys()))
        payload = sha256(self._election_id.encode(), b"|", b",".join(m.encode() for m in matricole))
        signature = sign(self._signing_key, payload)
        return SignedParticipantList(election_id=self._election_id, matricole=matricole, signature=signature)

    def destroy_issued_table(self) -> SignedDestructionStatement:
        """Passo 3 di §2.8: svuota Issued (serve per C.2) ed emette una
        dichiarazione firmata. È responsabilità non ripudiabile, non una
        prova crittografica che la cancellazione sia avvenuta davvero —
        quello non si può dimostrare a distanza, e il documento lo dice
        chiaramente."""
        if self._issued_destroyed:
            raise ElectionClosedError("Issued è già stata distrutta")

        self._issued.clear()
        self._authenticated.clear()
        self._issued_destroyed = True

        timestamp = self._clock()
        payload = sha256(f"Issued table destroyed at {timestamp.isoformat()}".encode())
        signature = sign(self._signing_key, payload)
        return SignedDestructionStatement(timestamp=timestamp, signature=signature)


# Verifiche indipendenti: chiunque le può fare con la sola pkIdP dal
# manifest, senza uno stato dell'IdP — per questo sono funzioni di modulo
# e non metodi.


def verify_participant_list(idp_public_key: RSAPublicKey, participant_list: SignedParticipantList) -> bool:
    """Chiunque può verificare la lista dei partecipanti con la sola pkIdP (§2.8)."""
    return verify(idp_public_key, participant_list.signed_payload(), participant_list.signature)


def verify_destruction_statement(
    idp_public_key: RSAPublicKey, statement: SignedDestructionStatement
) -> bool:
    """Chiunque può verificare la dichiarazione di distruzione con la sola pkIdP (§2.8)."""
    return verify(idp_public_key, statement.signed_payload(), statement.signature)


def verify_token_as_ballot_server(
    token: IssuedToken,
    idp_certificate: x509.Certificate,
    ca_certificate: x509.Certificate,
    crl: x509.CertificateRevocationList | None = None,
    now: datetime | None = None,
) -> bool:
    """
    La verifica del token come la farebbe davvero il Ballot Server: parte
    dal certificato dell'IdP e dalla PKI, non da una pkIdP che gli arriva
    già pronta e di cui deve fidarsi sulla parola. `verify_token` sopra va
    bene per i test perché usa la pkIdP dell'istanza, ma dà per scontato
    proprio quello che la PKI serve a stabilire; qui invece ci si fida
    solo della CA (F.1), e pkIdP si estrae dal certificato solo dopo
    averlo validato.

    Tre controlli in ordine: (1) il certificato è autentico, valido e non
    revocato — è questo che rende operativa la revoca di §2.4.2, senza
    non si vedrebbe alcun effetto dopo che la CA revoca la chiave a urne
    chiuse; (2) la Key Usage ha sia `digitalSignature` sia
    `nonRepudiation` — il secondo è il punto vero, perché il certificato
    TLS dell'IdP ha anch'esso digitalSignature (serve per l'handshake) ma
    non nonRepudiation, quindi accontentarsi del primo flag da solo
    accetterebbe un token firmato con la chiave sbagliata, vanificando la
    separazione che §2.4.2 vuole; (3) σ_token verifica su
    H(token_id ∥ pk_voter) con la chiave del certificato.

    `crl=None` vuol dire "non disponibile", stessa semantica di
    `verify_certificate_with_crl`.
    """
    if not verify_certificate_with_crl(idp_certificate, ca_certificate, crl, now):
        return False

    try:
        key_usage = idp_certificate.extensions.get_extension_for_class(x509.KeyUsage).value
    except x509.ExtensionNotFound:
        return False
    if not (key_usage.digital_signature and key_usage.content_commitment):
        return False

    idp_public_key = idp_certificate.public_key()
    if not isinstance(idp_public_key, RSAPublicKey):
        return False

    digest = sha256(token.token_id, public_key_der(token.voter_public_key))
    return verify(idp_public_key, digest, token.signature)
