"""
Test dell'IdP (§2.5, §2.8 passi 2-3): ceremony challenge-response,
anti-replay, backoff dopo k=3 fallimenti, token subordinato
all'autenticazione (I.1) e unico (I.2), lista partecipanti e distruzione
di Issued.
"""
from datetime import datetime, timedelta, timezone

import pytest

from src.ca.root_ca import EntityRole, UniversityCA
from src.common.hashing import sha256
from src.common.keys import generate_rsa_keypair
from src.common.password_hash import hash_password
from src.idp.identity_provider import (
    AuthenticationError,
    ElectionClosedError,
    IdentityProvider,
    RateLimitedError,
    TokenAlreadyIssuedError,
    verify_destruction_statement,
    verify_participant_list,
)

MATRICOLA = "0522500999"
PASSWORD = "correct horse battery staple"


class FakeClock:
    """Orologio iniettabile: avanza solo quando i test lo chiedono esplicitamente."""

    def __init__(self, start: datetime | None = None):
        self._now = start or datetime(2026, 5, 1, tzinfo=timezone.utc)

    def __call__(self) -> datetime:
        return self._now

    def advance(self, **kwargs) -> None:
        self._now += timedelta(**kwargs)


@pytest.fixture()
def ca() -> UniversityCA:
    return UniversityCA(organization_name="Universita di Test")


@pytest.fixture()
def signing_pair(ca: UniversityCA):
    signing_key = generate_rsa_keypair()
    ca.issue_certificate("idp-token.ateneo.it", EntityRole.IDP_TOKEN_SIGNING, public_key=signing_key.public_key())
    return signing_key, signing_key.public_key()


@pytest.fixture()
def clock() -> FakeClock:
    return FakeClock()


@pytest.fixture()
def idp(signing_pair, clock: FakeClock) -> IdentityProvider:
    signing_key, signing_public_key = signing_pair
    provider = IdentityProvider(
        election_id="referendum-ateneo-2026",
        signing_key=signing_key,
        signing_public_key=signing_public_key,
        clock=clock,
    )
    provider.enroll_student(MATRICOLA, PASSWORD)
    return provider


def _client_response(salt: bytes, nonce: bytes, password: str = PASSWORD) -> bytes:
    """Simula il calcolo lato client di §2.5.1: response = H(n1 ∥ hpwd)."""
    hpwd = hash_password(password, salt)
    return sha256(nonce, hpwd)


def test_successful_authentication_ceremony(idp: IdentityProvider):
    salt, nonce = idp.start_authentication(MATRICOLA)
    response = _client_response(salt, nonce)

    assert idp.verify_authentication(MATRICOLA, response) is True


def test_unknown_matricola_is_rejected(idp: IdentityProvider):
    with pytest.raises(AuthenticationError):
        idp.start_authentication("matricola-inesistente")


def test_wrong_password_fails_and_consumes_the_challenge(idp: IdentityProvider):
    salt, nonce = idp.start_authentication(MATRICOLA)
    wrong_response = _client_response(salt, nonce, password="password sbagliata")

    assert idp.verify_authentication(MATRICOLA, wrong_response) is False

    # La nonce era single-use: senza una nuova start_authentication non
    # c'è più alcuna sessione da verificare, nemmeno con la risposta giusta.
    correct_response = _client_response(salt, nonce)
    with pytest.raises(AuthenticationError):
        idp.verify_authentication(MATRICOLA, correct_response)


def test_replaying_a_previous_valid_response_fails(idp: IdentityProvider):
    """Anti-replay: catturare (n1, response) di una sessione passata non basta più."""
    salt, nonce = idp.start_authentication(MATRICOLA)
    response = _client_response(salt, nonce)
    assert idp.verify_authentication(MATRICOLA, response) is True

    with pytest.raises(AuthenticationError):
        idp.verify_authentication(MATRICOLA, response)  # nessuna sessione pendente


def test_rate_limiting_blocks_after_three_failures_then_expires(idp: IdentityProvider, clock: FakeClock):
    for _ in range(3):
        salt, nonce = idp.start_authentication(MATRICOLA)
        idp.verify_authentication(MATRICOLA, _client_response(salt, nonce, password="sbagliata"))

    with pytest.raises(RateLimitedError):
        idp.start_authentication(MATRICOLA)

    # Il blocco cresce esponenzialmente (base=2s, primo blocco 2*2^0=2s):
    # trascorso quell'intervallo, l'autenticazione torna disponibile.
    clock.advance(seconds=3)
    salt, nonce = idp.start_authentication(MATRICOLA)
    assert idp.verify_authentication(MATRICOLA, _client_response(salt, nonce)) is True


def test_issue_token_requires_prior_successful_authentication(idp: IdentityProvider):
    voter_key = generate_rsa_keypair().public_key()
    with pytest.raises(AuthenticationError):
        idp.issue_token(MATRICOLA, voter_key)


def test_issue_token_after_authentication_produces_valid_signature(idp: IdentityProvider):
    salt, nonce = idp.start_authentication(MATRICOLA)
    idp.verify_authentication(MATRICOLA, _client_response(salt, nonce))

    voter_key = generate_rsa_keypair().public_key()
    token = idp.issue_token(MATRICOLA, voter_key)

    assert idp.verify_token(token) is True
    assert len(token.token_id) == 16  # 128 bit, §2.5.3


def test_tampered_token_id_fails_verification(idp: IdentityProvider):
    salt, nonce = idp.start_authentication(MATRICOLA)
    idp.verify_authentication(MATRICOLA, _client_response(salt, nonce))
    token = idp.issue_token(MATRICOLA, generate_rsa_keypair().public_key())

    from dataclasses import replace

    tampered = replace(token, token_id=b"\x00" * len(token.token_id))
    assert idp.verify_token(tampered) is False


def test_second_token_for_same_matricola_is_rejected(idp: IdentityProvider):
    """I.2 — unicità: un solo token per matricola per elezione."""
    salt, nonce = idp.start_authentication(MATRICOLA)
    idp.verify_authentication(MATRICOLA, _client_response(salt, nonce))
    idp.issue_token(MATRICOLA, generate_rsa_keypair().public_key())

    # Anche ri-autenticandosi con successo, il secondo token è rifiutato.
    salt, nonce = idp.start_authentication(MATRICOLA)
    idp.verify_authentication(MATRICOLA, _client_response(salt, nonce))
    with pytest.raises(TokenAlreadyIssuedError):
        idp.issue_token(MATRICOLA, generate_rsa_keypair().public_key())


def test_close_and_publish_participants_lists_only_issued_matricole(idp: IdentityProvider):
    idp.enroll_student("0522500888", PASSWORD)

    salt, nonce = idp.start_authentication(MATRICOLA)
    idp.verify_authentication(MATRICOLA, _client_response(salt, nonce))
    idp.issue_token(MATRICOLA, generate_rsa_keypair().public_key())
    # "0522500888" non richiede mai un token: è un astenuto e non deve comparire.

    participant_list = idp.close_and_publish_participants()

    assert participant_list.matricole == (MATRICOLA,)
    assert verify_participant_list(idp.signing_public_key, participant_list) is True


def test_destroy_issued_table_returns_verifiable_statement_and_blocks_new_tokens(idp: IdentityProvider):
    salt, nonce = idp.start_authentication(MATRICOLA)
    idp.verify_authentication(MATRICOLA, _client_response(salt, nonce))
    idp.issue_token(MATRICOLA, generate_rsa_keypair().public_key())

    statement = idp.destroy_issued_table()

    assert verify_destruction_statement(idp.signing_public_key, statement) is True

    with pytest.raises(ElectionClosedError):
        idp.issue_token("0522500888", generate_rsa_keypair().public_key())

    with pytest.raises(ElectionClosedError):
        idp.destroy_issued_table()


def test_forged_participant_list_fails_verification(idp: IdentityProvider):
    """Un osservatore che verifica con pkIdP deve rilevare una lista manomessa."""
    from dataclasses import replace

    salt, nonce = idp.start_authentication(MATRICOLA)
    idp.verify_authentication(MATRICOLA, _client_response(salt, nonce))
    idp.issue_token(MATRICOLA, generate_rsa_keypair().public_key())

    genuine = idp.close_and_publish_participants()
    forged = replace(genuine, matricole=genuine.matricole + ("matricola-fantasma",))

    assert verify_participant_list(idp.signing_public_key, forged) is False
