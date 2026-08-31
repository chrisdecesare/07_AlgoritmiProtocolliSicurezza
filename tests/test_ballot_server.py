"""
Test del Ballot Server (§2.7): i sei controlli in ordine, la ricevuta e
la sua verifica indipendente (V.1).
"""
from dataclasses import replace
from datetime import datetime, timedelta, timezone

import pytest

from src.ballot.ballot_server import (
    BallotServer,
    DuplicateBallotError,
    InvalidBallotSignatureError,
    InvalidTokenError,
    StaleHeadReferenceError,
    VotingClosedError,
    verify_receipt,
    verify_signed_head,
)
from src.bulletin_board.bulletin_board import genesis_head, verify_hash_chain
from src.ca.root_ca import EntityRole, UniversityCA
from src.common.hashing import sha256
from src.common.keys import generate_rsa_keypair
from src.common.password_hash import hash_password
from src.idp.identity_provider import IdentityProvider
from src.voter.client import cast_vote, generate_voter_keypair

ELECTION_ID = "referendum-ateneo-2026"
MATRICOLA = "0522500999"
PASSWORD = "correct horse battery staple"


def _client_response(salt: bytes, nonce: bytes, password: str = PASSWORD) -> bytes:
    return sha256(nonce, hash_password(password, salt))


@pytest.fixture()
def ca() -> UniversityCA:
    return UniversityCA(organization_name="Universita di Test")


@pytest.fixture()
def idp_certificate_and_key(ca: UniversityCA):
    signing_key = generate_rsa_keypair()
    certificate = ca.issue_certificate(
        "idp-token.ateneo.it", EntityRole.IDP_TOKEN_SIGNING, public_key=signing_key.public_key()
    ).certificate
    return certificate, signing_key


@pytest.fixture()
def idp(idp_certificate_and_key) -> IdentityProvider:
    _certificate, signing_key = idp_certificate_and_key
    provider = IdentityProvider(
        election_id=ELECTION_ID, signing_key=signing_key, signing_public_key=signing_key.public_key()
    )
    provider.enroll_student(MATRICOLA, PASSWORD)
    return provider


@pytest.fixture()
def bs_encryption_key():
    """Sta al posto di pk_BS della Commissione: qui basta una chiave RSA
    qualunque, la cifratura del voto non passa dal Ballot Server."""
    return generate_rsa_keypair()


@pytest.fixture()
def ballot_server(ca, idp_certificate_and_key, bs_encryption_key) -> BallotServer:
    idp_certificate, _idp_signing_key = idp_certificate_and_key
    signing_key = generate_rsa_keypair()
    genesis = genesis_head(ELECTION_ID, "2026-05-01T08:00:00Z")
    now = datetime.now(timezone.utc)
    return BallotServer(
        election_id=ELECTION_ID,
        genesis_head=genesis,
        signing_key=signing_key,
        signing_public_key=signing_key.public_key(),
        idp_certificate=idp_certificate,
        ca_certificate=ca.certificate,
        voting_opens_at=now - timedelta(minutes=5),
        voting_closes_at=now + timedelta(hours=1),
    )


def _issue_token(idp: IdentityProvider, voter_public_key):
    salt, nonce = idp.start_authentication(MATRICOLA)
    idp.verify_authentication(MATRICOLA, _client_response(salt, nonce))
    return idp.issue_token(MATRICOLA, voter_public_key)


def _cast(idp, bs, bs_encryption_key, prefer_yes=True):
    voter_key = generate_voter_keypair()
    token = _issue_token(idp, voter_key.public_key())
    head_ref = bs.current_head_reference()
    ballot = cast_vote(token, voter_key, bs_encryption_key.public_key(), ELECTION_ID, head_ref, prefer_yes)
    return ballot


def test_valid_ballot_is_accepted_and_appended(idp, ballot_server, bs_encryption_key):
    ballot = _cast(idp, ballot_server, bs_encryption_key)

    receipt = ballot_server.submit_ballot(ballot)

    assert receipt.id_seq == 1
    assert len(ballot_server.bulletin_board.entries) == 1
    assert verify_receipt(receipt, ballot_server.signing_public_key, ballot.ciphertext) is True
    assert verify_hash_chain(ballot_server.bulletin_board.genesis, ballot_server.bulletin_board.entries)


def test_replayed_ballot_is_rejected(idp, ballot_server, bs_encryption_key):
    """I.2 — un secondo invio con lo stesso token_id (retry di rete o doppio voto) è respinto."""
    ballot = _cast(idp, ballot_server, bs_encryption_key)
    ballot_server.submit_ballot(ballot)

    with pytest.raises(DuplicateBallotError):
        ballot_server.submit_ballot(ballot)

    assert len(ballot_server.bulletin_board.entries) == 1


def test_invalid_token_signature_is_rejected(idp, ballot_server, bs_encryption_key):
    ballot = _cast(idp, ballot_server, bs_encryption_key)
    forged = replace(ballot, token_signature=b"\x00" * len(ballot.token_signature))

    with pytest.raises(InvalidTokenError):
        ballot_server.submit_ballot(forged)


def test_token_from_unrelated_idp_is_rejected(ca, idp, ballot_server, bs_encryption_key):
    """Un token firmato da un'altra CA/IdP non deve passare la verifica di catena."""
    other_ca = UniversityCA(organization_name="Ateneo Impostore")
    other_signing_key = generate_rsa_keypair()
    other_certificate = other_ca.issue_certificate(
        "idp-token.impostore.it", EntityRole.IDP_TOKEN_SIGNING, public_key=other_signing_key.public_key()
    ).certificate
    impostor_idp = IdentityProvider(
        election_id=ELECTION_ID, signing_key=other_signing_key, signing_public_key=other_signing_key.public_key()
    )
    impostor_idp.enroll_student(MATRICOLA, PASSWORD)

    voter_key = generate_voter_keypair()
    token = _issue_token(impostor_idp, voter_key.public_key())
    head_ref = ballot_server.current_head_reference()
    ballot = cast_vote(token, voter_key, bs_encryption_key.public_key(), ELECTION_ID, head_ref, True)

    with pytest.raises(InvalidTokenError):
        ballot_server.submit_ballot(ballot)


def test_tampered_ciphertext_invalidates_ballot_signature(idp, ballot_server, bs_encryption_key):
    ballot = _cast(idp, ballot_server, bs_encryption_key)
    tampered = replace(ballot, ciphertext=b"\x00" * len(ballot.ciphertext))

    with pytest.raises(InvalidBallotSignatureError):
        ballot_server.submit_ballot(tampered)


def test_stale_head_reference_is_rejected(idp, ballot_server, bs_encryption_key):
    voter_key = generate_voter_keypair()
    token = _issue_token(idp, voter_key.public_key())
    stale_head_ref = b"\xff" * 32  # mai stata una testa reale del BB
    ballot = cast_vote(token, voter_key, bs_encryption_key.public_key(), ELECTION_ID, stale_head_ref, True)

    with pytest.raises(StaleHeadReferenceError):
        ballot_server.submit_ballot(ballot)


def test_voting_closed_before_open_is_rejected(ca, idp_certificate_and_key, bs_encryption_key, idp):
    idp_certificate, _key = idp_certificate_and_key
    signing_key = generate_rsa_keypair()
    genesis = genesis_head(ELECTION_ID, "2026-05-01T08:00:00Z")
    now = datetime.now(timezone.utc)
    future_bs = BallotServer(
        election_id=ELECTION_ID, genesis_head=genesis,
        signing_key=signing_key, signing_public_key=signing_key.public_key(),
        idp_certificate=idp_certificate, ca_certificate=ca.certificate,
        voting_opens_at=now + timedelta(hours=1), voting_closes_at=now + timedelta(hours=2),
    )
    ballot = _cast(idp, future_bs, bs_encryption_key)

    with pytest.raises(VotingClosedError):
        future_bs.submit_ballot(ballot)


def test_close_voting_rejects_subsequent_ballots_and_double_close(idp, ballot_server, bs_encryption_key):
    ballot = _cast(idp, ballot_server, bs_encryption_key)
    final_snapshot = ballot_server.close_voting(final_index=999)

    assert verify_signed_head(final_snapshot, ballot_server.signing_public_key) is True

    with pytest.raises(VotingClosedError):
        ballot_server.submit_ballot(ballot)
    with pytest.raises(VotingClosedError):
        ballot_server.close_voting(final_index=1000)


def test_publish_signed_head_is_independently_verifiable(idp, ballot_server, bs_encryption_key):
    ballot = _cast(idp, ballot_server, bs_encryption_key)
    ballot_server.submit_ballot(ballot)

    snapshot = ballot_server.publish_signed_head(index=1)

    assert snapshot.head == ballot_server.bulletin_board.current_head
    assert verify_signed_head(snapshot, ballot_server.signing_public_key) is True


def test_forged_receipt_fails_verification(idp, ballot_server, bs_encryption_key):
    ballot = _cast(idp, ballot_server, bs_encryption_key)
    receipt = ballot_server.submit_ballot(ballot)

    forged = replace(receipt, id_seq=receipt.id_seq + 1)
    assert verify_receipt(forged, ballot_server.signing_public_key, ballot.ciphertext) is False
