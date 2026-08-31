"""
Test del client dell'elettore (§2.5.2, §2.6): codifica canonica del
voto, cifratura verso pk_BS, firma del pacchetto.
"""
from src.common.hashing import sha256
from src.common.keys import generate_rsa_keypair
from src.common.rsa_raw import raw_rsa_oaep_decrypt
from src.common.signing import verify
from src.voter.client import (
    cast_vote,
    encode_vote,
    encrypt_ballot,
    generate_voter_keypair,
    sign_ballot,
)
from src.common.ballot_encoding import VOTE_NO, VOTE_YES, unpack_ballot_plaintext
from src.idp.identity_provider import IssuedToken

ELECTION_ID = "referendum-ateneo-2026"
HEAD_REF = b"\x22" * 32


def test_encode_vote_matches_canonical_constants():
    assert encode_vote(True) == VOTE_YES
    assert encode_vote(False) == VOTE_NO
    assert len(VOTE_YES) == len(VOTE_NO)


def test_encrypt_ballot_round_trips_via_raw_oaep_decrypt():
    bs_key = generate_rsa_keypair()
    ciphertext = encrypt_ballot(bs_key.public_key(), ELECTION_ID, HEAD_REF, VOTE_YES)

    numbers = bs_key.private_numbers()
    plaintext = raw_rsa_oaep_decrypt(ciphertext, numbers.public_numbers.n, numbers.d)
    election_id, head_ref, vote = unpack_ballot_plaintext(plaintext)

    assert (election_id, head_ref, vote) == (ELECTION_ID, HEAD_REF, VOTE_YES)


def test_sign_ballot_produces_a_verifiable_signature():
    voter_key = generate_voter_keypair()
    ciphertext = b"fake-ciphertext"
    token_id = b"\x01" * 16

    signature = sign_ballot(voter_key, ciphertext, token_id, HEAD_REF)

    digest = sha256(ciphertext, token_id, HEAD_REF)
    assert verify(voter_key.public_key(), digest, signature) is True


def test_cast_vote_produces_internally_consistent_ballot():
    bs_key = generate_rsa_keypair()
    voter_key = generate_voter_keypair()
    token = IssuedToken(token_id=b"\x02" * 16, signature=b"fake-sigma-token", voter_public_key=voter_key.public_key())

    ballot = cast_vote(token, voter_key, bs_key.public_key(), ELECTION_ID, HEAD_REF, prefer_yes=False)

    assert ballot.token_id == token.token_id
    assert ballot.token_signature == token.signature
    digest = sha256(ballot.ciphertext, ballot.token_id, ballot.head_ref)
    assert verify(ballot.voter_public_key, digest, ballot.voter_signature) is True

    numbers = bs_key.private_numbers()
    plaintext = raw_rsa_oaep_decrypt(ballot.ciphertext, numbers.public_numbers.n, numbers.d)
    assert unpack_ballot_plaintext(plaintext) == (ELECTION_ID, HEAD_REF, VOTE_NO)


def test_tampering_ciphertext_after_signing_invalidates_signature():
    """Un intercettatore che sostituisca C dopo la firma dev'essere rilevabile (I.3)."""
    bs_key = generate_rsa_keypair()
    voter_key = generate_voter_keypair()
    token = IssuedToken(token_id=b"\x03" * 16, signature=b"fake-sigma-token", voter_public_key=voter_key.public_key())

    ballot = cast_vote(token, voter_key, bs_key.public_key(), ELECTION_ID, HEAD_REF, prefer_yes=True)

    tampered_digest = sha256(b"different-ciphertext", ballot.token_id, ballot.head_ref)
    assert verify(ballot.voter_public_key, tampered_digest, ballot.voter_signature) is False
