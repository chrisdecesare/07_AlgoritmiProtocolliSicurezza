"""Test della codifica canonica della scheda (§2.2.1, §2.6, §2.8.2)."""
import pytest

from src.common.ballot_encoding import (
    HEAD_REF_LENGTH_BYTES,
    VOTE_NO,
    VOTE_YES,
    BallotDecodingError,
    pack_ballot_plaintext,
    unpack_ballot_plaintext,
)

HEAD_REF = b"\x11" * HEAD_REF_LENGTH_BYTES


def test_pack_unpack_round_trip_yes():
    plaintext = pack_ballot_plaintext("referendum-2026", HEAD_REF, VOTE_YES)
    election_id, head_ref, vote = unpack_ballot_plaintext(plaintext)
    assert (election_id, head_ref, vote) == ("referendum-2026", HEAD_REF, VOTE_YES)


def test_pack_unpack_round_trip_no():
    plaintext = pack_ballot_plaintext("referendum-2026", HEAD_REF, VOTE_NO)
    election_id, head_ref, vote = unpack_ballot_plaintext(plaintext)
    assert (election_id, head_ref, vote) == ("referendum-2026", HEAD_REF, VOTE_NO)


def test_yes_and_no_have_identical_length():
    """§2.2.1: la codifica canonica non deve introdurre canali laterali di lunghezza."""
    yes_plaintext = pack_ballot_plaintext("e", HEAD_REF, VOTE_YES)
    no_plaintext = pack_ballot_plaintext("e", HEAD_REF, VOTE_NO)
    assert len(yes_plaintext) == len(no_plaintext)


def test_invalid_vote_value_rejected():
    with pytest.raises(ValueError):
        pack_ballot_plaintext("e", HEAD_REF, b"MAYBE")


def test_wrong_head_ref_length_rejected():
    with pytest.raises(ValueError):
        pack_ballot_plaintext("e", b"\x00" * 10, VOTE_YES)


def test_unpack_garbage_raises_decoding_error():
    with pytest.raises(BallotDecodingError):
        unpack_ballot_plaintext(b"\x00\x03not-actually-a-ballot")
