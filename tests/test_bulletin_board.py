"""
Test del Bulletin Board (§2.7): catena di hash e sua verifica
indipendente (§3.5.2, V.2 punto 3).
"""
from dataclasses import replace

from src.bulletin_board.bulletin_board import BulletinBoard, compute_next_head, genesis_head, verify_hash_chain
from src.common.keys import generate_rsa_keypair

GENESIS = genesis_head("referendum-2026", "2026-05-01T08:00:00Z")


def _voter_pk():
    return generate_rsa_keypair().public_key()


def test_first_entry_chains_from_genesis():
    bb = BulletinBoard(GENESIS)
    entry = bb.append(
        ciphertext=b"C1", voter_public_key=_voter_pk(), token_id=b"\x01" * 16,
        token_signature=b"sigma1", head_ref=GENESIS, voter_signature=b"sig1",
    )
    assert entry.id_seq == 1
    expected = compute_next_head(GENESIS, 1, b"C1", entry.voter_public_key, b"\x01" * 16)
    assert entry.head == expected
    assert bb.current_head == entry.head


def test_sequence_numbers_increment_and_chain_links():
    bb = BulletinBoard(GENESIS)
    first = bb.append(b"C1", _voter_pk(), b"\x01" * 16, b"s1", GENESIS, b"v1")
    second = bb.append(b"C2", _voter_pk(), b"\x02" * 16, b"s2", first.head, b"v2")

    assert first.id_seq == 1
    assert second.id_seq == 2
    assert second.head != first.head
    assert bb.current_head == second.head
    assert bb.entries == (first, second)


def test_verify_hash_chain_accepts_untampered_board():
    bb = BulletinBoard(GENESIS)
    bb.append(b"C1", _voter_pk(), b"\x01" * 16, b"s1", GENESIS, b"v1")
    head1 = bb.current_head
    bb.append(b"C2", _voter_pk(), b"\x02" * 16, b"s2", head1, b"v2")

    assert verify_hash_chain(GENESIS, bb.entries) is True


def test_verify_hash_chain_detects_tampering_with_a_past_entry():
    """§3.4.3: manomettere un'entry passata deve rompere la catena, anche se le entry successive non vengono toccate."""
    bb = BulletinBoard(GENESIS)
    first = bb.append(b"C1", _voter_pk(), b"\x01" * 16, b"s1", GENESIS, b"v1")
    bb.append(b"C2", _voter_pk(), b"\x02" * 16, b"s2", first.head, b"v2")

    tampered_first = replace(first, ciphertext=b"C1-MANOMESSO")
    tampered_entries = (tampered_first,) + bb.entries[1:]

    assert verify_hash_chain(GENESIS, tampered_entries) is False


def test_verify_hash_chain_rejects_wrong_genesis():
    bb = BulletinBoard(GENESIS)
    bb.append(b"C1", _voter_pk(), b"\x01" * 16, b"s1", GENESIS, b"v1")

    wrong_genesis = genesis_head("altra-elezione", "2026-05-01T08:00:00Z")
    assert verify_hash_chain(wrong_genesis, bb.entries) is False
