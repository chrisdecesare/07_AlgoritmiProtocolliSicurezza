"""
Test della Commissione (§2.2.4, §2.4.1, §2.8.1, §2.8.2): la cerimonia
non espone mai la chiave integra, qualunque terna di 3 commissari su 5
ricostruisce lo scrutinio corretto, meno di 3 no, e il tally bundle è
verificabile e tamper-evident.
"""
import dataclasses
import itertools

import pytest

from src.bulletin_board.bulletin_board import BulletinBoard, genesis_head
from src.commission.commission import (
    ElectionDecryptionKey,
    TallyIntegrityError,
    generate_and_share_decryption_key,
    run_scrutiny,
    sign_tally_bundle,
    verify_tally_bundle,
)
from src.commission.shamir import SHAMIR_THRESHOLD, SHAMIR_TOTAL_SHARES
from src.common.ballot_encoding import VOTE_NO, VOTE_YES, pack_ballot_plaintext
from src.common.keys import generate_rsa_keypair

ELECTION_ID = "referendum-ateneo-2026"
GENESIS = genesis_head(ELECTION_ID, "2026-05-01T08:00:00Z")


@pytest.fixture(scope="module")
def decryption_key() -> ElectionDecryptionKey:
    return generate_and_share_decryption_key()


def _bb_with_votes(decryption_key: ElectionDecryptionKey, votes: list[bytes]) -> BulletinBoard:
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import padding

    oaep = padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None)

    bb = BulletinBoard(GENESIS)
    head_ref = GENESIS
    for i, vote in enumerate(votes):
        plaintext = pack_ballot_plaintext(ELECTION_ID, head_ref, vote)
        ciphertext = decryption_key.public_key.encrypt(plaintext, oaep)
        voter_key = generate_rsa_keypair()
        entry = bb.append(
            ciphertext=ciphertext, voter_public_key=voter_key.public_key(), token_id=bytes([i]) * 16,
            token_signature=b"sigma-token", head_ref=head_ref, voter_signature=b"sigma-voter",
        )
        head_ref = entry.head
    return bb


def test_generate_and_share_never_exposes_the_private_key(decryption_key: ElectionDecryptionKey):
    field_names = {f.name for f in dataclasses.fields(decryption_key)}
    assert field_names == {"public_key", "modulus_n", "prime", "shares"}
    assert len(decryption_key.shares) == SHAMIR_TOTAL_SHARES


def test_any_three_of_five_shares_produce_the_correct_tally(decryption_key: ElectionDecryptionKey):
    votes = [VOTE_YES, VOTE_YES, VOTE_NO]
    bb = _bb_with_votes(decryption_key, votes)

    for combo in itertools.combinations(decryption_key.shares, SHAMIR_THRESHOLD):
        bundle = run_scrutiny(
            ELECTION_ID, b"head-final", bb.entries, combo, decryption_key.prime, decryption_key.modulus_n
        )
        assert bundle.total_decrypted == 3
        assert bundle.tally == {VOTE_YES: 2, VOTE_NO: 1}
        assert sorted(bundle.decrypted_votes) == sorted(votes)


def test_below_threshold_shares_fail_to_reconstruct_a_usable_key(decryption_key: ElectionDecryptionKey):
    """Con 2 share su 3 richieste, la d ricostruita è sbagliata: la decifratura OAEP fallisce (§2.8.1)."""
    bb = _bb_with_votes(decryption_key, [VOTE_YES])
    insufficient_shares = decryption_key.shares[: SHAMIR_THRESHOLD - 1]

    with pytest.raises(TallyIntegrityError):
        run_scrutiny(ELECTION_ID, b"head-final", bb.entries, insufficient_shares, decryption_key.prime, decryption_key.modulus_n)


def test_ballot_with_wrong_election_id_is_flagged(decryption_key: ElectionDecryptionKey):
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import padding

    oaep = padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
    plaintext = pack_ballot_plaintext("altra-elezione", GENESIS, VOTE_YES)
    ciphertext = decryption_key.public_key.encrypt(plaintext, oaep)

    bb = BulletinBoard(GENESIS)
    voter_key = generate_rsa_keypair()
    bb.append(ciphertext, voter_key.public_key(), b"\x01" * 16, b"sigma-token", GENESIS, b"sigma-voter")

    with pytest.raises(TallyIntegrityError):
        run_scrutiny(
            ELECTION_ID, b"head-final", bb.entries, decryption_key.shares[:SHAMIR_THRESHOLD],
            decryption_key.prime, decryption_key.modulus_n,
        )


def test_tally_bundle_signatures_below_threshold_fail_verification(decryption_key: ElectionDecryptionKey):
    bb = _bb_with_votes(decryption_key, [VOTE_YES, VOTE_NO])
    bundle = run_scrutiny(
        ELECTION_ID, b"head-final", bb.entries, decryption_key.shares[:SHAMIR_THRESHOLD],
        decryption_key.prime, decryption_key.modulus_n,
    )

    commissioners = [generate_rsa_keypair() for _ in range(SHAMIR_THRESHOLD)]
    signatures = sign_tally_bundle(bundle, commissioners[:2])  # solo 2 firme, ne servono 3

    ok = verify_tally_bundle(bundle, [c.public_key() for c in commissioners[:2]], signatures, threshold=SHAMIR_THRESHOLD)
    assert ok is False


def test_duplicated_signature_from_the_same_commissioner_does_not_count_twice(decryption_key: ElectionDecryptionKey):
    """Ripetere la stessa coppia (chiave, firma) non deve sostituire la collaborazione di commissari distinti."""
    bb = _bb_with_votes(decryption_key, [VOTE_YES, VOTE_NO])
    bundle = run_scrutiny(
        ELECTION_ID, b"head-final", bb.entries, decryption_key.shares[:SHAMIR_THRESHOLD],
        decryption_key.prime, decryption_key.modulus_n,
    )

    commissioners = [generate_rsa_keypair() for _ in range(2)]
    signatures = sign_tally_bundle(bundle, commissioners)
    # 3 voci ma solo 2 commissari distinti: il primo compare due volte.
    duplicated_keys = [commissioners[0].public_key(), commissioners[1].public_key(), commissioners[0].public_key()]
    duplicated_signatures = [signatures[0], signatures[1], signatures[0]]

    ok = verify_tally_bundle(bundle, duplicated_keys, duplicated_signatures, threshold=SHAMIR_THRESHOLD)
    assert ok is False


def test_tally_bundle_with_enough_signatures_verifies(decryption_key: ElectionDecryptionKey):
    bb = _bb_with_votes(decryption_key, [VOTE_YES, VOTE_NO, VOTE_YES])
    bundle = run_scrutiny(
        ELECTION_ID, b"head-final", bb.entries, decryption_key.shares[:SHAMIR_THRESHOLD],
        decryption_key.prime, decryption_key.modulus_n,
    )

    commissioners = [generate_rsa_keypair() for _ in range(SHAMIR_THRESHOLD)]
    signatures = sign_tally_bundle(bundle, commissioners)

    ok = verify_tally_bundle(bundle, [c.public_key() for c in commissioners], signatures, threshold=SHAMIR_THRESHOLD)
    assert ok is True


def test_forged_tally_bundle_fails_verification(decryption_key: ElectionDecryptionKey):
    bb = _bb_with_votes(decryption_key, [VOTE_YES, VOTE_NO])
    bundle = run_scrutiny(
        ELECTION_ID, b"head-final", bb.entries, decryption_key.shares[:SHAMIR_THRESHOLD],
        decryption_key.prime, decryption_key.modulus_n,
    )
    commissioners = [generate_rsa_keypair() for _ in range(SHAMIR_THRESHOLD)]
    signatures = sign_tally_bundle(bundle, commissioners)

    forged = dataclasses.replace(bundle, tally={VOTE_YES: 99, VOTE_NO: 0})
    ok = verify_tally_bundle(forged, [c.public_key() for c in commissioners], signatures, threshold=SHAMIR_THRESHOLD)
    assert ok is False
