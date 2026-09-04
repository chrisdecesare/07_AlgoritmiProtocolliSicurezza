"""
Test del manifest di elezione (§2.4.3): è la radice di fiducia da cui
ogni verifica successiva deriva, quindi qui interessa soprattutto che
non accetti nulla di manomesso — un manifest che verifica quando non
dovrebbe è peggio di nessun manifest, perché tutto il resto del
protocollo si appoggia su di lui (V.2 punto 2).
"""
import dataclasses
from datetime import datetime, timedelta, timezone

import pytest

from src.ballot.ballot_server import HEAD_REFERENCE_TOLERANCE
from src.bulletin_board.bulletin_board import genesis_head
from src.ca.root_ca import EntityRole, UniversityCA
from src.commission.shamir import SHAMIR_THRESHOLD, SHAMIR_TOTAL_SHARES
from src.common.ballot_encoding import VOTE_NO, VOTE_YES
from src.common.hashing import sha256
from src.common.keys import RSA_KEY_SIZE_BITS, generate_rsa_keypair
from src.common.manifest import (
    ElectionManifest,
    ManifestSigningError,
    check_turnout_consistency,
    sign_manifest,
    verify_manifest,
)

ELECTION_ID = "referendum-ateneo-2026"
OPENS_AT = datetime(2026, 5, 1, 8, 0, tzinfo=timezone.utc)
CLOSES_AT = datetime(2026, 5, 1, 20, 0, tzinfo=timezone.utc)
ELECTORATE_SIZE = 12_000


@pytest.fixture(scope="module")
def setup():
    """Il materiale della cerimonia di §2.2.4: CA, 5 commissari con i
    loro certificati, le chiavi degli altri attori."""
    ca = UniversityCA(organization_name="Universita degli Studi di Salerno")

    commissioner_keys = [generate_rsa_keypair() for _ in range(SHAMIR_TOTAL_SHARES)]
    commissioner_certificates = tuple(
        ca.issue_certificate(
            f"commissario-{i}", EntityRole.COMMISSIONER, public_key=key.public_key()
        ).certificate
        for i, key in enumerate(commissioner_keys, 1)
    )

    idp_signing_key = generate_rsa_keypair()
    bs_signing_key = generate_rsa_keypair()
    encryption_key = generate_rsa_keypair()

    idp_tls = ca.issue_certificate("idp.unisa.it", EntityRole.IDP_TLS).certificate
    bs_tls = ca.issue_certificate("bs.unisa.it", EntityRole.BS_TLS).certificate

    manifest = ElectionManifest(
        election_id=ELECTION_ID,
        question="Sei favorevole alla modifica dello statuto di Ateneo?",
        options=(VOTE_YES, VOTE_NO),
        voting_opens_at=OPENS_AT,
        voting_closes_at=CLOSES_AT,
        encryption_public_key=encryption_key.public_key(),
        pke_scheme="RSA-OAEP",
        pke_modulus_bits=RSA_KEY_SIZE_BITS,
        pke_hash="SHA-256",
        shamir_prime=2**3071 + 1,  # valore fittizio: qui conta solo che sia firmato
        shamir_threshold=SHAMIR_THRESHOLD,
        shamir_total_shares=SHAMIR_TOTAL_SHARES,
        bs_signing_public_key=bs_signing_key.public_key(),
        idp_signing_public_key=idp_signing_key.public_key(),
        commissioner_certificates=commissioner_certificates,
        electorate_size=ELECTORATE_SIZE,
        idp_endpoint="https://idp.unisa.it/vote",
        ballot_server_endpoint="https://bs.unisa.it/ballots",
        bulletin_board_endpoint="https://bb.unisa.it/",
        idp_tls_certificate=idp_tls,
        bs_tls_certificate=bs_tls,
        genesis_head=genesis_head(ELECTION_ID, OPENS_AT.isoformat()),
        head_reference_tolerance=HEAD_REFERENCE_TOLERANCE,
        voting_client_hash=sha256(b"client-di-voto-ufficiale-v1"),
    )
    signed = sign_manifest(manifest, commissioner_keys, ca.countersign)
    return ca, commissioner_keys, manifest, signed


def test_a_correctly_signed_manifest_verifies(setup):
    ca, _, _, signed = setup
    assert verify_manifest(signed, ca.certificate) is True


def test_manifest_contains_every_field_listed_in_the_document(setup):
    """§2.4.3 elenca undici voci: se una sparisce dal manifest, sparisce
    anche la possibilità di verificarla a valle."""
    _, _, manifest, _ = setup
    field_names = {f.name for f in dataclasses.fields(manifest)}
    assert {
        "election_id", "question", "options",
        "voting_opens_at", "voting_closes_at",
        "encryption_public_key", "pke_scheme", "pke_modulus_bits", "pke_hash",
        "shamir_prime", "shamir_threshold", "shamir_total_shares",
        "bs_signing_public_key", "idp_signing_public_key",
        "commissioner_certificates", "electorate_size",
        "idp_endpoint", "ballot_server_endpoint", "bulletin_board_endpoint",
        "idp_tls_certificate", "bs_tls_certificate",
        "genesis_head", "head_reference_tolerance", "voting_client_hash",
    } <= field_names


@pytest.mark.parametrize(
    "field, value",
    [
        ("election_id", "referendum-truccato-2026"),
        ("question", "Domanda sostituita dopo la pubblicazione"),
        ("electorate_size", ELECTORATE_SIZE + 5_000),
        ("shamir_threshold", 1),
        ("pke_modulus_bits", 512),
        ("voting_client_hash", sha256(b"client-malevolo")),
    ],
)
def test_any_modification_after_publication_breaks_verification(setup, field, value):
    """§2.4.3: "qualunque modifica successiva sarebbe rilevabile come
    incoerenza fra firme e contenuto"."""
    ca, _, manifest, signed = setup
    tampered = dataclasses.replace(signed, manifest=dataclasses.replace(manifest, **{field: value}))
    assert verify_manifest(tampered, ca.certificate) is False


def test_genesis_head_must_be_consistent_with_declared_opening(setup):
    """head_0 = H(election_id ∥ timestamp_apertura): un head_0 arbitrario
    renderebbe il manifest inutile come ancora della catena del BB."""
    ca, _, manifest, signed = setup
    tampered = dataclasses.replace(
        signed, manifest=dataclasses.replace(manifest, genesis_head=sha256(b"testa-arbitraria"))
    )
    assert verify_manifest(tampered, ca.certificate) is False


def test_a_missing_commissioner_signature_is_rejected(setup):
    """§2.4.3 vuole la firma di *tutti* i commissari, non di t come nel
    tally bundle (§2.8.2): prima dell'apertura delle urne sono tutti
    riuniti (§2.2.4, passo 1)."""
    ca, _, _, signed = setup
    partial = dataclasses.replace(signed, commissioner_signatures=signed.commissioner_signatures[:-1])
    assert verify_manifest(partial, ca.certificate) is False


def test_a_forged_commissioner_signature_is_rejected(setup):
    ca, commissioner_keys, manifest, signed = setup
    outsider = generate_rsa_keypair()
    forged = list(signed.commissioner_signatures)
    from src.common.signing import sign

    forged[2] = sign(outsider, manifest.signed_payload())
    assert verify_manifest(dataclasses.replace(signed, commissioner_signatures=tuple(forged)), ca.certificate) is False


def test_a_missing_ca_countersignature_is_rejected(setup):
    """Senza la controfirma della CA il manifest non è ancorato a F.1:
    chiunque potrebbe generarne uno con cinque commissari inventati."""
    ca, commissioner_keys, manifest, signed = setup
    other_ca = UniversityCA(organization_name="CA non di Ateneo")
    assert verify_manifest(dataclasses.replace(signed, ca_signature=other_ca.countersign(manifest.signed_payload())), ca.certificate) is False


def test_a_commissioner_certificate_from_another_ca_is_rejected(setup):
    """La catena di fiducia F.1 vale anche qui: un certificato emesso da
    una CA diversa non rende un commissario legittimo."""
    ca, _, manifest, _ = setup
    other_ca = UniversityCA(organization_name="CA non di Ateneo")
    impostor_key = generate_rsa_keypair()
    impostor_certificate = other_ca.issue_certificate(
        "commissario-falso", EntityRole.COMMISSIONER, public_key=impostor_key.public_key()
    ).certificate

    certificates = list(manifest.commissioner_certificates)
    certificates[0] = impostor_certificate
    tampered_manifest = dataclasses.replace(manifest, commissioner_certificates=tuple(certificates))

    keys = [impostor_key] + [generate_rsa_keypair() for _ in range(SHAMIR_TOTAL_SHARES - 1)]
    # le altre chiavi non corrispondono ai certificati: firmo a mano per
    # arrivare comunque alla verifica della catena di fiducia
    from src.common.signing import sign

    payload = tampered_manifest.signed_payload()
    signed_by_impostor = dataclasses.replace(
        _unsigned(tampered_manifest),
        commissioner_signatures=tuple(sign(k, payload) for k in keys),
        ca_signature=ca.countersign(payload),
    )
    assert verify_manifest(signed_by_impostor, ca.certificate) is False


def test_signing_with_a_key_that_does_not_match_the_certificate_fails_loudly(setup):
    """Meglio un errore alla firma che un manifest che non verificherà
    mai, scoperto a urne aperte."""
    ca, commissioner_keys, manifest, _ = setup
    wrong_keys = list(commissioner_keys)
    wrong_keys[1] = generate_rsa_keypair()
    with pytest.raises(ManifestSigningError):
        sign_manifest(manifest, wrong_keys, ca.countersign)


def test_signing_with_the_wrong_number_of_commissioners_fails_loudly(setup):
    ca, commissioner_keys, manifest, _ = setup
    with pytest.raises(ManifestSigningError):
        sign_manifest(manifest, commissioner_keys[:-1], ca.countersign)


def test_turnout_consistency_detects_more_tokens_than_eligible_voters(setup):
    """V.2 punto 9 / F.5: la cardinalità dichiarata rende rilevabile
    almeno la manipolazione del numero di aventi diritto."""
    _, _, manifest, _ = setup
    assert check_turnout_consistency(manifest, tokens_issued=9_000, ballots_registered=8_500) is True
    assert check_turnout_consistency(manifest, tokens_issued=ELECTORATE_SIZE + 1, ballots_registered=10) is False
    assert check_turnout_consistency(manifest, tokens_issued=100, ballots_registered=101) is False


def _unsigned(manifest: ElectionManifest):
    """Un `SignedElectionManifest` segnaposto da riempire con
    `dataclasses.replace` nei test che costruiscono le firme a mano."""
    from src.common.manifest import SignedElectionManifest

    return SignedElectionManifest(manifest=manifest, commissioner_signatures=(), ca_signature=b"")
