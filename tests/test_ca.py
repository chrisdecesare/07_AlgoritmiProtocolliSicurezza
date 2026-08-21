"""
Test della CA universitaria: copre esattamente le emissioni richieste dal
setup pre-elezione descritto in 07_APS_1 §2.4 (IdP, BS, n=5 commissari) e
verifica sia il caso di successo sia i casi di rigetto (certificato di
un'altra CA, certificato scaduto).
"""
import datetime

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.x509.oid import NameOID

from src.ca.root_ca import EntityRole, UniversityCA
from src.common.keys import generate_rsa_keypair


@pytest.fixture()
def ca() -> UniversityCA:
    return UniversityCA(organization_name="Universita di Test")


def test_root_is_self_signed_and_marked_as_ca(ca: UniversityCA):
    cert = ca.certificate
    assert cert.issuer == cert.subject
    basic_constraints = cert.extensions.get_extension_for_class(x509.BasicConstraints).value
    assert basic_constraints.ca is True
    assert basic_constraints.path_length == 0  # nessuna intermedia


def test_issue_idp_tls_certificate(ca: UniversityCA):
    issued = ca.issue_certificate("idp.ateneo.it", EntityRole.IDP_TLS)
    assert ca.verify_certificate(issued.certificate)
    eku = issued.certificate.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
    assert x509.oid.ExtendedKeyUsageOID.SERVER_AUTH in eku


def test_issue_bs_signing_certificate_is_signature_only(ca: UniversityCA):
    issued = ca.issue_certificate("bs-signing.ateneo.it", EntityRole.BS_SIGNING)
    assert ca.verify_certificate(issued.certificate)
    ku = issued.certificate.extensions.get_extension_for_class(x509.KeyUsage).value
    assert ku.digital_signature is True
    assert ku.key_encipherment is False  # non deve poter cifrare, solo firmare


def test_issue_certificates_for_five_commissioners(ca: UniversityCA):
    """(t, n) = (3, 5) come nell'esempio di 07_APS_1 §2.4.1."""
    issued_certs = [
        ca.issue_certificate(f"commissario-{i}@ateneo.it", EntityRole.COMMISSIONER)
        for i in range(1, 6)
    ]
    assert len(issued_certs) == 5
    for issued in issued_certs:
        assert ca.verify_certificate(issued.certificate)
        ku = issued.certificate.extensions.get_extension_for_class(x509.KeyUsage).value
        # deve poter firmare (manifest) E ricevere cifratura ibrida (share Shamir)
        assert ku.digital_signature is True
        assert ku.key_encipherment is True


def test_certificate_from_different_ca_is_rejected(ca: UniversityCA):
    other_ca = UniversityCA(organization_name="Ateneo Impostore")
    forged = other_ca.issue_certificate("idp.ateneo.it", EntityRole.IDP_TLS)
    assert ca.verify_certificate(forged.certificate) is False


def test_subject_can_bring_own_public_key(ca: UniversityCA):
    """
    Percorso realistico: il soggetto genera la propria coppia localmente e
    manda solo la chiave pubblica alla CA (cfr. slide 06, step 1-2), la
    CA non vede mai la chiave privata.
    """
    subject_key = generate_rsa_keypair()
    issued = ca.issue_certificate(
        "idp-token-signing.ateneo.it",
        EntityRole.IDP_TOKEN_SIGNING,
        public_key=subject_key.public_key(),
    )
    assert issued.private_key is None  # la CA non l'ha generata né la conosce
    assert ca.verify_certificate(issued.certificate)
    assert issued.certificate.public_key().public_numbers() == subject_key.public_key().public_numbers()


def test_ca_refuses_unauthenticated_subject(ca: UniversityCA):
    """
    Passo 3 di 'PKI - Certification' (slide 06): la CA deve autenticare il
    soggetto prima di emettere. Senza autenticazione dell'ID, l'emissione
    è rifiutata — è ciò che distingue una CA da un oracolo di firma.
    """
    with pytest.raises(PermissionError):
        ca.issue_certificate(
            "impostore.ateneo.it",
            EntityRole.IDP_TLS,
            subject_authenticated=False,
        )


def test_organizational_unit_appears_in_dn(ca: UniversityCA):
    """Il DN segue lo schema delle slide (CN/O/OU/C): l'OU deve comparire."""
    issued = ca.issue_certificate(
        "bs.ateneo.it",
        EntityRole.BS_TLS,
        organizational_unit="Commissione Elettorale",
    )
    ou_values = issued.certificate.subject.get_attributes_for_oid(NameOID.ORGANIZATIONAL_UNIT_NAME)
    assert len(ou_values) == 1
    assert ou_values[0].value == "Commissione Elettorale"
