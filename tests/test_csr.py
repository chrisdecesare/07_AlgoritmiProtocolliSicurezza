"""
Test dell'emissione via CSR (`issue_certificate_from_csr`) e della
proof-of-possession che la distingue dalla scorciatoia con chiave nuda.
"""
import pytest
from cryptography import x509
from cryptography.hazmat.primitives import serialization

from src.ca.csr import create_csr
from src.ca.root_ca import EntityRole, UniversityCA
from src.common.keys import generate_rsa_keypair


@pytest.fixture()
def ca() -> UniversityCA:
    return UniversityCA(organization_name="Universita di Test")


def test_csr_is_self_signed_proof_of_possession(ca: UniversityCA):
    key = generate_rsa_keypair()
    csr = create_csr("idp.ateneo.it", key, organization_name=ca.organization_name)
    assert csr.is_signature_valid


def test_issue_certificate_from_csr_succeeds_for_legitimate_request(ca: UniversityCA):
    key = generate_rsa_keypair()
    csr = create_csr(
        "idp.ateneo.it",
        key,
        organization_name=ca.organization_name,
        organizational_unit="Identity Provider",
    )
    certificate = ca.issue_certificate_from_csr(csr, EntityRole.IDP_TLS)

    assert ca.verify_certificate(certificate)
    assert certificate.public_key().public_numbers() == key.public_key().public_numbers()
    ou = certificate.subject.get_attributes_for_oid(x509.oid.NameOID.ORGANIZATIONAL_UNIT_NAME)
    assert ou[0].value == "Identity Provider"


def test_ca_does_not_receive_subject_private_key_via_csr(ca: UniversityCA):
    """
    A differenza di `issue_certificate(public_key=None)`, il percorso CSR
    non genera né restituisce mai la chiave privata: solo la CSR (che
    contiene la pubblica) attraversa il confine CA<->soggetto.
    """
    key = generate_rsa_keypair()
    csr = create_csr("bs.ateneo.it", key, organization_name=ca.organization_name)
    result = ca.issue_certificate_from_csr(csr, EntityRole.BS_TLS)

    assert isinstance(result, x509.Certificate)  # non un IssuedCertificate con .private_key


def test_ca_rejects_csr_from_different_organization(ca: UniversityCA):
    key = generate_rsa_keypair()
    csr = create_csr("idp.ateneo.it", key, organization_name="Ateneo Impostore")

    with pytest.raises(ValueError, match="[Oo]rganizzazione"):
        ca.issue_certificate_from_csr(csr, EntityRole.IDP_TLS)


def test_ca_refuses_unauthenticated_subject_via_csr(ca: UniversityCA):
    """Stesso passo 3 di 'PKI - Certification' già testato per issue_certificate."""
    key = generate_rsa_keypair()
    csr = create_csr("impostore.ateneo.it", key, organization_name=ca.organization_name)

    with pytest.raises(PermissionError):
        ca.issue_certificate_from_csr(csr, EntityRole.IDP_TLS, subject_authenticated=False)


def test_tampered_csr_signature_is_rejected(ca: UniversityCA):
    """
    Simula una CSR la cui firma non corrisponde più al contenuto (proof of
    possession fallita): la CA deve rifiutare prima ancora di guardare
    l'autenticazione del soggetto o l'organizzazione.
    """
    key = generate_rsa_keypair()
    csr = create_csr("idp.ateneo.it", key, organization_name=ca.organization_name)

    tampered_bytes = bytearray(csr.public_bytes(serialization.Encoding.DER))
    # Corrompe l'ultimo byte della firma (in coda alla struttura DER) per
    # invalidarla senza toccare i campi che precedono la firma stessa.
    tampered_bytes[-1] ^= 0xFF
    tampered_csr = x509.load_der_x509_csr(bytes(tampered_bytes))

    with pytest.raises(ValueError, match="CSR"):
        ca.issue_certificate_from_csr(tampered_csr, EntityRole.IDP_TLS)
