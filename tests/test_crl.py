"""
Test di revoca e CRL (Lab 4). Non solo che la meccanica funzioni, ma che
produca l'effetto voluto da §2.4.2: dopo la revoca a urne chiuse, i token
firmati con quella chiave non sono più accettati dal Ballot Server.
"""
import datetime

import pytest
from cryptography import x509

from src.ca.crl import crl_pem, is_revoked
from src.ca.root_ca import EntityRole, UniversityCA, verify_certificate_with_crl
from src.common.keys import generate_rsa_keypair
from src.idp.identity_provider import IdentityProvider, verify_token_as_ballot_server

CRL_URL = "http://pki.ateneo.it/crl/ateneo.crl.pem"


@pytest.fixture()
def ca() -> UniversityCA:
    return UniversityCA(organization_name="Universita di Test", crl_url=CRL_URL)


# ---------------------------------------------------------------------- #
# Database index.txt / serial (Lab 4, "Prepare the directory")
# ---------------------------------------------------------------------- #


def test_serials_are_sequential_from_the_store(ca: UniversityCA):
    """
    Il file `serial` del laboratorio è un contatore progressivo, non una
    sorgente casuale: l'unicità dei serial è ciò su cui poggia la CRL.
    """
    first = ca.issue_certificate("a.ateneo.it", EntityRole.IDP_TLS)
    second = ca.issue_certificate("b.ateneo.it", EntityRole.BS_TLS)
    assert second.certificate.serial_number == first.certificate.serial_number + 1


def test_issued_certificates_are_recorded_as_valid_in_index(ca: UniversityCA):
    issued = ca.issue_certificate("idp.ateneo.it", EntityRole.IDP_TLS)
    entry = ca.store.find(issued.certificate.serial_number)
    assert entry is not None
    assert entry.status == "V"
    assert entry.revoked_at is None
    assert "/CN=idp.ateneo.it" in entry.subject


def test_index_line_uses_openssl_format(ca: UniversityCA):
    """Formato del laboratorio: stato, scadenza, revoca, serial, file, DN."""
    issued = ca.issue_certificate("idp.ateneo.it", EntityRole.IDP_TLS)
    ca.revoke_certificate(issued.certificate)

    line = ca.store.index_txt().strip()
    fields = line.split("\t")
    assert len(fields) == 6
    assert fields[0] == "R"
    assert fields[1].endswith("Z")   # scadenza in UTCTime
    assert fields[2].endswith("Z")   # data di revoca, presente perché revocato
    assert int(fields[3], 16) == issued.certificate.serial_number
    assert fields[4] == "unknown"


# ---------------------------------------------------------------------- #
# crlDistributionPoints (Lab 4, "Prepare the configuration file")
# ---------------------------------------------------------------------- #


def test_leaf_certificates_carry_the_crl_distribution_point(ca: UniversityCA):
    """Chi verifica deve poter scoprire dal certificato dove trovare la CRL."""
    issued = ca.issue_certificate("idp.ateneo.it", EntityRole.IDP_TLS)
    extension = issued.certificate.extensions.get_extension_for_class(
        x509.CRLDistributionPoints
    ).value
    uris = [name.value for point in extension for name in point.full_name]
    assert uris == [CRL_URL]


def test_no_distribution_point_when_no_url_configured():
    ca_without_crl = UniversityCA(organization_name="Universita di Test")
    issued = ca_without_crl.issue_certificate("idp.ateneo.it", EntityRole.IDP_TLS)
    with pytest.raises(x509.ExtensionNotFound):
        issued.certificate.extensions.get_extension_for_class(x509.CRLDistributionPoints)


# ---------------------------------------------------------------------- #
# Revoca e generazione della CRL
# ---------------------------------------------------------------------- #


def test_empty_crl_is_signed_and_authentic(ca: UniversityCA):
    """
    Una CRL vuota è un'informazione ("nessuna revoca"), l'assenza di CRL no:
    per questo la CA deve saperla emettere anche senza revoche.
    """
    crl = ca.current_crl()
    assert len(crl) == 0
    assert crl.is_signature_valid(ca.public_key)


def test_revoked_certificate_appears_in_crl(ca: UniversityCA):
    issued = ca.issue_certificate("idp-token.ateneo.it", EntityRole.IDP_TOKEN_SIGNING)
    ca.revoke_certificate(issued.certificate)

    crl = ca.current_crl()
    assert is_revoked(crl, issued.certificate)
    assert crl.is_signature_valid(ca.public_key)


def test_crl_number_increases_at_every_generation(ca: UniversityCA):
    """
    Il contatore `crlnumber` impedisce a un avversario di servire una CRL
    vecchia — correttamente firmata — al posto di una più recente.
    """
    first = ca.current_crl().extensions.get_extension_for_class(x509.CRLNumber).value
    second = ca.current_crl().extensions.get_extension_for_class(x509.CRLNumber).value
    assert second.crl_number > first.crl_number


def test_ca_refuses_to_revoke_a_certificate_it_did_not_issue(ca: UniversityCA):
    other_ca = UniversityCA(organization_name="Ateneo Impostore")
    foreign = other_ca.issue_certificate("idp.ateneo.it", EntityRole.IDP_TLS)
    with pytest.raises(ValueError):
        ca.revoke_certificate(foreign.certificate)


def test_double_revocation_is_rejected(ca: UniversityCA):
    issued = ca.issue_certificate("idp.ateneo.it", EntityRole.IDP_TLS)
    ca.revoke_certificate(issued.certificate)
    with pytest.raises(ValueError):
        ca.revoke_certificate(issued.certificate)


def test_crl_is_inspectable_as_pem(ca: UniversityCA):
    """`openssl crl -in <file> -noout -text` deve poterla leggere."""
    assert crl_pem(ca.current_crl()).startswith(b"-----BEGIN X509 CRL-----")


# ---------------------------------------------------------------------- #
# Effetto della revoca sulla verifica
# ---------------------------------------------------------------------- #


def test_ca_side_verification_fails_after_revocation(ca: UniversityCA):
    issued = ca.issue_certificate("idp.ateneo.it", EntityRole.IDP_TLS)
    assert ca.verify_certificate(issued.certificate) is True

    ca.revoke_certificate(issued.certificate)
    assert ca.verify_certificate(issued.certificate) is False


def test_third_party_verification_needs_the_crl_to_see_the_revocation(ca: UniversityCA):
    """
    Verificabilità universale (§3.5.2): un osservatore esterno non ha
    l'index.txt della CA, ha solo i certificati e la CRL pubblicati.
    Senza CRL il certificato revocato gli appare ancora valido — ed è
    esattamente perché la CRL va pubblicata, non solo generata.
    """
    issued = ca.issue_certificate("idp.ateneo.it", EntityRole.IDP_TLS)
    ca.revoke_certificate(issued.certificate)

    assert verify_certificate_with_crl(issued.certificate, ca.certificate, crl=None) is True
    assert (
        verify_certificate_with_crl(issued.certificate, ca.certificate, crl=ca.current_crl())
        is False
    )


def test_crl_signed_by_another_ca_is_rejected(ca: UniversityCA):
    """Una CRL non autentica è peggio di nessuna CRL: potrebbe nascondere una revoca."""
    issued = ca.issue_certificate("idp.ateneo.it", EntityRole.IDP_TLS)
    impostor = UniversityCA(organization_name="Ateneo Impostore")

    assert (
        verify_certificate_with_crl(issued.certificate, ca.certificate, crl=impostor.current_crl())
        is False
    )


def test_expired_crl_is_treated_as_unavailable(ca: UniversityCA):
    """
    Una CRL scaduta non prova che il certificato non sia stato revocato nel
    frattempo: va trattata come indisponibile, non come "nessuna revoca".

    Per esercitare davvero il ramo serve una CRL già scaduta mentre il
    certificato è ancora valido; si costruisce quindi la CRL con una
    validità di un'ora e la si verifica il giorno dopo, quando il
    certificato (30 giorni) è ancora in corso.
    """
    issued = ca.issue_certificate("idp.ateneo.it", EntityRole.IDP_TLS)
    ca.revoke_certificate(issued.certificate)

    short_lived_crl = ca.current_crl(validity=datetime.timedelta(hours=1))

    tomorrow = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=1)
    assert short_lived_crl.next_update_utc < tomorrow            # la CRL è scaduta
    assert issued.certificate.not_valid_after_utc > tomorrow     # il certificato no

    # CRL scaduta: la revoca non è più opponibile, la verifica torna True
    # come se la CRL non fosse disponibile.
    assert (
        verify_certificate_with_crl(
            issued.certificate, ca.certificate, crl=short_lived_crl, now=tomorrow
        )
        is True
    )
    # Con una CRL ancora in corso di validità, invece, la revoca si vede.
    assert (
        verify_certificate_with_crl(
            issued.certificate, ca.certificate, crl=ca.current_crl(), now=tomorrow
        )
        is False
    )


# ---------------------------------------------------------------------- #
# Il caso d'uso di §2.4.2: revoca della chiave elettorale dell'IdP
# ---------------------------------------------------------------------- #


def test_ballot_server_accepts_token_while_idp_certificate_is_valid(ca: UniversityCA):
    signing_key = generate_rsa_keypair()
    idp_certificate = ca.issue_certificate(
        "idp-token.ateneo.it",
        EntityRole.IDP_TOKEN_SIGNING,
        public_key=signing_key.public_key(),
    ).certificate

    idp = IdentityProvider(
        election_id="referendum-test",
        signing_key=signing_key,
        signing_public_key=signing_key.public_key(),
    )
    idp.enroll_student("0522500001", "password")
    salt, nonce = idp.start_authentication("0522500001")

    from src.common.hashing import sha256
    from src.common.password_hash import hash_password

    idp.verify_authentication("0522500001", sha256(nonce, hash_password("password", salt)))
    token = idp.issue_token("0522500001", generate_rsa_keypair().public_key())

    assert (
        verify_token_as_ballot_server(token, idp_certificate, ca.certificate, ca.current_crl())
        is True
    )


def test_token_is_rejected_after_election_key_is_revoked(ca: UniversityCA):
    """
    §2.4.2: a urne chiuse la chiave elettorale dell'IdP viene revocata.
    Da quel momento un token firmato con essa non è più accettabile — è
    l'effetto osservabile che rende la revoca una proprietà del sistema e
    non una dichiarazione.
    """
    signing_key = generate_rsa_keypair()
    idp_certificate = ca.issue_certificate(
        "idp-token.ateneo.it",
        EntityRole.IDP_TOKEN_SIGNING,
        public_key=signing_key.public_key(),
    ).certificate

    idp = IdentityProvider(
        election_id="referendum-test",
        signing_key=signing_key,
        signing_public_key=signing_key.public_key(),
    )
    idp.enroll_student("0522500001", "password")
    salt, nonce = idp.start_authentication("0522500001")

    from src.common.hashing import sha256
    from src.common.password_hash import hash_password

    idp.verify_authentication("0522500001", sha256(nonce, hash_password("password", salt)))
    token = idp.issue_token("0522500001", generate_rsa_keypair().public_key())

    ca.revoke_certificate(idp_certificate)
    crl_after_closure = ca.current_crl()

    assert (
        verify_token_as_ballot_server(token, idp_certificate, ca.certificate, crl_after_closure)
        is False
    )
    # La firma in sé resta matematicamente valida: ciò che è cambiato è lo
    # stato del certificato, non la matematica. Distinguere i due piani è
    # il punto dell'intero meccanismo di revoca.
    assert idp.verify_token(token) is True


def test_tls_certificate_cannot_be_used_to_validate_tokens(ca: UniversityCA):
    """
    L'IdP ha due certificati distinti (§2.4.2, isolamento del rischio).

    Il caso è insidioso perché anche il certificato TLS porta
    `digitalSignature` — gli serve per l'handshake — quindi un controllo
    che si fermasse lì accetterebbe un token firmato con la chiave TLS,
    rendendo nominale la separazione. Il discriminante è
    `nonRepudiation`, che il profilo `server_cert` del Lab 4 non concede.

    Qui la stessa identica chiave viene certificata due volte, una per
    ruolo: la firma è quindi matematicamente valida in entrambi i casi, e
    l'unica cosa che cambia è il ruolo dichiarato dal certificato. È il
    modo più netto di mostrare che a essere rifiutato è l'uso, non la
    crittografia.
    """
    signing_key = generate_rsa_keypair()
    tls_certificate = ca.issue_certificate(
        "idp.ateneo.it", EntityRole.IDP_TLS, public_key=signing_key.public_key()
    ).certificate
    token_certificate = ca.issue_certificate(
        "idp-token.ateneo.it",
        EntityRole.IDP_TOKEN_SIGNING,
        public_key=signing_key.public_key(),
    ).certificate

    idp = IdentityProvider(
        election_id="referendum-test",
        signing_key=signing_key,
        signing_public_key=signing_key.public_key(),
    )
    idp.enroll_student("0522500001", "password")
    salt, nonce = idp.start_authentication("0522500001")

    from src.common.hashing import sha256
    from src.common.password_hash import hash_password

    idp.verify_authentication("0522500001", sha256(nonce, hash_password("password", salt)))
    token = idp.issue_token("0522500001", generate_rsa_keypair().public_key())

    # Premessa del test: entrambi i certificati concedono digitalSignature,
    # quindi quel solo flag non li distingue.
    tls_key_usage = tls_certificate.extensions.get_extension_for_class(x509.KeyUsage).value
    assert tls_key_usage.digital_signature is True
    assert tls_key_usage.content_commitment is False

    crl = ca.current_crl()
    assert verify_token_as_ballot_server(token, tls_certificate, ca.certificate, crl) is False
    assert verify_token_as_ballot_server(token, token_certificate, ca.certificate, crl) is True
