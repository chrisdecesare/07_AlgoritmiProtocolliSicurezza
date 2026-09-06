"""
Revoca e CRL — "Certificate revocation lists".

All'inizio avevo escluso la revoca dal progetto, pensando che con una
finestra di voto così breve non servisse davvero. Però srebbe stato
 un errore: il documento dice esplicitamente che la
chiave elettorale dell'IdP "può essere revocata al termine senza impatti
sui servizi di Ateneo". Senza revoca il prototipo non dimostra metà
di quello che viene richiesto.

Il ciclo è quello del Lab che ci aveva fatto il Prof Mazzocca: `openssl ca -revoke` (sta in store.py, che
possiede il database), `openssl ca -gencrl` (è `build_crl` qui sotto), e
`crlDistributionPoints` nel certificato per dire dove trovarla.
Una CRL firmata, pubblicata col manifest, basta ed è
verificabile offline.
"""
from __future__ import annotations

import datetime

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey, RSAPublicKey

from src.ca.store import IndexEntry

# `default_crl_days = 30` nel openssl.cnf del laboratorio.
DEFAULT_CRL_VALIDITY = datetime.timedelta(days=30)


def crl_distribution_points(crl_url: str) -> x509.CRLDistributionPoints:
    """Estensione `crlDistributionPoints` (Lab 4): va messa nel
    certificato al momento dell'emissione, così chi verifica sa dove
    andare a cercare la CRL senza doverlo sapere per altra via."""
    return x509.CRLDistributionPoints(
        [
            x509.DistributionPoint(
                full_name=[x509.UniformResourceIdentifier(crl_url)],
                relative_name=None,
                reasons=None,
                crl_issuer=None,
            )
        ]
    )


def build_crl(
    issuer_name: x509.Name,
    signing_key: RSAPrivateKey,
    revoked_entries: tuple[IndexEntry, ...],
    crl_number: int,
    now: datetime.datetime | None = None,
    validity: datetime.timedelta = DEFAULT_CRL_VALIDITY,
) -> x509.CertificateRevocationList:
    """
    Emette la CRL firmata (`openssl ca -gencrl`). Le voci vengono dalle
    righe `R` di `index.txt`: la CRL è solo una "foto" firmata del database
    in quel momento, per questo va rigenerata dopo ogni revoca, non prima.

    `crl_number` cresce ad ogni CRL emessa, così un verificatore si accorge
    se gli arriva una versione più vecchia di una che ha già visto.
    `next_update` conta davvero: una CRL scaduta va trattata come "non
    disponibile", non come "nessuna revoca".
    """
    now = now or datetime.datetime.now(datetime.timezone.utc)

    builder = (
        x509.CertificateRevocationListBuilder()
        .issuer_name(issuer_name)
        .last_update(now)
        .next_update(now + validity)
        # [ crl_ext ] del laboratorio: authorityKeyIdentifier=keyid:always.
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(signing_key.public_key()),
            critical=False,
        )
        .add_extension(x509.CRLNumber(crl_number), critical=False)
    )

    for entry in revoked_entries:
        if entry.revoked_at is None:
            raise ValueError(
                f"la voce {entry.serial:#x} è marcata revocata ma senza data di revoca: "
                f"index.txt incoerente"
            )
        builder = builder.add_revoked_certificate(
            x509.RevokedCertificateBuilder()
            .serial_number(entry.serial)
            .revocation_date(entry.revoked_at)
            .build()
        )

    return builder.sign(signing_key, hashes.SHA256())


# mi serve per capire se la crl è effettivamente corretta o meno quindi controllo la firma se è adeguata
def crl_is_authentic(crl: x509.CertificateRevocationList, ca_public_key: RSAPublicKey) -> bool:
    """senza questo controllo,
    chiunque riesca a sostituire il file servito dal distribution point
    potrebbe far sparire una revoca semplicemente togliendola dalla lista.
    Non so se è "esagerato" come controllo ma sicuramente è utile
    """
    return crl.is_signature_valid(ca_public_key)


def is_revoked(crl: x509.CertificateRevocationList, certificate: x509.Certificate) -> bool:
    """Vero se il certificato è fra le voci revocate. Il confronto è sul
    serial (è quello che la CRL contiene) — motivo per cui i serial
    devono essere univoci per CA, altrimenti una revoca ne colpirebbe due."""
    return crl.get_revoked_certificate_by_serial_number(certificate.serial_number) is not None


def crl_pem(crl: x509.CertificateRevocationList) -> bytes:
    """CRL in PEM, ispezionabile con `openssl crl -in <file> -noout -text`."""
    return crl.public_bytes(serialization.Encoding.PEM)
