"""
CA universitaria — simula la PKI di Ateneo che il documento dà per
scontata (§2.3).

Segue i 6 passi di "PKI – Certification" (slide 06): 1-2 stanno in
`csr.py` (il soggetto genera la coppia e manda la CSR), 3 è
l'autenticazione fatta in `issue_certificate_from_csr`, 4-6 sono qui,
condivisi dai due percorsi di emissione. Le estensioni vengono dai
profili di `profiles.py`, i certificati sono tracciati in `store.py`
(index.txt + serial), la revoca e la CRL sono in `crl.py`.

Fuori scope, di proposito: gerarchia root/intermedia (il documento
assume una sola CA — `pathlen:0` sulla root lo rende un vincolo
verificabile, non solo una dichiarazione) e OCSP (discusso in crl.py).

Questo modulo non è una scelta di design del protocollo: implementa
un'assunzione di fiducia che il documento dà per acquisita (F.1).
"""
from __future__ import annotations

import datetime
import pathlib
from dataclasses import dataclass

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric.rsa import (
    RSAPrivateKey,
    RSAPublicKey,
)
from cryptography.x509.oid import NameOID

from src.ca.crl import (
    DEFAULT_CRL_VALIDITY,
    build_crl,
    crl_distribution_points,
    is_revoked,
)
from src.ca.csr import csr_proves_key_possession
from src.ca.profiles import EntityRole, ExtensionProfile, profile_for_role, V3_CA
from src.ca.store import CertificateStore
from src.common.keys import generate_rsa_keypair

ONE_DAY = datetime.timedelta(days=1)

# EntityRole viveva qui prima di finire in profiles.py insieme ai
# profili; lo riesporto per non rompere chi lo importa da qui.
__all__ = ["EntityRole", "IssuedCertificate", "UniversityCA", "verify_certificate_with_crl"]


@dataclass(frozen=True)
class IssuedCertificate:
    """Coppia (certificato, chiave privata del soggetto) restituita alla CA."""

    certificate: x509.Certificate
    private_key: RSAPrivateKey | None

    def certificate_pem(self) -> bytes:
        from cryptography.hazmat.primitives import serialization

        return self.certificate.public_bytes(serialization.Encoding.PEM)


class UniversityCA:
    """
    CA di Ateneo, self-signed: emette i certificati finali per gli attori
    del sistema di voto e gestisce la revoca.

    Nella realtà la chiave privata della root andrebbe generata offline e
    tenuta al sicuro (come consiglia il Lab 4). Qui resta in memoria per
    semplicità — è una scorciatoia del prototipo, non qualcosa che il
    protocollo richiede.
    """

    ROOT_VALIDITY = 365 * ONE_DAY          # vita della root, non della singola elezione
    LEAF_VALIDITY = 30 * ONE_DAY           # commisurata alla durata di una elezione

    def __init__(
        self,
        organization_name: str = "Universita degli Studi - Ateneo",
        crl_url: str | None = None,
        store_directory: pathlib.Path | None = None,
    ):
        """
        `crl_url`, se dato, finisce scritto in ogni certificato emesso
        (estensione `crlDistributionPoints`) così chi verifica sa dove
        cercare la CRL. `store_directory`, se data, scrive index.txt /
        serial / crlnumber su disco; altrimenti restano in memoria.
        """
        self._organization_name = organization_name
        self._crl_url = crl_url
        self._store = CertificateStore(store_directory)
        self._private_key: RSAPrivateKey = generate_rsa_keypair()
        self._certificate: x509.Certificate = self._self_sign_root()

    # ------------------------------------------------------------------ #
    # Root
    # ------------------------------------------------------------------ #

    def _self_sign_root(self) -> x509.Certificate:
        """Certificato di root, self-signed, profilo v3_ca. Il serial è
        casuale e non passa dal contatore di `store.py`: nel Lab la root
        si crea con `openssl req -x509`, non con `openssl ca`, quindi il
        contatore resta dedicato a ciò che la CA emette per altri."""
        subject = issuer = x509.Name(
            [
                x509.NameAttribute(NameOID.COUNTRY_NAME, "IT"),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, self._organization_name),
                x509.NameAttribute(NameOID.COMMON_NAME, f"{self._organization_name} Root CA"),
            ]
        )
        now = datetime.datetime.now(datetime.timezone.utc)

        builder = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(self._private_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - ONE_DAY)  # margine per clock skew
            .not_valid_after(now + self.ROOT_VALIDITY)
            .add_extension(V3_CA.basic_constraints, critical=True)
            .add_extension(V3_CA.key_usage, critical=True)
            .add_extension(
                x509.SubjectKeyIdentifier.from_public_key(self._private_key.public_key()),
                critical=False,
            )
        )
        return builder.sign(self._private_key, hashes.SHA256())

    @property
    def certificate(self) -> x509.Certificate:
        return self._certificate

    @property
    def public_key(self) -> RSAPublicKey:
        return self._private_key.public_key()

    @property
    def organization_name(self) -> str:
        return self._organization_name

    @property
    def store(self) -> CertificateStore:
        """Database dei certificati emessi (`index.txt` + `serial`)."""
        return self._store

    # ------------------------------------------------------------------ #
    # Emissione certificati finali — logica condivisa
    # ------------------------------------------------------------------ #

    def _build_leaf_certificate(
        self,
        subject: x509.Name,
        public_key: RSAPublicKey,
        profile: ExtensionProfile,
        validity: datetime.timedelta,
    ) -> x509.Certificate:
        """Passi 4-6 di "PKI – Certification": firma, allega, restituisce.
        Le estensioni arrivano tutte dal `profile`, non sono decise qui.
        Il certificato viene anche registrato in index.txt — è questo che
        lo rende revocabile in seguito."""
        now = datetime.datetime.now(datetime.timezone.utc)

        builder = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(self._certificate.subject)
            .public_key(public_key)
            .serial_number(self._store.next_serial())
            .not_valid_before(now - ONE_DAY)
            .not_valid_after(now + validity)
            .add_extension(profile.basic_constraints, critical=True)
            .add_extension(profile.key_usage, critical=True)
            .add_extension(
                x509.SubjectKeyIdentifier.from_public_key(public_key),
                critical=False,
            )
            .add_extension(
                x509.AuthorityKeyIdentifier.from_issuer_public_key(self.public_key),
                critical=False,
            )
        )

        if profile.extended_key_usage is not None:
            builder = builder.add_extension(profile.extended_key_usage, critical=False)

        if self._crl_url is not None:
            builder = builder.add_extension(
                crl_distribution_points(self._crl_url), critical=False
            )

        certificate = builder.sign(self._private_key, hashes.SHA256())
        self._store.record(certificate)
        return certificate

    def _require_authenticated(self, subject_label: str, subject_authenticated: bool) -> None:
        if not subject_authenticated:
            # Passo 3 delle slide: senza autenticazione la CA non firma.
            # Firmare comunque vorrebbe dire certificare un legame
            # (ID, chiave) mai verificato — e con questo va a farsi
            # benedire la fiducia su cui si regge tutta la PKI.
            raise PermissionError(
                f"Soggetto '{subject_label}' non autenticato: la CA non emette "
                f"certificati per identità non verificate (PKI-Certification, passo 3)."
            )

    # ------------------------------------------------------------------ #
    # Emissione — percorso raccomandato (CSR)
    # ------------------------------------------------------------------ #

    def issue_certificate_from_csr(
        self,
        csr: x509.CertificateSigningRequest,
        role: EntityRole,
        validity: datetime.timedelta | None = None,
        subject_authenticated: bool = True,
    ) -> x509.Certificate:
        """
        Il percorso di emissione realistico, quello che il Lab 4 consiglia
        per terze parti: il soggetto genera la coppia e la CSR da solo con
        `csr.create_csr`, la CA non vede mai la chiave privata. Qui
        autentico il soggetto e controllo che la CSR provi il possesso
        della chiave (altrimenti chiunque potrebbe chiedere un certificato
        per la chiave pubblica di qualcun altro), poi firmo con
        `_build_leaf_certificate`.
        """
        common_name = csr.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
        self._require_authenticated(common_name, subject_authenticated)

        if not csr_proves_key_possession(csr):
            raise ValueError(
                f"CSR per '{common_name}' non valida: la firma non dimostra "
                f"il possesso della chiave privata corrispondente."
            )

        csr_organization = csr.subject.get_attributes_for_oid(NameOID.ORGANIZATION_NAME)
        if not csr_organization or csr_organization[0].value != self._organization_name:
            raise ValueError(
                f"CSR per '{common_name}' rifiutata: organizzazione dichiarata "
                f"non corrisponde a questa CA ('{self._organization_name}')."
            )

        validity = validity or self.LEAF_VALIDITY
        return self._build_leaf_certificate(
            csr.subject, csr.public_key(), profile_for_role(role), validity
        )

    # ------------------------------------------------------------------ #
    # Emissione — scorciatoia di prototipo (chiave pubblica nuda)
    # ------------------------------------------------------------------ #

    def issue_certificate(
        self,
        common_name: str,
        role: EntityRole,
        public_key: RSAPublicKey | None = None,
        validity: datetime.timedelta | None = None,
        organizational_unit: str | None = None,
        subject_authenticated: bool = True,
    ) -> IssuedCertificate:
        """
        Scorciatoia tenuta per compatibilità con test, demo e benchmark
        esistenti — per codice nuovo usare `issue_certificate_from_csr`.
        Qui NON c'è nessuna proof-of-possession: se passi `public_key` la
        CA la certifica fidandosi e basta; se la ometti, la CA genera lei
        stessa la coppia e ti ridà anche la privata, il che va bene per
        un test ma sarebbe inaccettabile in un deployment vero (la CA non
        deve mai maneggiare la chiave privata di qualcun altro).
        """
        self._require_authenticated(common_name, subject_authenticated)

        subject_private_key: RSAPrivateKey | None = None
        if public_key is None:
            subject_private_key = generate_rsa_keypair()
            public_key = subject_private_key.public_key()

        name_attributes = [
            x509.NameAttribute(NameOID.COUNTRY_NAME, "IT"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, self._organization_name),
        ]
        if organizational_unit is not None:
            name_attributes.append(
                x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, organizational_unit)
            )
        name_attributes.append(x509.NameAttribute(NameOID.COMMON_NAME, common_name))
        subject = x509.Name(name_attributes)

        validity = validity or self.LEAF_VALIDITY
        certificate = self._build_leaf_certificate(
            subject, public_key, profile_for_role(role), validity
        )
        return IssuedCertificate(certificate=certificate, private_key=subject_private_key)

    # ------------------------------------------------------------------ #
    # Revoca e CRL — Lab 4
    # ------------------------------------------------------------------ #

    def revoke_certificate(
        self, certificate: x509.Certificate, when: datetime.datetime | None = None
    ) -> None:
        """
        Revoca un certificato (`openssl ca -revoke`): marca la riga in
        index.txt come `R`. Non basta da sola — diventa visibile a terzi
        solo quando `current_crl()` la rigenera e la pubblica, per questo
        il metodo non ritorna niente: ha solo aggiornato lo stato interno.

        Nel nostro caso è usata a urne chiuse, per revocare la chiave di
        firma dei token dell'IdP (§2.4.2).
        """
        if certificate.issuer != self._certificate.subject:
            raise ValueError(
                "questa CA non ha emesso il certificato indicato e non può revocarlo"
            )
        self._store.revoke(certificate.serial_number, when)

    def current_crl(
        self,
        now: datetime.datetime | None = None,
        validity: datetime.timedelta = DEFAULT_CRL_VALIDITY,
    ) -> x509.CertificateRevocationList:
        """
        Emette la CRL corrente (`openssl ca -gencrl`). Va bene chiamarla
        anche senza nulla da revocare: una CRL vuota e firmata dice
        comunque qualcosa ("nessun certificato revocato al momento"),
        mentre l'assenza di CRL non dice nulla. `validity` decide ogni
        quanto la CA si impegna a ripubblicarla (`next_update`).
        """
        return build_crl(
            issuer_name=self._certificate.subject,
            signing_key=self._private_key,
            revoked_entries=self._store.revoked,
            crl_number=self._store.next_crl_number(),
            now=now,
            validity=validity,
        )

    # ------------------------------------------------------------------ #
    # Verifica
    # ------------------------------------------------------------------ #

    def verify_certificate(self, certificate: x509.Certificate) -> bool:
        """
        I 4 "Requirements" della slide 06 più la revoca del Lab 4:

            R1. nome e chiave pubblica leggibili in chiaro — gratis, è il
                formato X.509 stesso (cert.subject / cert.public_key()).
            R2. il certificato viene davvero dalla CA ed è autentico —
                verifico la firma.
            R3. solo la CA può creare/aggiornare certificati — non è un
                controllo a parte, è una conseguenza di R2: senza la
                privata della CA nessuno produce una firma valida.
            R4. validità temporale — controllo le date.

        Più R5, la revoca: qui guardo direttamente `index.txt` perché
        questo è il controllo lato CA, che il database ce l'ha. Chi è
        fuori usa `verify_certificate_with_crl`, che non serve stato
        interno.
        """
        now = datetime.datetime.now(datetime.timezone.utc)

        # R4 — validità temporale
        if not (certificate.not_valid_before_utc <= now <= certificate.not_valid_after_utc):
            return False

        # R2 (pre-filtro) — l'issuer dichiarato deve essere questa CA
        if certificate.issuer != self._certificate.subject:
            return False

        # R2 crittografico: la firma deve verificare con la chiave della CA
        # (è questo che rende vero R3, senza skCA nessuno la falsifica).
        try:
            self.public_key.verify(
                certificate.signature,
                certificate.tbs_certificate_bytes,
                padding.PKCS1v15(),
                certificate.signature_hash_algorithm,
            )
        except Exception:
            return False

        # R5 — revoca (Lab 4)
        if self._store.is_revoked(certificate.serial_number):
            return False

        return True


def verify_certificate_with_crl(
    certificate: x509.Certificate,
    ca_certificate: x509.Certificate,
    crl: x509.CertificateRevocationList | None = None,
    now: datetime.datetime | None = None,
) -> bool:
    """
    Verifica che chiunque può fare con i soli artefatti pubblici —
    certificato, certificato della CA, CRL — senza toccare lo stato
    interno della CA. È l'equivalente di
    `openssl verify -CAfile ca.cert.pem <cert>` più la lettura della CRL;
    è quello che conta per la verificabilità universale (§3.5.2), dato
    che un osservatore esterno non ha accesso a `index.txt`.

    `crl=None` vuol dire "non disponibile", non "nessuna revoca": in quel
    caso torno solo autenticità e validità temporale, e chi chiama deve
    sapere che sullo stato di revoca non so dire nulla. Stesso trattamento
    per una CRL scaduta.
    """
    now = now or datetime.datetime.now(datetime.timezone.utc)

    if not (certificate.not_valid_before_utc <= now <= certificate.not_valid_after_utc):
        return False

    if certificate.issuer != ca_certificate.subject:
        return False

    ca_public_key = ca_certificate.public_key()
    try:
        ca_public_key.verify(
            certificate.signature,
            certificate.tbs_certificate_bytes,
            padding.PKCS1v15(),
            certificate.signature_hash_algorithm,
        )
    except Exception:
        return False

    if crl is not None:
        # una CRL non autentica è peggio di niente: potrebbe essere stata
        # sostituita apposta per nascondere una revoca
        if not crl.is_signature_valid(ca_public_key):
            return False
        if crl.next_update_utc is not None and crl.next_update_utc >= now:
            if is_revoked(crl, certificate):
                return False

    return True
