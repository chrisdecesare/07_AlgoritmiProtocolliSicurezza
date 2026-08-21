"""
CA universitaria — simulazione minimale della PKI preesistente assunta in
07_APS_1 §2.3 ("PKI universitaria preesistente").

Aderenza al materiale del corso (slide 06_Key_Distribution):
    - Un certificato è (chiave pubblica + identificatore del proprietario +
      firma digitale della CA), come da scheda "Public Key Certificates".
    - Il processo di certificazione segue i 6 passi della scheda
      "PKI – Certification": (1) il soggetto genera la coppia di chiavi,
      (2) chiede la certificazione di (subject_ID, public_key), (3) la CA
      AUTENTICA il soggetto verificando che l'ID gli appartenga, (4) la CA
      firma (subject_ID, public_key), (5) allega la firma, (6) restituisce
      il certificato. I passi 1-2 sono modellati in `src/ca/csr.py`; il
      passo 3 è discusso in `issue_certificate` (vedi nota sul punto di
      autenticazione); i passi 4-6 sono qui.
    - La verifica soddisfa i 4 "Requirements" della slide omonima:
      leggibilità di nome+chiave, autenticità (firma CA), esclusività di
      emissione, validità temporale. Vedi `verify_certificate`.

Scope dichiarato (semplificazioni rispetto alle slide, tutte consapevoli):
    - Una sola CA di Ateneo, self-signed: le slide trattano catene e
      gerarchie di CA ("PKI – Certificate Chains", "CA Hierarchies"), qui
      non necessarie perché il documento assume "una CA di Ateneo" singola.
    - Nessuna CRL/OCSP: le slide dedicano due schede alla revoca
      ("PKI – Revocation", "Certificate Revocation List"), ma nel contesto
      di una singola elezione la finestra di validità è così breve che la
      revoca non è operativamente rilevante. Esclusione consapevole, non
      per omissione — da dichiarare così in WP4.

Questo modulo NON rappresenta una scelta di design originale del protocollo:
implementa un'assunzione di fiducia che WP2 dà per acquisita. Il suo unico
scopo è rendere eseguibile il prototipo, fornendo certificati verificabili
a IdP, Ballot Server e commissari.
"""
from __future__ import annotations

import datetime
import enum
from dataclasses import dataclass

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric.rsa import (
    RSAPrivateKey,
    RSAPublicKey,
)
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from src.common.keys import generate_rsa_keypair

ONE_DAY = datetime.timedelta(days=1)


class EntityRole(enum.Enum):
    """
    Ruoli previsti dal modello (07_APS_1 §2.3, §2.4) per cui la CA emette
    certificati. Ogni ruolo determina Key Usage / Extended Key Usage
    differenti: non tutti gli attori hanno bisogno delle stesse capacità
    crittografiche, e concedere più permessi del necessario violerebbe il
    principio di least privilege che il resto del protocollo rispetta
    (vedi separazione IdP/BS nel documento).
    """

    IDP_TLS = "idp_tls"                # canale autenticato elettore <-> IdP
    IDP_TOKEN_SIGNING = "idp_signing"  # pkIdP_BS, firma cieca del token
    BS_TLS = "bs_tls"                  # canale autenticato elettore <-> BS
    BS_SIGNING = "bs_signing"          # pkBS-server, firma ricevute/teste BB
    COMMISSIONER = "commissioner"      # firma manifest + cifratura share Shamir


@dataclass(frozen=True)
class IssuedCertificate:
    """Coppia (certificato, chiave privata del soggetto) restituita alla CA."""

    certificate: x509.Certificate
    private_key: RSAPrivateKey

    def certificate_pem(self) -> bytes:
        from cryptography.hazmat.primitives import serialization

        return self.certificate.public_bytes(serialization.Encoding.PEM)


class UniversityCA:
    """
    CA di Ateneo, self-signed, che emette certificati leaf per gli attori
    del sistema di voto.

    Nota sulla cerimonia: nel mondo reale la chiave privata della root
    andrebbe generata e custodita offline (analogamente alla cerimonia
    descritta in 07_APS_1 §2.4.1 per skAE). Nel prototipo la teniamo in
    memoria per semplicità implementativa; questa è una semplificazione
    dichiarata, non una proprietà di sicurezza del protocollo.
    """

    ROOT_VALIDITY = 365 * ONE_DAY          # vita della root, non della singola elezione
    LEAF_VALIDITY = 30 * ONE_DAY           # commisurata alla durata di una elezione

    def __init__(self, organization_name: str = "Universita degli Studi - Ateneo"):
        self._organization_name = organization_name
        self._private_key: RSAPrivateKey = generate_rsa_keypair()
        self._certificate: x509.Certificate = self._self_sign_root()

    # ------------------------------------------------------------------ #
    # Root
    # ------------------------------------------------------------------ #

    def _self_sign_root(self) -> x509.Certificate:
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
            .add_extension(
                # CA:true, nessuna intermedia consentita (path_length=0):
                # scelta coerente con "una sola CA di Ateneo" del documento.
                x509.BasicConstraints(ca=True, path_length=0),
                critical=True,
            )
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True,
                    key_cert_sign=True,
                    crl_sign=False,  # nessuna CRL: scelta di scope dichiarata
                    content_commitment=False,
                    key_encipherment=False,
                    data_encipherment=False,
                    key_agreement=False,
                    encipher_only=False,
                    decipher_only=False,
                ),
                critical=True,
            )
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

    # ------------------------------------------------------------------ #
    # Emissione certificati leaf
    # ------------------------------------------------------------------ #

    def _key_usage_for_role(self, role: EntityRole) -> x509.KeyUsage:
        """
        Ogni ruolo riceve solo le capacità crittografiche che gli servono
        nel protocollo (least privilege a livello di certificato, non solo
        a livello di attore):

        - IDP_TLS / BS_TLS: digital_signature + key_encipherment, tipiche
          di un certificato TLS server (handshake autenticato).
        - IDP_TOKEN_SIGNING / BS_SIGNING: solo digital_signature — sono
          chiavi single-purpose per firma (token, ricevute, teste BB),
          coerentemente con la motivazione di isolamento del rischio
          data in 07_APS_1 §2.4.2 per pkIdP_BS.
        - COMMISSIONER: digital_signature (firma del manifest, firma
          persistente skAE_sig) + key_encipherment (destinatario della
          cifratura ibrida delle share Shamir, §2.4.1). Il documento
          stesso riusa qui il certificato di Ateneo per entrambi gli
          scopi: è una semplificazione ereditata dalla specifica, non
          introdotta da questa implementazione.
        """
        if role in (EntityRole.IDP_TLS, EntityRole.BS_TLS):
            return x509.KeyUsage(
                digital_signature=True,
                key_encipherment=True,
                content_commitment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            )
        if role in (EntityRole.IDP_TOKEN_SIGNING, EntityRole.BS_SIGNING):
            return x509.KeyUsage(
                digital_signature=True,
                content_commitment=True,  # non-repudiation: firme su token/ricevute/teste
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            )
        if role is EntityRole.COMMISSIONER:
            return x509.KeyUsage(
                digital_signature=True,
                content_commitment=True,
                key_encipherment=True,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            )
        raise ValueError(f"Ruolo non riconosciuto: {role}")

    def _extended_key_usage_for_role(self, role: EntityRole) -> x509.ExtendedKeyUsage | None:
        if role in (EntityRole.IDP_TLS, EntityRole.BS_TLS):
            return x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH])
        return None  # firma/commissario: EKU non applicabile, KeyUsage basta

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
        Emette un certificato leaf per un soggetto (IdP, BS, commissario),
        seguendo i 6 passi di "PKI – Certification" (slide 06):

            (1-2) il soggetto genera la coppia e chiede la certificazione:
                  se `public_key` è fornita, questi passi sono già avvenuti
                  altrove (vedi src/ca/csr.py); se è None, per comodità di
                  test la CA genera qui la coppia e restituisce anche la
                  privata — scorciatoia di prototipo, MAI accettabile in un
                  deployment reale (la CA non deve mai vedere la privata).
            (3)   la CA AUTENTICA il soggetto: verifica che l'ID gli
                  appartenga davvero. Nel prototipo questo controllo è
                  simulato dal flag `subject_authenticated`; in un sistema
                  reale qui avverrebbe la verifica dell'identità (es. il
                  soggetto si presenta di persona alla segreteria, o esibisce
                  credenziali istituzionali). Se il soggetto non è
                  autenticato la CA rifiuta di emettere — è il passo che
                  distingue una CA da un semplice "oracolo di firma".
            (4-6) la CA firma (subject_ID, public_key), allega la firma e
                  restituisce il certificato: parte finale di questo metodo.

        Il DN segue lo schema mostrato nelle slide (CN/O/OU/C).
        """
        if not subject_authenticated:
            # Passo 3 delle slide: senza autenticazione dell'ID del soggetto
            # la CA non emette. Firmare comunque significherebbe certificare
            # un legame (ID, chiave) non verificato, vanificando la fiducia
            # su cui l'intera PKI si regge ("The certification process is
            # based on trust", slide "PKI - CAs").
            raise PermissionError(
                f"Soggetto '{common_name}' non autenticato: la CA non emette "
                f"certificati per identità non verificate (PKI-Certification, passo 3)."
            )

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
        now = datetime.datetime.now(datetime.timezone.utc)
        validity = validity or self.LEAF_VALIDITY

        builder = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(self._certificate.subject)
            .public_key(public_key)
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - ONE_DAY)
            .not_valid_after(now + validity)
            .add_extension(
                x509.BasicConstraints(ca=False, path_length=None),
                critical=True,
            )
            .add_extension(self._key_usage_for_role(role), critical=True)
            .add_extension(
                x509.SubjectKeyIdentifier.from_public_key(public_key),
                critical=False,
            )
            .add_extension(
                x509.AuthorityKeyIdentifier.from_issuer_public_key(self.public_key),
                critical=False,
            )
        )

        eku = self._extended_key_usage_for_role(role)
        if eku is not None:
            builder = builder.add_extension(eku, critical=False)

        certificate = builder.sign(self._private_key, hashes.SHA256())
        return IssuedCertificate(certificate=certificate, private_key=subject_private_key)

    # ------------------------------------------------------------------ #
    # Verifica
    # ------------------------------------------------------------------ #

    def verify_certificate(self, certificate: x509.Certificate) -> bool:
        """
        Verifica un certificato secondo i 4 "Requirements" della slide 06
        (scheda "Requirements"). Chiunque (elettore, osservatore) esegue
        questo controllo usando solo la chiave pubblica della CA distribuita
        nel manifest — nessun segreto è richiesto (verificabilità universale,
        §3.5.2). I quattro requisiti:

            R1. "Any participant can read a certificate to determine the name
                and public key of the certificate's owner" — garantito dal
                fatto che subject e public_key sono campi leggibili in chiaro
                del certificato (non serve codice qui: è una proprietà del
                formato X.509, verificabile da chiunque via cert.subject /
                cert.public_key()).
            R2. "Any participant can verify that the certificate originated
                from the CA and is not counterfeit" — controllo della firma
                della CA sotto (RSA hash-and-sign, slide 05): si ricalcola
                l'hash del tbsCertificate e si verifica la firma con la
                chiave pubblica della CA. Se il certificato è contraffatto o
                emesso da un'altra CA, la verifica fallisce.
            R3. "Only the CA can create and update certificates" — non è un
                controllo lato verificatore ma una proprietà garantita da
                R2: senza la chiave privata della CA nessuno può produrre una
                firma che superi R2. La verifica di R2 fa quindi rispettare
                R3 di riflesso.
            R4. "Any participant can verify the time validity of the
                certificate" — controllo not_valid_before / not_valid_after
                sotto.

        Restituisce True solo se R2 e R4 sono soddisfatti (R1 e R3 sono
        strutturali). Il match issuer==subject-della-CA è un pre-filtro che
        rende esplicito R2 prima ancora della verifica crittografica.
        """
        now = datetime.datetime.now(datetime.timezone.utc)

        # R4 — validità temporale
        if not (certificate.not_valid_before_utc <= now <= certificate.not_valid_after_utc):
            return False

        # R2 (pre-filtro) — l'issuer dichiarato deve essere questa CA
        if certificate.issuer != self._certificate.subject:
            return False

        # R2 (crittografico) — la firma deve verificare con la chiave della CA.
        # Questo è ciò che rende R3 effettivo: senza skCA nessuno la produce.
        try:
            self.public_key.verify(
                certificate.signature,
                certificate.tbs_certificate_bytes,
                padding.PKCS1v15(),
                certificate.signature_hash_algorithm,
            )
        except Exception:
            return False

        return True
