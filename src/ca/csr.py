"""
CSR - Certificate Signing Request (PKCS#10) — passi 1-2 di "PKI – Certification" : il
soggetto genera la coppia in locale e chiede alla CA di certificare
(subject_ID, public_key).

La CSR è autofirmata dal richiedente: è la prova che possiede davvero la
chiave privata corrispondente, non solo un'affermazione. Senza questo
controllo chiunque potrebbe chiedere un certificato per la chiave
pubblica di qualcun altro spacciandola per propria.
`UniversityCA.issue_certificate_from_csr` la verifica prima di firmare.
"""
from __future__ import annotations

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey
from cryptography.x509.oid import NameOID


def create_csr(
    common_name: str,
    private_key: RSAPrivateKey,
    organization_name: str,
    organizational_unit: str | None = None,
    country_name: str = "IT",
) -> x509.CertificateSigningRequest:
    """
    Costruisce e autofirma la CSR (passi 1-2 auth e validazione di "PKI – Certification").

    Il chiamante genera la coppia altrove (tipicamente con
    `generate_rsa_keypair`) e passa qui solo `private_key`; la chiave
    privata non lascia mai il processo del soggetto, viaggia solo la CSR.
    Il DN (CN/O/OU/C) è lo stesso schema che usa `UniversityCA`, così può
    controllare che l'organizzazione dichiarata sia la propria.
    """
    name_attributes = [
        x509.NameAttribute(NameOID.COUNTRY_NAME, country_name),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, organization_name),
    ]
    if organizational_unit is not None:
        name_attributes.append(
            x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, organizational_unit)
        )
    name_attributes.append(x509.NameAttribute(NameOID.COMMON_NAME, common_name))

    builder = x509.CertificateSigningRequestBuilder().subject_name(x509.Name(name_attributes))
    return builder.sign(private_key, hashes.SHA256())


def csr_proves_key_possession(csr: x509.CertificateSigningRequest) -> bool:
    """
    Proof of possession: se la firma della CSR verifica con la chiave
    pubblica che contiene, chi l'ha creata controllava davvero la privata.
    È solo un alias di `csr.is_signature_valid` con un nome che dice a chi
    legge `root_ca.py` perché quel controllo viene fatto.
    """
    return csr.is_signature_valid
