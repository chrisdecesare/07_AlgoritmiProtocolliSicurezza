"""
Demo della Fase 0 (Setup pre-elezione, §2.4).

Fa vedere la CA al lavoro: emette i certificati di tutti gli attori
(IdP: TLS + firma; BS: TLS + firma; 5 commissari), li verifica, li salva
in PEM e stampa un riepilogo. Il modo più veloce per capire cosa fa la CA
senza leggersi root_ca.py.

Uso: PYTHONPATH=. python3 -m src.demo_setup
"""
from __future__ import annotations

import pathlib

from cryptography.hazmat.primitives import serialization
from cryptography.x509.oid import NameOID

from src.ca.root_ca import EntityRole, IssuedCertificate, UniversityCA

CERTS_DIR = pathlib.Path(__file__).resolve().parent.parent / "certs"


def _save_pem(issued: IssuedCertificate, filename: str) -> pathlib.Path:
    """Salva il certificato (e la chiave privata, se generata dalla CA) su disco."""
    CERTS_DIR.mkdir(exist_ok=True)
    cert_path = CERTS_DIR / f"{filename}.cert.pem"
    cert_path.write_bytes(issued.certificate_pem())

    if issued.private_key is not None:
        key_path = CERTS_DIR / f"{filename}.key.pem"
        key_path.write_bytes(
            issued.private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(),
            )
        )
    return cert_path


def _describe(issued: IssuedCertificate, ca: UniversityCA) -> str:
    """Riga di riepilogo leggibile per un certificato emesso."""
    cert = issued.certificate
    cn = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
    valid = "OK" if ca.verify_certificate(cert) else "FALLITA"
    not_after = cert.not_valid_after_utc.date()
    serial = cert.serial_number
    return f"  [{valid:>7}] {cn:<38} scad. {not_after}  serial={serial:#x}"


def main() -> None:
    print("=" * 78)
    print(" FASE 0 — Setup pre-elezione: la CA di Ateneo emette i certificati")
    print("=" * 78)

    # 1. La CA di Ateneo si costituisce (root self-signed).
    ca = UniversityCA(organization_name="Universita degli Studi di Salerno")
    print(f"\n[CA] Root self-signed creata.")
    root_cn = ca.certificate.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
    print(f"     Subject/Issuer: {root_cn}")
    _save_pem(IssuedCertificate(ca.certificate, None), "00_root_ca")
    print(f"     Salvata in: certs/00_root_ca.cert.pem")

    issued_all: list[tuple[str, IssuedCertificate]] = []

    # 2. Certificati dell'IdP (TLS + firma token).
    print("\n[CA] Emissione certificati per l'Identity Provider (IdP)...")
    idp_tls = ca.issue_certificate(
        "idp.unisa.it", EntityRole.IDP_TLS, organizational_unit="Identity Provider"
    )
    idp_sign = ca.issue_certificate(
        "idp-token.unisa.it", EntityRole.IDP_TOKEN_SIGNING, organizational_unit="Identity Provider"
    )
    issued_all += [("01_idp_tls", idp_tls), ("02_idp_token_signing", idp_sign)]

    # 3. Certificati del Ballot Server (TLS + firma ricevute/teste BB).
    print("[CA] Emissione certificati per il Ballot Server (BS)...")
    bs_tls = ca.issue_certificate(
        "ballot.unisa.it", EntityRole.BS_TLS, organizational_unit="Ballot Server"
    )
    bs_sign = ca.issue_certificate(
        "ballot-sign.unisa.it", EntityRole.BS_SIGNING, organizational_unit="Ballot Server"
    )
    issued_all += [("03_bs_tls", bs_tls), ("04_bs_signing", bs_sign)]

    # 4. Certificati dei 5 commissari (esempio (t,n)=(3,5)).
    print("[CA] Emissione certificati per i 5 commissari...")
    for i in range(1, 6):
        commissioner = ca.issue_certificate(
            f"commissario-{i}.unisa.it",
            EntityRole.COMMISSIONER,
            organizational_unit="Commissione Elettorale",
        )
        issued_all.append((f"05_commissario_{i}", commissioner))

    # 5. Salvataggio + verifica di tutti i certificati.
    print("\n" + "-" * 78)
    print(" Certificati emessi (verifica con la sola chiave pubblica della CA):")
    print("-" * 78)
    for filename, issued in issued_all:
        _save_pem(issued, filename)
        print(_describe(issued, ca))

    # 6. Controprova: un certificato di un'altra CA deve essere RIFIUTATO.
    print("\n" + "-" * 78)
    print(" Controprova di sicurezza:")
    print("-" * 78)
    impostor_ca = UniversityCA(organization_name="Ateneo Impostore")
    forged = impostor_ca.issue_certificate("idp.unisa.it", EntityRole.IDP_TLS)
    rejected = not ca.verify_certificate(forged.certificate)
    print(f"  Certificato falso (altra CA) rifiutato dalla nostra CA: {rejected}")

    print(f"\n  Totale certificati salvati in '{CERTS_DIR}/': {len(issued_all) + 1}")
    print("  (apri i .cert.pem con:  openssl x509 -in <file> -text -noout )\n")


if __name__ == "__main__":
    main()
