"""
Demo della Fase 1 (Autenticazione e token, §2.5) più chiusura urne
(§2.8 passi 2-3).

Percorso: la CA emette il certificato di firma dell'IdP, tre studenti si
iscrivono, uno sbaglia la password due volte prima di indovinarla (senza
scattare il blocco, serve k=3), riceve il token dopo l'autenticazione, un
secondo token per la stessa matricola viene rifiutato (I.2), un altro
studente si becca il rate limiting dopo 3 fallimenti, e infine chiusura
urne con lista firmata dei partecipanti e distruzione di Issued.

Uso: PYTHONPATH=. python3 -m src.demo_idp
"""
from __future__ import annotations

import sys

# Forza stdout/stderr a UTF-8: su Windows la console (cp1252) non sa
# codificare i simboli usati nella notazione del protocollo (σ, ∥, ...)
# che possono comparire nei messaggi di errore.
for _stream in (sys.stdout, sys.stderr):
    try:
        _stream.reconfigure(encoding="utf-8")
    except (AttributeError, ValueError):
        pass

from src.ca.root_ca import EntityRole, UniversityCA
from src.common.hashing import sha256
from src.common.keys import generate_rsa_keypair
from src.common.password_hash import hash_password
from src.idp.identity_provider import (
    IdentityProvider,
    RateLimitedError,
    TokenAlreadyIssuedError,
    verify_destruction_statement,
    verify_participant_list,
    verify_token_as_ballot_server,
)


def client_response(salt: bytes, nonce: bytes, password: str) -> bytes:
    """Calcolo lato client di §2.5.1: response = H(n1 ∥ hpwd), hpwd = H(password ∥ salt)."""
    return sha256(nonce, hash_password(password, salt))


def main() -> None:
    print("=" * 78)
    print(" FASE 1 — Autenticazione e token (§2.5), chiusura urne (§2.8)")
    print("=" * 78)

    # 0. La CA emette la chiave di firma dei token dell'IdP.
    ca = UniversityCA(
        organization_name="Universita degli Studi di Salerno",
        crl_url="http://pki.unisa.it/crl/ateneo.crl.pem",
    )
    signing_key = generate_rsa_keypair()
    idp_certificate = ca.issue_certificate(
        "idp-token.unisa.it",
        EntityRole.IDP_TOKEN_SIGNING,
        public_key=signing_key.public_key(),
        organizational_unit="Identity Provider",
    ).certificate
    print("\n[CA] Certificato di firma dei token dell'IdP emesso (IDP_TOKEN_SIGNING).")

    idp = IdentityProvider(
        election_id="referendum-ateneo-2026",
        signing_key=signing_key,
        signing_public_key=signing_key.public_key(),
    )

    # 1. Iscrizione al registro elettorale (F.6, fuori dal protocollo).
    students = {
        "0522500001": "Tr0ub4dor&3",
        "0522500002": "correct horse battery staple",
        "0522500003": "hunter2-ma-meglio",
    }
    for matricola, password in students.items():
        idp.enroll_student(matricola, password)
    print(f"[IdP] Registro elettorale caricato: {len(students)} studenti.")

    # 2. Autenticazione con un tentativo sbagliato prima di quello giusto.
    matricola = "0522500001"
    print(f"\n[Elettore {matricola}] Primo tentativo con password sbagliata...")
    salt, nonce = idp.start_authentication(matricola)
    ok = idp.verify_authentication(matricola, client_response(salt, nonce, "password-sbagliata"))
    print(f"  Esito: {'OK' if ok else 'RIFIUTATO (atteso)'}")

    print(f"[Elettore {matricola}] Secondo tentativo, questa volta corretto...")
    salt, nonce = idp.start_authentication(matricola)  # nuova nonce: la precedente era single-use
    ok = idp.verify_authentication(matricola, client_response(salt, nonce, students[matricola]))
    print(f"  Esito: {'OK' if ok else 'RIFIUTATO'}")

    # 3. Generazione locale della coppia dell'elettore (§2.5.2) ed
    #    emissione del token (§2.5.3).
    voter_key = generate_rsa_keypair()
    token = idp.issue_token(matricola, voter_key.public_key())
    print(f"[IdP] Token emesso: token_id={token.token_id.hex()}  firma valida={idp.verify_token(token)}")

    # 4. Un secondo token per la stessa matricola viene rifiutato (I.2).
    print(
        f"\n[ATTACCANTE - DOUBLE TOKEN REQUEST] L'elettore {matricola} (o chi ne ha "
        "rubato la sessione) tenta di farsi emettere un secondo token dopo averne "
        "gia' ricevuto uno, nel tentativo di ottenere due possibilita' di voto. "
        "Proprieta' attaccata: unicita' (I.2)..."
    )
    salt, nonce = idp.start_authentication(matricola)
    idp.verify_authentication(matricola, client_response(salt, nonce, students[matricola]))
    try:
        idp.issue_token(matricola, generate_rsa_keypair().public_key())
        print("  ERRORE: il secondo token non doveva essere emesso!")
    except TokenAlreadyIssuedError as exc:
        print(f"  Rifiutato correttamente - unicita' preservata (I.2): {exc}")

    # 5. Rate limiting: 3 password sbagliate consecutive per un altro studente.
    victim = "0522500002"
    print(
        f"\n[ATTACCANTE - BRUTE FORCE] 3 tentativi consecutivi di password errata "
        f"sulla matricola {victim}, nel tentativo di indovinarne le credenziali per "
        "autenticazione. Proprieta' attaccata: resistenza al brute-force (§2.5.1)..."
    )
    for i in range(3):
        salt, nonce = idp.start_authentication(victim)
        idp.verify_authentication(victim, client_response(salt, nonce, f"tentativo-{i}"))
    try:
        idp.start_authentication(victim)
        print("  ERRORE: l'IdP doveva bloccare la matricola dopo 3 fallimenti!")
    except RateLimitedError as exc:
        print(f"  Bloccato correttamente - rate limit scattato (§2.5.1): {exc}")

    # 6. Chiusura urne: lo studente 0522500003 non vota mai (astenuto).
    print("\n" + "-" * 78)
    print(" Chiusura urne (§2.8, passi 2-3)")
    print("-" * 78)
    participant_list = idp.close_and_publish_participants()
    print(f"[IdP] Lista partecipanti pubblicata e firmata: {participant_list.matricole}")
    print(f"      Verifica con pkIdP (osservatore indipendente): "
          f"{verify_participant_list(idp.signing_public_key, participant_list)}")
    print(f"      '0522500003' (astenuto) presente in lista: "
          f"{'0522500003' in participant_list.matricole} (atteso: False)")

    statement = idp.destroy_issued_table()
    print(f"[IdP] Issued distrutta; dichiarazione firmata alle {statement.timestamp.isoformat()}")
    print(f"      Verifica con pkIdP: {verify_destruction_statement(idp.signing_public_key, statement)}")

    # 7. Fine vita della chiave elettorale (§2.4.2): la CA la revoca e
    #    pubblica la CRL nuova.
    print("\n" + "-" * 78)
    print(" Revoca della chiave elettorale dell'IdP (§2.4.2)")
    print("-" * 78)

    crl_before = ca.current_crl()
    print("[BS] Token accettato prima della revoca: "
          f"{verify_token_as_ballot_server(token, idp_certificate, ca.certificate, crl_before)}")

    ca.revoke_certificate(idp_certificate)
    crl_after = ca.current_crl()
    print(f"[CA] Certificato {idp_certificate.serial_number:#x} revocato; CRL rigenerata "
          f"({len(crl_after)} voce/i).")

    print("[BS] Token accettato dopo la revoca:     "
          f"{verify_token_as_ballot_server(token, idp_certificate, ca.certificate, crl_after)} "
          f"(atteso: False)")
    print(f"     La firma resta però matematicamente valida: {idp.verify_token(token)}")
    print("     A cambiare non è la crittografia ma lo stato del certificato.\n")


if __name__ == "__main__":
    main()
