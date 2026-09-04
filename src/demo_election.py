"""
Demo end-to-end del protocollo (§2.1): setup, Fase 1 (autenticazione e
token), Fase 2 (espressione del voto), Fase 3 (registrazione nel BB) e
Fase 4 (scrutinio). Mette insieme CA + IdP (già mostrati in demo_setup.py
/ demo_idp.py) con i quattro componenti di questo WP4: Client, Ballot
Server, Bulletin Board, Commissione.

Percorso: 6 studenti si autenticano e ricevono un token; 4 votano (3 Sì,
1 No), uno si astiene; un elettore tenta di rivotare con lo stesso token
(respinto, I.2); un intercettatore tenta di alterare in transito la
scheda firmata del sesto (respinto, I.3); a urne chiuse la Commissione
ricostruisce la chiave con 3 commissari su 5 e pubblica lo scrutinio,
verificabile da chiunque con la sola pk_BS e le firme dei commissari.

Uso: PYTHONPATH=. python3 -m src.demo_election
"""
from __future__ import annotations

from dataclasses import replace
from datetime import datetime, timedelta, timezone

from src.ballot.ballot_server import (
    HEAD_REFERENCE_TOLERANCE,
    BallotServer,
    DuplicateBallotError,
    InvalidBallotSignatureError,
    verify_receipt,
    verify_signed_head,
)
from src.bulletin_board.bulletin_board import genesis_head, verify_hash_chain
from src.ca.root_ca import EntityRole, UniversityCA
from src.commission.commission import (
    generate_and_share_decryption_key,
    run_scrutiny,
    sign_tally_bundle,
    verify_tally_bundle,
)
from src.commission.shamir import SHAMIR_THRESHOLD, SHAMIR_TOTAL_SHARES
from src.common.ballot_encoding import VOTE_NO, VOTE_YES
from src.common.hashing import sha256
from src.common.keys import RSA_KEY_SIZE_BITS, generate_rsa_keypair
from src.common.manifest import (
    ElectionManifest,
    check_turnout_consistency,
    sign_manifest,
    verify_manifest,
)
from src.common.password_hash import hash_password
from src.idp.identity_provider import IdentityProvider
from src.voter.client import cast_vote, generate_voter_keypair

ELECTION_ID = "referendum-ateneo-2026"


def client_response(salt: bytes, nonce: bytes, password: str) -> bytes:
    return sha256(nonce, hash_password(password, salt))


def main() -> None:
    print("=" * 78)
    print(" DEMO END-TO-END — Referendum di Ateneo (WP1-WP2)")
    print("=" * 78)

    # 0. Setup pre-elezione (§2.4): CA, chiave di firma dei token
    #    dell'IdP, chiave di firma del BS, chiave di decifratura
    #    condivisa via Shamir (3,5).
    ca = UniversityCA(organization_name="Universita degli Studi di Salerno")

    idp_signing_key = generate_rsa_keypair()
    idp_certificate = ca.issue_certificate(
        "idp-token.unisa.it", EntityRole.IDP_TOKEN_SIGNING, public_key=idp_signing_key.public_key()
    ).certificate
    idp = IdentityProvider(
        election_id=ELECTION_ID, signing_key=idp_signing_key, signing_public_key=idp_signing_key.public_key()
    )

    print("\n[Commissione] Cerimonia di generazione e condivisione di sk_BS (§2.2.4, §2.4.1)...")
    decryption_key = generate_and_share_decryption_key()
    print(f"  pk_BS generata, modulo N a {decryption_key.modulus_n.bit_length()} bit.")
    print(f"  d condivisa in {len(decryption_key.shares)} share (t={SHAMIR_THRESHOLD}) su Z_p, p a {decryption_key.prime.bit_length()} bit.")
    print("  sk_BS integra non è mai uscita da quella funzione: da qui in poi esistono solo le share.")

    bs_signing_key = generate_rsa_keypair()
    now = datetime.now(timezone.utc)
    opens_at = now - timedelta(minutes=1)
    closes_at = now + timedelta(hours=1)

    # I 5 commissari della cerimonia di §2.2.4: certificati dalla CA, sono
    # loro (tutti, non solo t) a firmare il manifest insieme alla CA.
    commissioner_keys = [generate_rsa_keypair() for _ in range(SHAMIR_TOTAL_SHARES)]
    commissioner_certificates = tuple(
        ca.issue_certificate(f"commissario-{i}", EntityRole.COMMISSIONER, public_key=key.public_key()).certificate
        for i, key in enumerate(commissioner_keys, 1)
    )

    # Manifest di elezione (§2.4.3): fissa il contesto crittografico
    # PRIMA dell'apertura delle urne. Da qui in poi client e osservatori
    # leggono i parametri da qui, non "sulla parola" da IdP o BS.
    manifest = ElectionManifest(
        election_id=ELECTION_ID,
        question="Sei favorevole alla modifica dello statuto di Ateneo?",
        options=(VOTE_YES, VOTE_NO),
        voting_opens_at=opens_at,
        voting_closes_at=closes_at,
        encryption_public_key=decryption_key.public_key,
        pke_scheme="RSA-OAEP",
        pke_modulus_bits=RSA_KEY_SIZE_BITS,
        pke_hash="SHA-256",
        shamir_prime=decryption_key.prime,
        shamir_threshold=SHAMIR_THRESHOLD,
        shamir_total_shares=SHAMIR_TOTAL_SHARES,
        bs_signing_public_key=bs_signing_key.public_key(),
        idp_signing_public_key=idp_signing_key.public_key(),
        commissioner_certificates=commissioner_certificates,
        electorate_size=6,
        idp_endpoint="https://idp.unisa.it/vote",
        ballot_server_endpoint="https://bs.unisa.it/ballots",
        bulletin_board_endpoint="https://bb.unisa.it/",
        idp_tls_certificate=ca.issue_certificate("idp.unisa.it", EntityRole.IDP_TLS).certificate,
        bs_tls_certificate=ca.issue_certificate("bs.unisa.it", EntityRole.BS_TLS).certificate,
        genesis_head=genesis_head(ELECTION_ID, opens_at.isoformat()),
        head_reference_tolerance=HEAD_REFERENCE_TOLERANCE,
        voting_client_hash=sha256(b"client-di-voto-ufficiale-v1"),
    )
    signed_manifest = sign_manifest(manifest, commissioner_keys, ca.countersign)
    print(f"\n[Commissione] Manifest di elezione pubblicato e firmato da {len(commissioner_keys)} commissari + CA (§2.4.3).")

    # Il primo atto di chiunque — client o osservatore — è verificare il
    # manifest: è la radice di fiducia, tutto il resto deriva da qui.
    print(f"[Client/Osservatore] Verifica del manifest prima di ogni interazione: {verify_manifest(signed_manifest, ca.certificate)}")

    ballot_server = BallotServer(
        election_id=manifest.election_id,
        genesis_head=manifest.genesis_head,
        signing_key=bs_signing_key,
        signing_public_key=manifest.bs_signing_public_key,
        idp_certificate=idp_certificate,
        ca_certificate=ca.certificate,
        voting_opens_at=manifest.voting_opens_at,
        voting_closes_at=manifest.voting_closes_at,
    )

    # 1. Registro elettorale (F.6, fuori dal protocollo).
    students = {
        "0522500001": "Tr0ub4dor&3",
        "0522500002": "correct horse battery staple",
        "0522500003": "hunter2-ma-meglio",
        "0522500004": "una password decente",
        "0522500005": "altra password decente",
        "0522500006": "yet-another-decent-password",
    }
    for matricola, password in students.items():
        idp.enroll_student(matricola, password)
    print(f"\n[IdP] Registro elettorale caricato: {len(students)} studenti.")

    # 2-3. Fase 1 (token) + Fase 2 (voto) per quattro studenti; il quinto si astiene.
    print("\n" + "-" * 78)
    print(" Fase 1+2 — Autenticazione, token, voto (§2.5, §2.6)")
    print("-" * 78)

    preferences = {
        "0522500001": True,
        "0522500002": True,
        "0522500003": False,
        "0522500004": True,
    }
    receipts = {}
    for matricola, prefer_yes in preferences.items():
        salt, nonce = idp.start_authentication(matricola)
        idp.verify_authentication(matricola, client_response(salt, nonce, students[matricola]))

        voter_key = generate_voter_keypair()
        token = idp.issue_token(matricola, voter_key.public_key())

        head_ref = ballot_server.current_head_reference()
        ballot = cast_vote(
            token, voter_key, manifest.encryption_public_key, ELECTION_ID, head_ref, prefer_yes=prefer_yes
        )
        receipt = ballot_server.submit_ballot(ballot)
        receipts[matricola] = (ballot, receipt)
        print(
            f"  [{matricola}] voto={'SI' if prefer_yes else 'NO'}  "
            f"IDseq={receipt.id_seq}  ricevuta valida={verify_receipt(receipt, ballot_server.signing_public_key, ballot.ciphertext)}"
        )
    print(f"  [{'0522500005'}] astenuto: non richiede mai un token.")

    # 4. Un elettore tenta di rivotare con lo stesso token (I.2).
    print("\n[Attaccante] Riinvio dello stesso pacchetto di voto di 0522500001 (replay)...")
    first_ballot, _ = receipts["0522500001"]
    try:
        ballot_server.submit_ballot(first_ballot)
        print("  ERRORE: il secondo invio non doveva essere accettato!")
    except DuplicateBallotError as exc:
        print(f"  Rifiutato correttamente (I.2): {exc}")

    # 5. Un intercettatore altera in transito il ciphertext di una scheda
    #    firmata ma non ancora sottomessa (I.3). Serve una scheda fresca:
    #    riusarne una già accettata cadrebbe prima sul controllo di
    #    unicità del passo 3 (token_id già in Used), non su questo.
    print("\n[Intercettatore] Sostituzione di C in una scheda firmata ma non ancora inviata...")
    salt, nonce = idp.start_authentication("0522500006")
    idp.verify_authentication("0522500006", client_response(salt, nonce, students["0522500006"]))
    interceptable_voter_key = generate_voter_keypair()
    interceptable_token = idp.issue_token("0522500006", interceptable_voter_key.public_key())
    interceptable_ballot = cast_vote(
        interceptable_token, interceptable_voter_key, manifest.encryption_public_key,
        ELECTION_ID, ballot_server.current_head_reference(), prefer_yes=True,
    )
    tampered = replace(interceptable_ballot, ciphertext=b"\x00" * len(interceptable_ballot.ciphertext))
    try:
        ballot_server.submit_ballot(tampered)
        print("  ERRORE: la scheda manomessa non doveva essere accettata!")
    except InvalidBallotSignatureError as exc:
        print(f"  Rifiutato correttamente (I.3): {exc}")

    # 6. Verifica universale della catena di hash (V.2, punto 3).
    bb = ballot_server.bulletin_board
    print(
        f"\n[Osservatore] Catena di hash del Bulletin Board ({len(bb.entries)} entry) "
        f"verificata: {verify_hash_chain(bb.genesis, bb.entries)}"
    )

    # 7. Chiusura urne (§2.8, passi 1, 4-5).
    print("\n" + "-" * 78)
    print(" Chiusura urne e scrutinio (§2.8)")
    print("-" * 78)
    final_snapshot = ballot_server.close_voting(final_index=len(bb.entries) + 1)
    print(f"[BS] Testa finale firmata; verifica indipendente: {verify_signed_head(final_snapshot, ballot_server.signing_public_key)}")

    participant_list = idp.close_and_publish_participants()
    print(f"[IdP] Lista partecipanti pubblicata: {participant_list.matricole}")
    idp.destroy_issued_table()
    print("[IdP] Issued distrutta (C.2).")

    # 8. Cerimonia di ricostruzione (§2.8.1) con soli 3 commissari su 5.
    print("\n[Commissione] Ricostruzione di sk_BS con 3 commissari su 5 (C1, C3, C5)...")
    reconstruction_shares = (decryption_key.shares[0], decryption_key.shares[2], decryption_key.shares[4])
    bundle = run_scrutiny(
        ELECTION_ID, final_snapshot.head, bb.entries, reconstruction_shares, decryption_key.prime, decryption_key.modulus_n
    )
    yes_count = bundle.tally.get(VOTE_YES, 0)
    no_count = bundle.tally.get(VOTE_NO, 0)
    print(f"[Commissione] Schede decifrate: {bundle.total_decrypted}  Tally: {{SI: {yes_count}, NO: {no_count}}}")

    # Firmano i 3 commissari che hanno davvero partecipato (C1, C3, C5);
    # l'osservatore preleva le loro chiavi pubbliche dai certificati
    # elencati nel manifest, non da chi gli passa le firme — è la catena
    # manifest -> certificati -> firma del tally che rende eseguibile
    # V.2 punto 8 per chi non ha assistito allo scrutinio.
    scrutiny_indexes = (0, 2, 4)
    scrutiny_keys = [commissioner_keys[i] for i in scrutiny_indexes]
    signatures = sign_tally_bundle(bundle, scrutiny_keys)
    observer_public_keys = [manifest.commissioner_certificates[i].public_key() for i in scrutiny_indexes]
    verified = verify_tally_bundle(bundle, observer_public_keys, signatures, threshold=SHAMIR_THRESHOLD)
    print(f"[Osservatore] Tally bundle verificato con le {SHAMIR_THRESHOLD} firme dei commissari del manifest: {verified}")

    # V.2 punto 9: token emessi vs schede registrate vs cardinalità
    # dichiarata nel manifest prima dell'apertura delle urne (F.5).
    tokens_issued = len(participant_list.matricole)
    print(
        f"[Osservatore] Token emessi={tokens_issued}, schede registrate={len(bb.entries)}, "
        f"aventi diritto dichiarati nel manifest={manifest.electorate_size} -> "
        f"coerenza: {check_turnout_consistency(manifest, tokens_issued, len(bb.entries))}"
    )

    print(
        "\n[Osservatore] Nota: la lista mescolata dei voti decifrati non porta alcun "
        "riferimento a IDseq o pk_voter — nessuno può seguire un singolo voto fino al tally (C.2, C.3)."
    )


if __name__ == "__main__":
    main()
