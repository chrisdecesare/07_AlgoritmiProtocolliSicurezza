"""
Benchmark delle fasi 2, 3 e 4 per WP4 — voto, registrazione, scrutinio.

`bench_ca.py` e `bench_idp.py` coprono il setup pre-elezione (§2.4) e la
Fase 1 (§2.5). Restavano fuori proprio le fasi in cui il protocollo fa il
suo lavoro: l'espressione del voto (§2.6), i controlli del Ballot Server
e la catena di hash (§2.7), la ricostruzione della chiave e lo scrutinio
(§2.8). Questo file le misura, coprendo le quattro categorie che la
traccia di WP4 elenca esplicitamente:

  A. costo computazionale delle operazioni crittografiche;
  B. tempi di interazione (round trip di un elettore);
  C. latenza delle operazioni di verifica, incluso lo scaling di
     `verify_hash_chain` e di `run_scrutiny` al crescere dell'affluenza —
     è la misura che dice quanto costa davvero la verificabilità
     universale promessa in §3.5.2;
  D. dimensione dei messaggi scambiati.

Uso: PYTHONPATH=. python benchmarks/bench_voting.py --iterations 100
"""
from __future__ import annotations

import argparse
import statistics
import time
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

from src.ballot.ballot_server import (
    HEAD_REFERENCE_TOLERANCE,
    BallotServer,
    verify_receipt,
    verify_signed_head,
)
from src.bulletin_board.bulletin_board import BulletinBoard, genesis_head, verify_hash_chain
from src.ca.root_ca import EntityRole, UniversityCA
from src.commission.commission import (
    generate_and_share_decryption_key,
    run_scrutiny,
    sign_tally_bundle,
    verify_tally_bundle,
)
from src.commission.shamir import (
    SHAMIR_THRESHOLD,
    SHAMIR_TOTAL_SHARES,
    reconstruct_secret,
    shamir_prime,
    split_secret,
)
from src.common.ballot_encoding import VOTE_NO, VOTE_YES
from src.common.hashing import sha256
from src.common.keys import RSA_KEY_SIZE_BITS, generate_rsa_keypair, public_key_der
from src.common.manifest import ElectionManifest, sign_manifest, verify_manifest
from src.common.password_hash import hash_password
from src.common.rsa_raw import raw_rsa_oaep_decrypt
from src.idp.identity_provider import IdentityProvider
from src.voter.client import cast_vote, encrypt_ballot, generate_voter_keypair, sign_ballot

ELECTION_ID = "bench-referendum-ateneo"
PASSWORD = "correct horse battery staple"

# Il pool di chiavi elettore serve solo a popolare il Bulletin Board per
# le misure di scaling: generare una coppia RSA-2048 per ognuna delle
# 1000 entry dominerebbe il tempo misurato senza dire nulla su ciò che
# si vuole misurare (la verifica della catena, non il keygen).
VOTER_KEY_POOL_SIZE = 8


@dataclass
class Stats:
    label: str
    unit: str
    samples: list[float]

    def summary(self) -> str:
        mean = statistics.mean(self.samples)
        stdev = statistics.stdev(self.samples) if len(self.samples) > 1 else 0.0
        return (
            f"{self.label:<46} mean={mean:9.4f}{self.unit}  "
            f"stdev={stdev:8.4f}{self.unit}  n={len(self.samples)}"
        )


def timed_ms(fn, iterations: int) -> list[float]:
    samples = []
    for _ in range(iterations):
        start = time.perf_counter()
        fn()
        samples.append((time.perf_counter() - start) * 1000.0)
    return samples


# --------------------------------------------------------------------- #
# Setup: una elezione completa, come in demo_election.py
# --------------------------------------------------------------------- #


class Election:
    """Contesto di elezione riusabile dalle varie misure."""

    def __init__(self) -> None:
        self.ca = UniversityCA(organization_name="Universita degli Studi di Salerno")

        self.idp_signing_key = generate_rsa_keypair()
        self.idp_certificate = self.ca.issue_certificate(
            "idp-token.unisa.it",
            EntityRole.IDP_TOKEN_SIGNING,
            public_key=self.idp_signing_key.public_key(),
        ).certificate
        self.idp = IdentityProvider(
            election_id=ELECTION_ID,
            signing_key=self.idp_signing_key,
            signing_public_key=self.idp_signing_key.public_key(),
        )

        self.decryption_key = generate_and_share_decryption_key()
        self.bs_signing_key = generate_rsa_keypair()

        now = datetime.now(timezone.utc)
        self.opens_at = now - timedelta(minutes=1)
        self.closes_at = now + timedelta(hours=4)

        self.commissioner_keys = [generate_rsa_keypair() for _ in range(SHAMIR_TOTAL_SHARES)]
        self.commissioner_certificates = tuple(
            self.ca.issue_certificate(
                f"commissario-{i}", EntityRole.COMMISSIONER, public_key=key.public_key()
            ).certificate
            for i, key in enumerate(self.commissioner_keys, 1)
        )

        self.manifest = ElectionManifest(
            election_id=ELECTION_ID,
            question="Sei favorevole alla modifica dello statuto di Ateneo?",
            options=(VOTE_YES, VOTE_NO),
            voting_opens_at=self.opens_at,
            voting_closes_at=self.closes_at,
            encryption_public_key=self.decryption_key.public_key,
            pke_scheme="RSA-OAEP",
            pke_modulus_bits=RSA_KEY_SIZE_BITS,
            pke_hash="SHA-256",
            shamir_prime=self.decryption_key.prime,
            shamir_threshold=SHAMIR_THRESHOLD,
            shamir_total_shares=SHAMIR_TOTAL_SHARES,
            bs_signing_public_key=self.bs_signing_key.public_key(),
            idp_signing_public_key=self.idp_signing_key.public_key(),
            commissioner_certificates=self.commissioner_certificates,
            electorate_size=50000,
            idp_endpoint="https://idp.unisa.it/vote",
            ballot_server_endpoint="https://bs.unisa.it/ballots",
            bulletin_board_endpoint="https://bb.unisa.it/",
            idp_tls_certificate=self.ca.issue_certificate(
                "idp.unisa.it", EntityRole.IDP_TLS
            ).certificate,
            bs_tls_certificate=self.ca.issue_certificate(
                "bs.unisa.it", EntityRole.BS_TLS
            ).certificate,
            genesis_head=genesis_head(ELECTION_ID, self.opens_at.isoformat()),
            head_reference_tolerance=HEAD_REFERENCE_TOLERANCE,
            voting_client_hash=sha256(b"client-di-voto-ufficiale-v1"),
        )
        self.signed_manifest = sign_manifest(
            self.manifest, self.commissioner_keys, self.ca.countersign
        )

    def new_ballot_server(self) -> BallotServer:
        return BallotServer(
            election_id=self.manifest.election_id,
            genesis_head=self.manifest.genesis_head,
            signing_key=self.bs_signing_key,
            signing_public_key=self.manifest.bs_signing_public_key,
            idp_certificate=self.idp_certificate,
            ca_certificate=self.ca.certificate,
            voting_opens_at=self.manifest.voting_opens_at,
            voting_closes_at=self.manifest.voting_closes_at,
        )

    def enrolled_token(self, matricola: str):
        """Fase 1 completa per una matricola nuova, restituisce (token, sk_voter)."""
        self.idp.enroll_student(matricola, PASSWORD)
        salt, nonce = self.idp.start_authentication(matricola)
        self.idp.verify_authentication(matricola, sha256(nonce, hash_password(PASSWORD, salt)))
        voter_key = generate_voter_keypair()
        return self.idp.issue_token(matricola, voter_key.public_key()), voter_key


def populate_board(election: Election, count: int, voter_keys) -> BulletinBoard:
    """Bulletin Board con `count` entry reali (ciphertext veri, decifrabili
    con la chiave dell'elezione), senza passare dal BS: qui interessa la
    struttura del registro, non i controlli di §2.7."""
    board = BulletinBoard(election.manifest.genesis_head)
    for i in range(count):
        voter_key = voter_keys[i % len(voter_keys)]
        head_ref = board.current_head
        ciphertext = encrypt_ballot(
            election.manifest.encryption_public_key,
            ELECTION_ID,
            head_ref,
            VOTE_YES if i % 2 == 0 else VOTE_NO,
        )
        board.append(
            ciphertext=ciphertext,
            voter_public_key=voter_key.public_key(),
            token_id=i.to_bytes(16, "big"),
            token_signature=b"\x00" * 256,
            head_ref=head_ref,
            voter_signature=sign_ballot(voter_key, ciphertext, i.to_bytes(16, "big"), head_ref),
        )
    return board


# --------------------------------------------------------------------- #
# Le quattro categorie
# --------------------------------------------------------------------- #


def bench_crypto_cost(election: Election, iterations: int) -> None:
    print("=== A. Costo computazionale delle operazioni crittografiche ===\n")

    pk_bs = election.manifest.encryption_public_key
    voter_key = generate_voter_keypair()
    head_ref = election.manifest.genesis_head

    print(
        Stats(
            "Generazione coppia elettore (RSA-2048)",
            " ms",
            timed_ms(generate_voter_keypair, max(iterations // 4, 5)),
        ).summary()
    )
    print(
        Stats(
            "Cifratura scheda RSA-OAEP (§2.6 passo 4)",
            " ms",
            timed_ms(lambda: encrypt_ballot(pk_bs, ELECTION_ID, head_ref, VOTE_YES), iterations),
        ).summary()
    )

    ciphertext = encrypt_ballot(pk_bs, ELECTION_ID, head_ref, VOTE_YES)
    token_id = b"\x11" * 16
    print(
        Stats(
            "Firma scheda sigma_voter (§2.6 passo 5)",
            " ms",
            timed_ms(lambda: sign_ballot(voter_key, ciphertext, token_id, head_ref), iterations),
        ).summary()
    )

    # Shamir. `shamir_prime` è lru_cache-ata: per misurarne il costo reale
    # va svuotata la cache a ogni giro, altrimenti si misura un hit. Dopo
    # la misura la cache contiene un primo DIVERSO da quello dell'elezione
    # in corso, quindi da qui in poi si usa sempre e solo
    # `election.decryption_key.prime`, mai `shamir_prime()`.
    def fresh_prime():
        shamir_prime.cache_clear()
        shamir_prime()

    print(
        Stats(
            "Generazione primo pubblico p (RSA-6144)",
            " ms",
            timed_ms(fresh_prime, 3),
        ).summary()
    )
    prime = election.decryption_key.prime
    secret = election.decryption_key.shares[0].value  # un intero della taglia giusta
    print(
        Stats(
            "Shamir split_secret (3,5)",
            " ms",
            timed_ms(lambda: split_secret(secret, prime=prime), iterations),
        ).summary()
    )
    shares = election.decryption_key.shares[:SHAMIR_THRESHOLD]
    print(
        Stats(
            "Shamir reconstruct_secret (3 share)",
            " ms",
            timed_ms(lambda: reconstruct_secret(shares, prime), iterations),
        ).summary()
    )

    # Decifratura OAEP a mano, con la sola (N, d) — §2.8.2.
    exponent_d = reconstruct_secret(shares, prime)
    print(
        Stats(
            "Decifratura OAEP a (N,d) — 1 scheda",
            " ms",
            timed_ms(
                lambda: raw_rsa_oaep_decrypt(ciphertext, election.decryption_key.modulus_n, exponent_d),
                iterations,
            ),
        ).summary()
    )
    print()


def bench_interaction(election: Election, iterations: int) -> None:
    print("=== B. Tempi di interazione (lato elettore) ===\n")

    counter = [0]

    def full_round_trip():
        counter[0] += 1
        matricola = f"9{counter[0]:09d}"
        token, voter_key = election.enrolled_token(matricola)
        head_ref = server.current_head_reference()
        ballot = cast_vote(
            token, voter_key, election.manifest.encryption_public_key,
            ELECTION_ID, head_ref, prefer_yes=True,
        )
        server.submit_ballot(ballot)

    server = election.new_ballot_server()
    rounds = max(iterations // 2, 10)
    print(
        Stats(
            "Round trip completo (auth+token+voto+ricevuta)",
            " ms",
            timed_ms(full_round_trip, rounds),
        ).summary()
    )

    # submit_ballot isolata: i 5 controlli di §2.7 + append + ricevuta.
    # È il tempo che il Ballot Server impiega per scheda, cioè il collo di
    # bottiglia lato server durante la finestra di voto. La preparazione
    # della scheda resta fuori dal cronometro; ogni scheda va costruita
    # sulla testa corrente, perché la finestra di tolleranza è di 5 teste
    # e non infinita (§2.7 passo 5).
    server3 = election.new_ballot_server()
    submit_samples: list[float] = []
    for _ in range(rounds):
        counter[0] += 1
        token, voter_key = election.enrolled_token(f"7{counter[0]:09d}")
        head_ref = server3.current_head_reference()
        ballot = cast_vote(
            token, voter_key, election.manifest.encryption_public_key,
            ELECTION_ID, head_ref, prefer_yes=True,
        )
        start = time.perf_counter()
        server3.submit_ballot(ballot)
        submit_samples.append((time.perf_counter() - start) * 1000.0)

    print(Stats("submit_ballot (5 controlli §2.7 + append)", " ms", submit_samples).summary())
    print()


def bench_verification(election: Election, iterations: int, voter_keys) -> None:
    print("=== C. Latenza delle operazioni di verifica ===\n")

    ca_cert = election.ca.certificate
    print(
        Stats(
            "verify_manifest (7 cert. + 5 firme + CA)",
            " ms",
            timed_ms(lambda: verify_manifest(election.signed_manifest, ca_cert), iterations),
        ).summary()
    )

    server = election.new_ballot_server()
    token, voter_key = election.enrolled_token("0522599999")
    head_ref = server.current_head_reference()
    ballot = cast_vote(
        token, voter_key, election.manifest.encryption_public_key,
        ELECTION_ID, head_ref, prefer_yes=True,
    )
    receipt = server.submit_ballot(ballot)
    print(
        Stats(
            "verify_receipt (V.1, lato elettore)",
            " ms",
            timed_ms(
                lambda: verify_receipt(receipt, server.signing_public_key, ballot.ciphertext),
                iterations,
            ),
        ).summary()
    )

    snapshot = server.publish_signed_head(1)
    print(
        Stats(
            "verify_signed_head (osservatore, §2.7.1)",
            " ms",
            timed_ms(
                lambda: verify_signed_head(snapshot, server.signing_public_key), iterations
            ),
        ).summary()
    )
    print()

    print("--- Scaling: verify_hash_chain al crescere dell'affluenza (V.2 punto 3) ---\n")
    print(f"{'schede sul BB':>14}  {'media (ms)':>12}  {'us/scheda':>12}")
    for n in (10, 100, 500, 1000):
        board = populate_board(election, n, voter_keys)
        entries = board.entries
        reps = 20 if n <= 100 else 5
        samples = timed_ms(lambda: verify_hash_chain(board.genesis, entries), reps)
        mean = statistics.mean(samples)
        print(f"{n:>14}  {mean:>12.4f}  {mean * 1000 / n:>12.3f}")
    print()

    print("--- Scaling: run_scrutiny al crescere dell'affluenza (§2.8.2) ---\n")
    shares = election.decryption_key.shares[:SHAMIR_THRESHOLD]
    print(f"{'schede sul BB':>14}  {'totale (ms)':>13}  {'ms/scheda':>12}")
    for n in (10, 50, 100, 250):
        board = populate_board(election, n, voter_keys)
        samples = timed_ms(
            lambda: run_scrutiny(
                ELECTION_ID,
                board.current_head,
                board.entries,
                shares,
                election.decryption_key.prime,
                election.decryption_key.modulus_n,
            ),
            3,
        )
        mean = statistics.mean(samples)
        print(f"{n:>14}  {mean:>13.2f}  {mean / n:>12.3f}")
    print()

    # Verifica del tally bundle: soglia di 3 firme distinte (V.2 punto 8).
    board = populate_board(election, 20, voter_keys)
    bundle = run_scrutiny(
        ELECTION_ID, board.current_head, board.entries, shares,
        election.decryption_key.prime, election.decryption_key.modulus_n,
    )
    participating = election.commissioner_keys[:SHAMIR_THRESHOLD]
    signatures = sign_tally_bundle(bundle, participating)
    pubs = [k.public_key() for k in participating]
    print(
        Stats(
            "verify_tally_bundle (3 firme distinte)",
            " ms",
            timed_ms(lambda: verify_tally_bundle(bundle, pubs, signatures), iterations),
        ).summary()
    )
    print()


def bench_sizes(election: Election, voter_keys) -> None:
    print("=== D. Dimensione dei messaggi scambiati ===\n")

    server = election.new_ballot_server()
    token, voter_key = election.enrolled_token("0522588888")
    head_ref = server.current_head_reference()
    ballot = cast_vote(
        token, voter_key, election.manifest.encryption_public_key,
        ELECTION_ID, head_ref, prefer_yes=True,
    )
    receipt = server.submit_ballot(ballot)
    entry = server.bulletin_board.entries[-1]

    pk_der = len(public_key_der(ballot.voter_public_key))

    print("Token di voto — IssuedToken (§2.5.3, IdP -> elettore)")
    rows = [
        ("token_id", len(token.token_id)),
        ("sigma_token", len(token.signature)),
        ("pk_voter (DER)", pk_der),
    ]
    for label, size in rows:
        print(f"  {label:<34} {size:>6} byte")
    print(f"  {'TOTALE':<34} {sum(s for _, s in rows):>6} byte\n")

    print("Scheda di voto — M_vote (§2.6 passo 6, elettore -> BS)")
    rows = [
        ("token_id", len(ballot.token_id)),
        ("sigma_token", len(ballot.token_signature)),
        ("pk_voter (DER)", pk_der),
        ("C (ciphertext RSA-OAEP)", len(ballot.ciphertext)),
        ("head_ref", len(ballot.head_ref)),
        ("sigma_voter", len(ballot.voter_signature)),
    ]
    for label, size in rows:
        print(f"  {label:<34} {size:>6} byte")
    ballot_total = sum(s for _, s in rows)
    print(f"  {'TOTALE':<34} {ballot_total:>6} byte\n")

    print("Ricevuta — Receipt (§2.7 passo 8, BS -> elettore)")
    rows = [
        ("IDseq (intero, 8 byte)", 8),
        ("head", len(receipt.head)),
        ("sigma_receipt", len(receipt.signature)),
    ]
    for label, size in rows:
        print(f"  {label:<34} {size:>6} byte")
    print(f"  {'TOTALE':<34} {sum(s for _, s in rows):>6} byte\n")

    print("Entry pubblica del Bulletin Board (§2.7 passo 7)")
    entry_size = (
        8 + len(entry.ciphertext) + pk_der + len(entry.token_id)
        + len(entry.token_signature) + len(entry.head_ref)
        + len(entry.voter_signature) + len(entry.head)
    )
    print(f"  {'TOTALE per entry':<34} {entry_size:>6} byte")
    for n in (1000, 10000, 50000):
        print(f"  {'BB con ' + str(n) + ' schede':<34} {entry_size * n / 1_048_576:>6.2f} MiB")
    print()

    manifest_size = len(election.manifest.canonical_bytes())
    signed_size = manifest_size + sum(
        len(s) for s in election.signed_manifest.commissioner_signatures
    ) + len(election.signed_manifest.ca_signature)
    print("Manifest di elezione (§2.4.3, scaricato da ogni client)")
    print(f"  {'canonical_bytes()':<34} {manifest_size:>6} byte")
    print(f"  {'+ 5 firme commissari + firma CA':<34} {signed_size:>6} byte")
    print()


def main(iterations: int) -> None:
    print("=" * 92)
    print(" Benchmark WP4 — Fasi 2, 3 e 4 (voto, registrazione, scrutinio)")
    print("=" * 92)
    print()

    setup_start = time.perf_counter()
    election = Election()
    setup_ms = (time.perf_counter() - setup_start) * 1000.0
    voter_keys = [generate_voter_keypair() for _ in range(VOTER_KEY_POOL_SIZE)]
    print(f"Setup pre-elezione completo (CA + 7 certificati + Shamir + manifest firmato): {setup_ms:.1f} ms\n")

    bench_crypto_cost(election, iterations)
    bench_interaction(election, iterations)
    bench_verification(election, iterations, voter_keys)
    bench_sizes(election, voter_keys)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--iterations", type=int, default=100)
    args = parser.parse_args()
    main(args.iterations)
