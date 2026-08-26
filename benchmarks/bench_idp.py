"""
Benchmark dell'IdP per WP4, stesso spirito di bench_ca.py: costo della
Fase 1 (§2.5) e della chiusura (§2.8).

Misura: cerimonia di autenticazione, emissione token, verifica token
lato BS, pubblicazione + verifica della lista partecipanti. Passa
sempre dall'API pubblica di `IdentityProvider`, niente scorciatoie
sullo stato interno.

Uso: PYTHONPATH=. python3 benchmarks/bench_idp.py --iterations 200
"""
from __future__ import annotations

import argparse
import statistics
import time
from dataclasses import dataclass

from src.common.hashing import sha256
from src.common.keys import generate_rsa_keypair
from src.common.password_hash import hash_password
from src.idp.identity_provider import IdentityProvider, verify_participant_list

PASSWORD = "correct horse battery staple"


@dataclass
class Stats:
    label: str
    unit: str
    samples: list[float]

    def summary(self) -> str:
        mean = statistics.mean(self.samples)
        stdev = statistics.stdev(self.samples) if len(self.samples) > 1 else 0.0
        return (
            f"{self.label:<40} mean={mean:8.4f}{self.unit}  "
            f"stdev={stdev:8.4f}{self.unit}  n={len(self.samples)}"
        )


def timed_ms(fn, iterations: int) -> list[float]:
    samples = []
    for _ in range(iterations):
        start = time.perf_counter()
        fn()
        samples.append((time.perf_counter() - start) * 1000.0)
    return samples


def _client_response(salt: bytes, nonce: bytes, password: str = PASSWORD) -> bytes:
    """Simula il calcolo lato client di §2.5.1: response = H(n1 ∥ hpwd)."""
    return sha256(nonce, hash_password(password, salt))


def run_benchmarks(iterations: int) -> None:
    signing_key = generate_rsa_keypair()
    idp = IdentityProvider(
        election_id="bench-election",
        signing_key=signing_key,
        signing_public_key=signing_key.public_key(),
    )

    # Due gruppi separati: uno solo si autentica (mai un token), l'altro
    # riceve anche il token e finisce nella lista dei partecipanti.
    auth_only_matricole = [f"bench-auth-{i}" for i in range(iterations)]
    issuance_matricole = [f"bench-issue-{i}" for i in range(iterations)]
    for matricola in auth_only_matricole + issuance_matricole:
        idp.enroll_student(matricola, PASSWORD)

    # 1. Cerimonia di autenticazione completa (start + verify).
    auth_iter = iter(auth_only_matricole)

    def full_ceremony():
        matricola = next(auth_iter)
        salt, nonce = idp.start_authentication(matricola)
        idp.verify_authentication(matricola, _client_response(salt, nonce))

    ceremony_samples = timed_ms(full_ceremony, iterations)

    # 2. Emissione: autenticazione + issue_token insieme, come vuole
    #    l'API (I.1 richiede l'una prima dell'altro).
    issue_iter = iter(issuance_matricole)
    voter_keys = [generate_rsa_keypair() for _ in range(iterations)]

    def authenticate_and_issue(key_box=[0]):
        matricola = next(issue_iter)
        salt, nonce = idp.start_authentication(matricola)
        idp.verify_authentication(matricola, _client_response(salt, nonce))
        idp.issue_token(matricola, voter_keys[key_box[0]].public_key())
        key_box[0] += 1

    issuance_samples = timed_ms(authenticate_and_issue, iterations)

    # 3. Verifica token (lato BS) — non muta stato, riuso lo stesso token.
    idp.enroll_student("bench-verify-target", PASSWORD)
    salt, nonce = idp.start_authentication("bench-verify-target")
    idp.verify_authentication("bench-verify-target", _client_response(salt, nonce))
    sample_token = idp.issue_token("bench-verify-target", generate_rsa_keypair().public_key())
    verification_samples = timed_ms(lambda: idp.verify_token(sample_token), iterations)

    # 4. Lista partecipanti (§2.8): a questo punto issuance_matricole ha
    #    tutti un token, auth_only_matricole no.
    publish_start = time.perf_counter()
    participant_list = idp.close_and_publish_participants()
    publish_ms = (time.perf_counter() - publish_start) * 1000.0
    verify_list_samples = timed_ms(
        lambda: verify_participant_list(idp.signing_public_key, participant_list), iterations
    )

    print("=== Benchmark IdP — costo computazionale (WP4) ===\n")
    print(Stats("Cerimonia di autenticazione (start+verify)", " ms", ceremony_samples).summary())
    print(Stats("Emissione token (auth + issue)", " ms", issuance_samples).summary())
    print(Stats("Verifica token (lato BS)", " ms", verification_samples).summary())
    print(Stats("Verifica lista partecipanti firmata", " ms", verify_list_samples).summary())
    print()
    print("=== Costo one-shot e dimensione messaggi (chiusura urne) ===\n")
    n_participants = len(participant_list.matricole)
    print(f"{'Pubblicazione lista partecipanti (n=' + str(n_participants) + ')':<40} {publish_ms:8.4f} ms")
    print(f"{'Dimensione payload firmato della lista':<40} {len(participant_list.signed_payload())} byte")
    print(f"{'Elettori astenuti (non in lista)':<40} {len(auth_only_matricole)}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--iterations", type=int, default=100)
    args = parser.parse_args()
    run_benchmarks(args.iterations)
