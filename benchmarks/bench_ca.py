"""
Benchmark delle prestazioni della CA, per la sezione WP4 ("Mostrare anche le
prestazioni ottenute con la sperimentazione, come il costo computazionale
delle operazioni crittografiche, la dimensione dei messaggi scambiati, la
latenza delle operazioni di verifica") — cfr. traccia ufficiale del project
work.

Misura:
    - costo di generazione di una coppia RSA-2048 (operazione ripetuta per
      ogni soggetto certificato: IdP, BS, ciascun commissario);
    - costo di emissione di un certificato (firma della CA);
    - costo di verifica di un certificato (lato client/elettore, eseguita
      potenzialmente molte volte durante la verifica universale);
    - dimensione su filo di un certificato (PEM e DER), rilevante per il
      calcolo della dimensione del manifest che li include.

Uso:
    PYTHONPATH=. python3 benchmarks/bench_ca.py --iterations 200
"""
from __future__ import annotations

import argparse
import statistics
import time
from dataclasses import dataclass

from cryptography.hazmat.primitives import serialization

from src.ca.root_ca import EntityRole, UniversityCA
from src.common.keys import generate_rsa_keypair


@dataclass
class Stats:
    label: str
    unit: str
    samples: list[float]

    def summary(self) -> str:
        mean = statistics.mean(self.samples)
        stdev = statistics.stdev(self.samples) if len(self.samples) > 1 else 0.0
        return (
            f"{self.label:<32} mean={mean:8.4f}{self.unit}  "
            f"stdev={stdev:8.4f}{self.unit}  n={len(self.samples)}"
        )


def timed_ms(fn, iterations: int) -> list[float]:
    samples = []
    for _ in range(iterations):
        start = time.perf_counter()
        fn()
        samples.append((time.perf_counter() - start) * 1000.0)
    return samples


def run_benchmarks(iterations: int) -> None:
    ca = UniversityCA(organization_name="Universita Benchmark")

    # 1. Generazione chiave RSA-2048 (indipendente dalla CA, ma è il costo
    #    sostenuto da ciascun soggetto - IdP, BS, ogni commissario - prima
    #    di richiedere la certificazione).
    keygen_samples = timed_ms(generate_rsa_keypair, iterations)

    # 2. Emissione certificato (lato CA): chiave già generata a parte per
    #    isolare il costo della sola firma X.509, non del keygen.
    pending_keys = [generate_rsa_keypair() for _ in range(iterations)]

    def issue_one(idx_box=[0]):
        key = pending_keys[idx_box[0]]
        idx_box[0] += 1
        ca.issue_certificate(
            f"bench-subject-{idx_box[0]}.ateneo.it",
            EntityRole.IDP_TLS,
            public_key=key.public_key(),
        )

    issuance_samples = timed_ms(issue_one, iterations)

    # 3. Verifica certificato (lato elettore/osservatore, ripetuta per ogni
    #    certificato incontrato durante la verifica universale: IdP, BS,
    #    ciascun commissario).
    sample_cert = ca.issue_certificate("verify-target.ateneo.it", EntityRole.BS_SIGNING).certificate
    verification_samples = timed_ms(lambda: ca.verify_certificate(sample_cert), iterations)

    # 4. Dimensione del certificato (rilevante per il calcolo della
    #    dimensione totale del manifest che include n=5 certificati
    #    commissario + 2 certificati server).
    pem_size = len(sample_cert.public_bytes(serialization.Encoding.PEM))
    der_size = len(sample_cert.public_bytes(serialization.Encoding.DER))

    print("=== Benchmark CA — costo computazionale (WP4) ===\n")
    print(Stats("Generazione chiave RSA-2048", " ms", keygen_samples).summary())
    print(Stats("Emissione certificato (firma CA)", " ms", issuance_samples).summary())
    print(Stats("Verifica certificato", " ms", verification_samples).summary())
    print()
    print("=== Dimensione messaggi ===\n")
    print(f"{'Certificato singolo (PEM)':<32} {pem_size} byte")
    print(f"{'Certificato singolo (DER)':<32} {der_size} byte")
    manifest_certs = 2 + 5  # IdP + BS + 5 commissari, come da esempio (t,n)=(3,5)
    print(f"{'Stima certificati nel manifest':<32} {manifest_certs} cert. "
          f"({manifest_certs * der_size} byte in DER)")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--iterations", type=int, default=100)
    args = parser.parse_args()
    run_benchmarks(args.iterations)
