# E-Voting — Prototipo (WP4)

Prototipo del sistema di voto elettronico progettato in WP1–WP3
(`07_APS_1.pdf`). È un ambiente simulato stand-alone, come chiede la
traccia — non un'infrastruttura reale, non un'app mobile.

## Struttura del progetto

```
evoting-project/
├── NOTES.md               # Note di sviluppo, stato di avanzamento, decisioni di scope
├── README.md              # Questo file
├── requirements.txt       # Dipendenze (cryptography, pytest)
│
├── src/                   # Codice sorgente del sistema (il TUO codice)
│   ├── common/
│   │   ├── keys.py            # Generazione chiavi RSA-2048 condivisa fra gli attori
│   │   ├── hashing.py         # sha256(*chunks) — hashing condiviso
│   │   ├── signing.py         # sign/verify RSA hash-and-sign (PKCS1v15 + SHA-256)
│   │   └── password_hash.py   # Salted password hashing (§2.2.5)
│   ├── ca/
│   │   ├── root_ca.py     # Certification Authority di Ateneo (FATTO)
│   │   ├── csr.py         # CSR (PKCS#10) + verifica proof-of-possession
│   │   ├── profiles.py    # Profili di estensioni X.509 (sezioni di openssl.cnf, Lab 4)
│   │   ├── store.py       # Database index.txt / serial / crlnumber (Lab 4)
│   │   └── crl.py         # Revoca e Certificate Revocation List (Lab 4, §2.4.2)
│   ├── idp/
│   │   └── identity_provider.py  # Autenticazione + token (§2.5), chiusura (§2.8) (FATTO)
│   ├── demo_setup.py      # Demo eseguibile della Fase 0 (setup pre-elezione)
│   └── demo_idp.py        # Demo eseguibile della Fase 1 + chiusura urne + revoca
│
├── tests/
│   ├── test_ca.py         # Test della CA (8 casi)
│   ├── test_csr.py        # Test CSR/proof-of-possession (6 casi)
│   ├── test_idp.py        # Test dell'IdP (12 casi)
│   └── test_crl.py        # Test revoca/CRL e verifica token lato BS (18 casi)
│
├── benchmarks/
│   ├── bench_ca.py        # Misure di prestazione della CA (per WP4)
│   └── bench_idp.py       # Misure di prestazione dell'IdP (per WP4)
│
└── certs/                 # Certificati generati dalla demo (output, .pem)
```

Un package per ogni attore del protocollo (CA, IdP, e in futuro Ballot
Server, Bulletin Board, Commissione, Voter); le primitive condivise
(chiavi, hash, firma, password hashing) stanno in `src/common/`. Per ora
ci sono **CA** e **IdP**.

## Installazione

```bash
pip install -r requirements.txt
```

## Come eseguire

Tutti i comandi vanno lanciati dalla cartella `evoting-project/`, con
`PYTHONPATH=.` (dice a Python di cercare i package dentro `src/`).

**1. Vedere la CA al lavoro (demo Fase 0):**
```bash
PYTHONPATH=. python3 -m src.demo_setup
```
Emette i certificati per IdP, Ballot Server e i 5 commissari, li verifica,
li salva in `certs/` e mostra una controprova (un certificato falso viene
rifiutato).

**2. Ispezionare un certificato prodotto** (richiede OpenSSL da riga di comando):
```bash
openssl x509 -in certs/01_idp_tls.cert.pem -text -noout
```

**3. Vedere l'IdP al lavoro (demo Fase 1 + chiusura urne):**
```bash
PYTHONPATH=. python3 -m src.demo_idp
```
Mostra l'intera cerimonia §2.5 (autenticazione con tentativo sbagliato,
emissione del token, rifiuto di un secondo token per la stessa matricola,
rate limiting dopo 3 fallimenti) e la chiusura §2.8 (lista firmata dei
partecipanti che esclude gli astenuti, distruzione firmata di `Issued`),
entrambe verificate da un "osservatore" che possiede solo la chiave
pubblica dell'IdP.

**4. Eseguire i test:**
```bash
PYTHONPATH=. python3 -m pytest tests/ -v
```

**5. Misurare le prestazioni (per WP4):**
```bash
PYTHONPATH=. python3 benchmarks/bench_ca.py --iterations 200
PYTHONPATH=. python3 benchmarks/bench_idp.py --iterations 200
```

## Stato di avanzamento

| Componente | Stato |
|---|---|
| CA (root + emissione via CSR/proof-of-possession + verifica certificati) | ✅ Fatto, testato, con benchmark |
| CA — revoca e CRL (§2.4.2: la chiave elettorale dell'IdP «può essere revocata al termine») | ✅ Fatto, testato |
| IdP (autenticazione challenge-response §2.5 + token + chiusura §2.8) | ✅ Fatto, testato, con benchmark |
| Ballot Server | ⬜ Prossimo passo |
| Bulletin Board | ⬜ Da fare |
| Commissione / Shamir threshold | ⬜ Da fare |
| Client elettore | ⬜ Da fare |

## Nota sulla libreria crittografica

La traccia non vincola la libreria, solo l'uso corretto delle primitive
studiate a corso. Uso `cryptography` per RSA/X.509/hashing/firme; la
logica del protocollo (ruoli, Key Usage, catena di fiducia,
autenticazione) è scritta a mano — è quella la parte valutata. Dettagli
in `NOTES.md`.
