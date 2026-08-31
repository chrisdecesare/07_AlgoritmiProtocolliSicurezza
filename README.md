# E-Voting — Prototipo (WP4)

Prototipo del sistema di voto elettronico progettato in WP1–WP3
(`07_APS.pdf`). È un ambiente simulato stand-alone, come chiede la
traccia — non un'infrastruttura reale, non un'app mobile. Tutti e sei
gli attori del protocollo (CA, IdP, Client elettore, Ballot Server,
Bulletin Board, Commissione di scrutinio) sono implementati e
funzionano integrati fra loro (vedi `src/demo_election.py`).

## Struttura del progetto

```
07_APS/
├── NOTES.md               # Note di sviluppo, decisioni di scope, deviazioni dichiarate
├── README.md              # Questo file
├── requirements.txt       # Dipendenze (cryptography, pytest)
│
├── src/
│   ├── common/
│   │   ├── keys.py            # Generazione chiavi RSA-2048 condivisa fra gli attori
│   │   ├── hashing.py         # sha256(*chunks) — hashing condiviso
│   │   ├── signing.py         # sign/verify RSA hash-and-sign (PKCS1v15 + SHA-256)
│   │   ├── password_hash.py   # Salted password hashing (§2.2.5)
│   │   ├── ballot_encoding.py # Codifica canonica election_id ∥ head_ref ∥ voto (§2.2.1, §2.6)
│   │   └── rsa_raw.py         # RSA-OAEP decrypt manuale da soli (N, d) — RFC 8017 (§2.8.2)
│   ├── ca/                    # Certification Authority di Ateneo (§2.3, §2.4.2)
│   ├── idp/                   # Identity Provider — autenticazione + token (§2.5), chiusura (§2.8)
│   ├── voter/
│   │   └── client.py          # Client elettore — chiavi (§2.5.2), voto (§2.6)
│   ├── ballot/
│   │   └── ballot_server.py   # Ballot Server — verifica scheda, Used, ricevute (§2.7)
│   ├── bulletin_board/
│   │   └── bulletin_board.py  # Bulletin Board — append-only, catena di hash (§2.7)
│   ├── commission/
│   │   ├── shamir.py          # Secret sharing di Shamir (3,5) su Z_p (§2.2.3)
│   │   └── commission.py      # Cerimonia chiave + scrutinio (§2.4.1, §2.8.1, §2.8.2)
│   ├── demo_setup.py          # Demo Fase 0 (setup pre-elezione, CA)
│   ├── demo_idp.py            # Demo Fase 1 (autenticazione/token) + chiusura + revoca
│   └── demo_election.py       # Demo END-TO-END: tutte le fasi, tutti gli attori insieme
│
├── tests/                  # Un file di test per modulo, ~90 casi in totale
├── benchmarks/             # Misure di prestazione di CA e IdP
└── certs/                  # Certificati generati dalla demo (output, .pem)
```

## Installazione

```bash
pip install -r requirements.txt
```

## Come eseguire

Tutti i comandi vanno lanciati dalla cartella del progetto, con
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

**3. Vedere l'IdP al lavoro (demo Fase 1 + chiusura urne + revoca):**
```bash
PYTHONPATH=. python3 -m src.demo_idp
```
Mostra l'intera cerimonia §2.5 (autenticazione con tentativo sbagliato,
emissione del token, rifiuto di un secondo token per la stessa matricola,
rate limiting dopo 3 fallimenti) e la chiusura §2.8 (lista firmata dei
partecipanti che esclude gli astenuti, distruzione firmata di `Issued`),
poi la revoca della chiave elettorale dell'IdP a urne chiuse (§2.4.2).

**4. Vedere il protocollo end-to-end (demo completa, tutti gli attori):**
```bash
PYTHONPATH=. python3 -m src.demo_election
```
Setup (CA + cerimonia Shamir della Commissione) → autenticazione e
token per 6 elettori → 4 votano, 1 si astiene → un replay dello stesso
token viene respinto (I.2) → un tentativo di manomissione in transito
viene respinto (I.3) → verifica indipendente della catena di hash del
Bulletin Board → chiusura urne → scrutinio con solo 3 commissari su 5
(§2.8.1) → tally verificato con le firme della Commissione.

**5. Eseguire i test:**
```bash
PYTHONPATH=. python3 -m pytest tests/ -v
```

**6. Misurare le prestazioni (CA e IdP):**
```bash
PYTHONPATH=. python3 benchmarks/bench_ca.py --iterations 200
PYTHONPATH=. python3 benchmarks/bench_idp.py --iterations 200
```

## Stato di avanzamento

| Componente | Stato |
|---|---|
| CA (root + emissione via CSR/proof-of-possession + revoca/CRL) | ✅ Fatto, testato, con benchmark |
| IdP (autenticazione challenge-response §2.5 + token + chiusura §2.8) | ✅ Fatto, testato, con benchmark |
| Client elettore (chiavi §2.5.2, cifratura + firma voto §2.6) | ✅ Fatto, testato |
| Ballot Server (verifica scheda, `Used`, ricevute, §2.7) | ✅ Fatto, testato |
| Bulletin Board (append-only, catena di hash, §2.7) | ✅ Fatto, testato |
| Commissione / Shamir (3,5) su Z_p (§2.2.3/§2.4.1, scrutinio §2.8.2) | ✅ Fatto, testato |

Tutti i sei componenti sono integrati fra loro (nessun mock): la stessa
`pk_BS` generata dalla Commissione cifra i voti del client e li decifra
la Commissione stessa a scrutinio; lo stesso certificato dell'IdP emesso
dalla CA è quello che il Ballot Server verifica. Vedi `NOTES.md` per le
decisioni di scope e le deviazioni dichiarate rispetto al testo del WP2.

## Nota sulla libreria crittografica

La traccia non vincola la libreria, solo l'uso corretto delle primitive
studiate a corso. Uso `cryptography` per RSA/X.509/hashing/firme; la
logica del protocollo (ruoli, Key Usage, catena di fiducia,
autenticazione) è scritta a mano — è quella la parte valutata. Dettagli
in `NOTES.md`.
