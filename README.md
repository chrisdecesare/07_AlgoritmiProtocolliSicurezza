# E-Voting — Prototipo (WP4)

Prototipo del sistema di voto elettronico progettato in WP1–WP3
(`07_APS_1.pdf`). Ambiente simulato stand-alone, come richiesto dalla traccia
(non un'infrastruttura reale né un'app mobile).

## Struttura del progetto

```
evoting-project/
├── NOTES.md               # Note di sviluppo, stato di avanzamento, decisioni di scope
├── README.md              # Questo file
├── requirements.txt       # Dipendenze (cryptography, pytest)
│
├── src/                   # Codice sorgente del sistema (il TUO codice)
│   ├── common/
│   │   └── keys.py        # Generazione chiavi RSA-2048 condivisa fra gli attori
│   ├── ca/
│   │   └── root_ca.py     # Certification Authority di Ateneo (FATTO)
│   └── demo_setup.py      # Demo eseguibile della Fase 0 (setup pre-elezione)
│
├── tests/
│   └── test_ca.py         # Test della CA (8 casi)
│
├── benchmarks/
│   └── bench_ca.py        # Misure di prestazione della CA (per WP4)
│
└── certs/                 # Certificati generati dalla demo (output, .pem)
```

La struttura riflette gli attori del modello: ogni componente del protocollo
(CA, e in futuro IdP, Ballot Server, Bulletin Board, Commissione, Voter) è un
package dentro `src/`. Finora è implementata solo la **CA**.

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

**3. Eseguire i test:**
```bash
PYTHONPATH=. python3 -m pytest tests/ -v
```

**4. Misurare le prestazioni (per WP4):**
```bash
PYTHONPATH=. python3 benchmarks/bench_ca.py --iterations 200
```

## Stato di avanzamento

| Componente | Stato |
|---|---|
| CA (root + emissione + verifica certificati) | ✅ Fatto, testato, con benchmark |
| IdP (challenge-response + token) | ⬜ Da fare |
| Ballot Server | ⬜ Da fare |
| Bulletin Board | ⬜ Da fare |
| Commissione / Shamir threshold | ⬜ Da fare |
| Client elettore | ⬜ Da fare |

## Nota sulla libreria crittografica

La traccia (Nota 2.2) richiede l'uso corretto degli strumenti studiati nel
corso, senza vincolare la libreria. Si usa `cryptography` per le primitive
(RSA, X.509, hashing, firme); la logica del protocollo — ruoli, Key Usage,
catena di fiducia, autenticazione del soggetto — è scritta a mano ed è la
parte progettuale valutata. Vedi `NOTES.md` per il dettaglio.
