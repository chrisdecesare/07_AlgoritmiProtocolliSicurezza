# Note di sviluppo — E-Voting (Algoritmi e Protocolli per la Sicurezza)

Documento di specifica di riferimento: `07_APS_1.pdf` — WP1 (modello),
WP2 (soluzione/protocollo), WP3 (analisi di sicurezza). Qualunque scelta
implementativa deve restare coerente con quanto lì dichiarato; eventuali
deviazioni vanno segnalate esplicitamente.

## Sintesi del modello (WP1/WP2)

- **Attori**: elettore, Identity Provider (IdP), Ballot Server (BS),
  Commissione di Scrutinio (n=5, soglia t=3), Bulletin Board (BB, append-only,
  hash chain), CA universitaria (PKI preesistente).
- **Least privilege**: IdP conosce l'identità ma non il voto; BS conosce il
  voto cifrato ma non l'identità; la commissione controlla la chiave di
  decifratura ma solo a urne chiuse.
- **Fasi**: 0) Setup pre-elezione (CA + Commissione) -> 1) Autenticazione e
  token (challenge-response) -> 2) Espressione del voto (RSA-OAEP) ->
  3) Registrazione nel BB -> 4) Chiusura, scrutinio (threshold RSA,
  Shamir (t,n)), pubblicazione.
- **Primitive**: RSA-OAEP (cifratura voto), RSA hash-and-sign (firme),
  Shamir (t,n)-threshold applicato all'esponente privato `d`, challenge-response
  su segreto condiviso con salted hash. (Firma cieca RSA per il token: da
  decidere — vedi punto aperto sotto.)
- **Assunzioni di fiducia dichiarate (§2.3)**: PKI universitaria preesistente
  (CA fidata già ha certificato IdP, BS, commissari); onestà della
  maggioranza qualificata della commissione (< t corrotti); IdP e BS
  amministrativamente separati e non collusivi; client onesto dell'elettore.
- **Scelte fuori scope del corso**: zk-SNARK, MPC avanzato, blockchain,
  revoca/sostituzione del voto (esclusa con motivazione, §2.9).

## Punto aperto da decidere (a monte dell'IdP)

Il documento è ambiguo sulla firma cieca: §2.4.2 la nomina, ma §3.3.2 dice
che NON è stata adottata (mitigazione operativa via tabella `Issued` +
cancellazione post-elezione). Va deciso prima di scrivere §2.5.3 (emissione
del token) e di implementare l'IdP, perché le due strade producono un
protocollo e un codice diversi.

## Stato di avanzamento implementazione (WP4)

| Componente | Stato | Note |
|---|---|---|
| CA (root + emissione certificati) | Fatto | `src/ca/root_ca.py`, test in `tests/test_ca.py`, benchmark in `benchmarks/bench_ca.py` |
| IdP (auth challenge-response + token) | Da iniziare | dipende dal punto aperto sopra |
| Ballot Server (ricezione, verifica, append BB) | Da iniziare | |
| Bulletin Board (hash chain, teste firmate) | Da iniziare | |
| Commissione / Shamir threshold | Da iniziare | |
| Client elettore | Da iniziare | |

## Decisioni di scope per la CA

La CA nel modello è un'assunzione preesistente (§2.3), non un elemento di
design originale del protocollo; l'implementazione la simula per rendere
eseguibile il prototipo. Aderenza al materiale del corso (slide
06_Key_Distribution): processo di certificazione in 6 passi, 4 requisiti di
verifica, certificato = chiave pubblica + identificatore + firma della CA.

Semplificazioni consapevoli rispetto alle slide (da dichiarare in WP4):

- Nessuna CRL/OCSP: le slide trattano la revoca, ma nel contesto di una
  singola elezione a finestra breve non è operativamente rilevante.
  Esclusione motivata, non per omissione.
- Una sola CA di Ateneo, self-signed: le slide trattano catene e gerarchie
  di CA, qui non necessarie (il documento assume una CA singola).
- Profilo X.509: Basic Constraints, Key Usage, Extended Key Usage
  differenziati per ruolo (TLS server / firma / commissario); DN con
  CN/O/OU/C come nello schema delle slide.
- Validità dei certificati commisurata alla durata di una singola elezione.

## Nota sulla libreria crittografica

La traccia (Nota 2.2) richiede l'uso corretto degli strumenti studiati nel
corso, senza vincolare la libreria: si usa `cryptography` (Python) per le
primitive (RSA, X.509, hashing, firme). La logica del protocollo — ruoli,
Key Usage, catena di fiducia, autenticazione del soggetto — è scritta a mano
ed è la parte progettuale. Verificare con il docente solo in caso di dubbi
su un eventuale vincolo OpenSSL esplicito.

## Convenzioni di progetto

- Linguaggio: Python (libreria `cryptography`).
- Stile: separazione netta tra CA / IdP / BS / BB / commissione, coerente
  con la separazione dei ruoli del modello (least privilege). Un package
  `src/<attore>/` per ciascun attore del protocollo.
- RSA: modulo 2048 bit, esponente pubblico e=65537, coerente con §2.5.2 del
  documento (chiavi elettore); stessi parametri per tutti gli attori, salvo
  motivazione esplicita di deviazione.
