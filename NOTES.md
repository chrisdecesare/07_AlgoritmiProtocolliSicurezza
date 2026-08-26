# Note di sviluppo — E-Voting (Algoritmi e Protocolli per la Sicurezza)

Riferimento: `project_work_gruppo7.pdf` (WP1 modello, WP2 protocollo, WP3
analisi di sicurezza — "Un protocollo di voto elettronico per referendum
di Ateneo", Gruppo 7). Ogni scelta implementativa deve restare coerente
con quel documento; le deviazioni sono segnalate qui, componente per
componente.

## Il modello in breve (WP1/WP2)

Referendum binario Sì/No, interno a Unisa — questo tiene bassa la
complessità crittografica fin dall'inizio (WP1). Priorità dichiarata, in
ordine: integrità/autenticità/unicità, poi segretezza (la verificabilità
individuale non deve produrre una prova mostrabile a terzi), poi
revocabilità del voto — che infatti è esclusa.

Attori: elettori; IdP (autentica, rilascia il token, non vede mai il
voto); Ballot Server (riceve/pubblica le schede cifrate, non conosce
l'identità); Commissione di Scrutinio (5 commissari, soglia 3, Shamir
sull'esponente privato RSA `d`); Bulletin Board (registro pubblico, hash
chain); osservatori indipendenti (archiviano le teste firmate — è quello
che rende vero l'append-only); CA di Ateneo (PKI preesistente).

Least privilege: l'IdP sa chi vota ma non cosa, il BS sa cosa ma non chi.
C.2 (segretezza) dipende solo dall'IdP — dalla riservatezza e
cancellazione di `Issued`, non dal fatto che IdP e BS non colludano,
perché il BB pubblica comunque `pk_voter` accanto a ogni ciphertext.

Fasi (§2.1): 0) setup pre-elezione (CA + cerimonia Shamir) → 1)
autenticazione e token (§2.5) → 2) voto, RSA-OAEP (§2.6) → 3)
registrazione nel BB (§2.7) → 4) chiusura, ricostruzione, scrutinio
(§2.8).

Primitive (§2.2): RSA-OAEP 2048/SHA-256 per il voto; RSA hash-and-sign
per tutte le firme; Shamir (3,5) sull'esponente `d` su Z_p (p primo >
2048 bit, non modulo φ(N) — §2.2.3 spiega perché); challenge-response
con hash salato (§2.2.5).

Sulla firma cieca: il documento non è ambiguo, anche se a prima lettura
sembra. §2.4.2 e §3.3.2 dicono chiaramente che una versione preliminare
la prevedeva per il token, ma è stata scartata nel design finale — l'IdP
riceve `pk_voter` in chiaro e la registra in `Issued`. Il prezzo è che
C.2 dipende interamente dalla riservatezza di `Issued` (F.4, T.5). Niente
da decidere qui: l'implementazione (`src/idp/`) segue direttamente questa
scelta.

Assunzioni di fiducia (§2.3, §3.8): PKI preesistente; almeno 3
commissari onesti; l'IdP tiene `Issued` riservata e la cancella in
tempo; registro elettorale corretto (F.6, non verificato dal
protocollo); client dell'elettore onesto (T.2 non mitigato); BB
scrivibile solo dal BS con archiviazione indipendente (F.9); canale
autenticato verso IdP/BS; orologi ragionevolmente sincronizzati.

Rischi dichiarati e non mitigati (§3.7): T.2 un client compromesso rompe
tutto da solo; T.3 vendita del voto trattenendo `r_enc`, non impedibile;
T.4 correttezza della decifratura non verificabile universalmente; T.5
IdP come collo di bottiglia del rischio.

Fuori scope per dichiarazione esplicita del documento: threshold RSA di
Shoup, distributed key generation, zk-SNARK, mixnet verificabili, code
voting — estensioni future, non buchi.

Revocabilità (R.1): esclusa di proposito, integrità/unicità vince sulla
resistenza alla coercizione avanzata (§2.9).

## Stato implementazione (WP4)

| Componente | Stato | Dove |
|---|---|---|
| CA (root, emissione via CSR e via chiave nuda, verifica) | ✅ Fatto | `src/ca/root_ca.py`, `csr.py`, `profiles.py` — test in `test_ca.py`, `test_csr.py`, benchmark in `bench_ca.py` |
| CA — database `index.txt`/`serial` e revoca/CRL (§2.4.2) | ✅ Fatto | `src/ca/store.py`, `crl.py` — test in `test_crl.py` |
| Helper condivisi (hash, firma, password salting) | ✅ Fatto | `src/common/` |
| IdP (auth §2.5.1, token §2.5.3, chiusura §2.8 passi 2-3) | ✅ Fatto | `src/idp/identity_provider.py` — test in `test_idp.py`, demo in `demo_idp.py`, benchmark in `bench_idp.py` |
| Client elettore (§2.5.2 chiavi, §2.6 cifratura + firma scheda) | ⬜ Prossimo | genera pk_voter/sk_voter, cifra `election_id ∥ head_ref ∥ vote_plain` con OAEP, firma il pacchetto |
| Ballot Server (§2.7: token/firma/head_ref, tabella `Used`, ricevute) | ⬜ Da fare | il passo 2 è già pronto: `verify_token_as_ballot_server` |
| Bulletin Board (§2.7: append-only, hash chain) | ⬜ Da fare | |
| Commissione / Shamir (3,5) su Z_p (§2.4.1/§2.8.1, scrutinio §2.8.2) | ⬜ Da fare | |

## CA — decisioni di scope

La CA nel modello è un'assunzione preesistente (§2.3), non qualcosa che
il protocollo disegna; qui la simulo per rendere eseguibile il resto.
Segue le slide 06 (6 passi, 4 requisiti, certificato = chiave + ID +
firma).

Due percorsi di emissione: `issue_certificate_from_csr` (quello giusto —
la CA non vede mai la privata) e `issue_certificate(public_key=...)`,
scorciatoia tenuta per compatibilità con test/benchmark preesistenti; se
si omette la chiave, la CA se la genera da sola e la restituisce insieme
al certificato — comodo per un test, mai accettabile davvero.

Dal Lab 4 ho preso tre cose: i profili di estensione (`profiles.py`, con
in più `signing_cert` che il Lab non ha), il database `index.txt`/`serial`
(`store.py`, serial progressivi da `0x1000` come nel Lab, non casuali),
revoca e CRL (`crl.py`).

### La revoca doveva starci (§2.4.2)

All'inizio l'avevo classificata fuori scope, pensando che con una
finestra elettorale così breve non contasse. Era un errore: §2.4.2
motiva la separazione fra chiave elettorale dell'IdP e chiave SSO di
Ateneo proprio dicendo che la prima *"può essere revocata al termine
senza impatti sui servizi di Ateneo"* — senza revoca il prototipo non
dimostra metà di quella frase.

Ho implementato tutto il ciclo del Lab: `revoke_certificate` marca `R`
in `index.txt`, `current_crl` firma la CRL, `crlDistributionPoints` dice
dove trovarla. Il test che conta è
`test_token_is_rejected_after_election_key_is_revoked`, e `demo_idp.py`
lo mostra dal vivo.

OCSP resta fuori: un responder online sarebbe solo un altro single point
of failure (§3.2 lo elenca già fra i rischi). Una CRL basta.

Semplificazioni rimaste, dichiarate: nessuna gerarchia root/intermedia
(il documento assume una sola CA — `pathlen:0` lo rende un vincolo
verificabile, non solo dichiarato); chiave di root in memoria invece che
offline e cifrata; 2048 bit invece dei 4096 che il Lab consiglia per la
root, per restare coerente con §2.5.2; validità dei certificati
commisurata a una singola elezione.

## IdP — decisioni di scope

Implementa §2.5 e la parte IdP di §2.8.

- **Verifica lato BS** (`verify_token_as_ballot_server`): il BS è
  un'entità separata (§1.1) e non ha motivo di fidarsi di una pkIdP che
  gli arriva già pronta — si fida della CA. La funzione parte dal
  certificato, verifica autenticità/validità/revoca, solo dopo estrae
  pkIdP. `IdentityProvider.verify_token` resta per i test ma dà per
  scontato proprio quello che la PKI serve a stabilire.
- **Perché serve `nonRepudiation` e non solo `digitalSignature`**:
  l'IdP ha due certificati, e anche quello TLS porta `digitalSignature`
  (serve per l'handshake). Accontentarsi di quel flag accetterebbe un
  token firmato con la chiave sbagliata, rendendo inutile la
  separazione di §2.4.2.
- **Non ho usato il pattern del Lab 3 (KDC)**, anche se "autorità fidata
  emette ticket" somiglia all'emissione del token: §3.3.2 scarta
  esplicitamente l'alternativa del bearer token stile OAuth perché
  richiederebbe introspezione in tempo reale fra BS e IdP, ricreando il
  legame che si vuole evitare.
- **Confronto a tempo costante** (`hmac.compare_digest`): non richiesto
  esplicitamente dal documento, ma è la stessa lezione del caso Xbox 360
  sui timing attack.
- **Autorizzazione single-use**: `issue_token` consuma
  `verify_authentication`, applica I.1 nel codice e non solo a parole.
- **Backoff esponenziale**: `2 · 2^(tentativi-3)` secondi dopo k=3
  fallimenti. Il documento dice solo "cresce esponenzialmente", questa
  è la formula più semplice coerente con l'enunciato.
- **hpwd plaintext-equivalent**: implementato così com'è specificato,
  senza aggiungere un PBKDF2/bcrypt di nascosto — il documento accetta
  questo costo esplicitamente.
- **`Issued` non esce mai** da `IdentityProvider`: solo `issue_token`
  scrive, `close_and_publish_participants` legge solo le matricole,
  `destroy_issued_table` svuota.
- **Quello che non previene, di proposito**: un IdP disonesto può
  comunque emettere token per astenuti (ballot stuffing, T.6) — il
  documento lo dichiara rilevabile solo a posteriori, non prevenibile
  dal codice di un IdP che ha già deciso di barare.

## Libreria crittografica

Uso `cryptography` per le primitive (RSA, X.509, hashing, firme); la
logica del protocollo — ruoli, Key Usage, catena di fiducia, stato di
`Issued`, backoff — è scritta a mano, ed è quella la parte valutata.

## Convenzioni

- Python, libreria `cryptography`.
- Un package per attore (`src/<attore>/`), primitive condivise in
  `src/common/`.
- RSA 2048 / e=65537 ovunque, anche se il documento lo richiede
  esplicitamente solo per le chiavi dell'elettore.
- Ogni modulo dice nel proprio docstring a quale sezione del documento
  corrisponde e cosa NON garantisce.
- Test: un caso per ogni proprietà di sicurezza rilevante, non solo il
  percorso felice, con nomi che citano la proprietà (I.1, I.2, C.2, ...)
  dove ha senso.
