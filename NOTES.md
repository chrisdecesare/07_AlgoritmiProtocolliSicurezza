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
| Client elettore (§2.5.2 chiavi, §2.6 cifratura + firma scheda) | ✅ Fatto | `src/voter/client.py` — test in `test_client.py` |
| Bulletin Board (§2.7: append-only, hash chain) | ✅ Fatto | `src/bulletin_board/bulletin_board.py` — test in `test_bulletin_board.py` |
| Ballot Server (§2.7: token/firma/head_ref, tabella `Used`, ricevute) | ✅ Fatto | `src/ballot/ballot_server.py` — test in `test_ballot_server.py` |
| Commissione / Shamir (3,5) su Z_p (§2.4.1/§2.8.1, scrutinio §2.8.2) | ✅ Fatto | `src/commission/shamir.py`, `commission.py` — test in `test_shamir.py`, `test_commission.py` |
| Decifratura OAEP a (N, d) noti, senza (p, q) | ✅ Fatto | `src/common/rsa_raw.py` — test in `test_rsa_raw.py` |
| Codifica canonica della scheda | ✅ Fatto | `src/common/ballot_encoding.py` — test in `test_ballot_encoding.py` |
| Demo end-to-end (setup → voto → scrutinio) | ✅ Fatto | `src/demo_election.py` |

## Client, Ballot Server, Bulletin Board — decisioni di scope

Lavoro meccanico che ricalca pattern già visti in CA/IdP (store,
verifica, firma), implementato insieme perché il flusso voto→BS→BB è
un unico percorso end-to-end.

- **Nessuna rete reale**: come IdP, tutto è chiamata di funzione diretta
  (`cast_vote` produce un `Ballot`, `BallotServer.submit_ballot` lo
  consuma). `head_ref` non viene "letto dal BB" via HTTP, è
  `BallotServer.current_head_reference()` chiamato direttamente.
- **`r_enc` non è mai esposta**: `encrypt_ballot` passa dritto per
  `RSAPublicKey.encrypt` di `cryptography`, che genera la randomness
  OAEP internamente. Conseguenza dichiarata: non è possibile
  riprodurre nel codice lo scenario T.3 (vendita del voto via
  ritenzione di `r_enc`) esattamente come descritto nel documento — la
  discussione di T.3 resta valida a livello di analisi (WP3), semplicemente
  non c'è un modo pulito di dimostrarla contro questa particolare API.
- **`σ_token` finisce nella entry del BB**, anche se la tupla elencata
  testualmente al passo 7 di §2.7 non lo include. Senza salvarla, il
  controllo V.2 punto 4 di WP3 ("verificare ogni σtoken con pkIdP")
  non sarebbe eseguibile da un osservatore esterno che non ha assistito
  alla sottomissione. Non costa nulla in segretezza (è già nota al BS
  al momento dell'accettazione, e non lega comunque a un'identità).
- **Finestra di tolleranza su `head_ref`** (passo 5 di §2.7): il
  documento la lascia parametrica ("valore dichiarato nel manifest, non
  derivabile analiticamente"). Implementata come le ultime
  `HEAD_REFERENCE_TOLERANCE = 5` teste accettate, non solo l'ultima —
  altrimenti due elettori che leggono `head_ref` quasi in contemporanea
  si bloccherebbero a vicenda per interleaving, non per un attacco.
- **Ordine dei controlli in `submit_ballot`** rispetta rigorosamente
  §2.7 (finestra temporale → token → unicità → integrità → coerenza
  della testa), fermandosi al primo fallimento — l'ordine conta: una
  scheda con `token_id` già usato viene scartata come replay (I.2)
  anche se il suo ciphertext è stato manomesso, perché l'unicità è
  controllata prima dell'integrità.

## Commissione / Shamir (3,5) — decisioni di scope

La parte a rischio più alto del piano iniziale, come previsto.

- **Si condivide `d`, mai `(p, q)`**: coerente con §2.2.3. La
  conseguenza è che la Commissione, dopo la ricostruzione, non ha un
  `RSAPrivateKey` di `cryptography` utilizzabile (che richiederebbe i
  fattori primi) — da qui `src/common/rsa_raw.py`, un'implementazione a
  mano di RSADP + EME-OAEP-DECODE (RFC 8017 §7.1.2) con SHA-256, che
  decifra dati solo `(N, d)`. Validato con un round-trip diretto contro
  ciphertext prodotti da `cryptography` prima di collegarlo al resto.
- **Il primo pubblico `p` non è generato con Miller-Rabin scritto a
  mano**: un tentativo con `dh.generate_parameters` per un primo
  "safe" anche solo di poco sopra i 2048 bit ha impiegato quasi due
  minuti — inaccettabile anche per un solo run dei test. La soluzione:
  si genera una chiave RSA usa-e-getta da 6144 bit (con OpenSSL via
  `cryptography`, meno di un secondo) e si preleva uno dei due fattori
  primi, che OpenSSL garantisce primo e che a 3072 bit è ben sopra
  qualunque `d` di una chiave elettorale RSA-2048. La chiave RSA
  generata per l'occasione non serve ad altro. `shamir_prime()` è
  cache-ata (`lru_cache`): il costo si paga una sola volta per processo.
- **Nessuna verifica della soglia di ricostruzione**: `reconstruct_secret`
  con meno di 3 share non solleva un errore, restituisce un valore
  sbagliato — è la proprietà stessa dello schema di Shamir (sotto
  soglia, zero informazione), non uno schema di verifica come Feldman
  VSS che il documento non prevede. In pratica, ricostruire con `d`
  sbagliata fa fallire la decifratura OAEP su ogni entry del BB
  (`TallyIntegrityError`), quindi l'errore emerge comunque, solo più a
  valle.
- **La chiave integra non esce mai da una funzione**: sia
  `generate_and_share_decryption_key` sia `run_scrutiny` tengono
  `RSAPrivateKey`/`d` in variabili locali che escono di scope a fine
  chiamata — la rappresentazione più diretta in Python di "la chiave
  esiste in memoria volatile solo per il tempo strettamente necessario"
  (§2.2.4 passo 5, §2.8.1 passo 3), senza un vero dispositivo
  air-gapped a disposizione.
- **Le firme dei commissari sul tally bundle sono tenute separate** dal
  `TallyBundle` stesso (`sign_tally_bundle`/`verify_tally_bundle`)
  invece di essere incorporate nella dataclass, per poter contare
  quante e quali firme coprono un bundle senza doverlo ricostruire.
  `verify_tally_bundle` deduplica per chiave pubblica prima di contare:
  trovato con `/code-review high` sui quattro componenti sopra — senza
  dedup, la stessa coppia (chiave, firma) ripetuta nelle liste
  d'ingresso avrebbe potuto raggiungere la soglia con meno di 3
  commissari realmente distinti.
- **`raw_rsa_oaep_decrypt` non è a tempo costante**, nonostante il
  proprio docstring dichiari di voler evitare un oracolo di padding
  (Manger's attack): lo stesso `/code-review` ha trovato che i quattro
  controlli di validità erano combinati con `and` a corto circuito
  (tempi diversi a seconda di quale controllo fallisce per primo) e il
  confronto dell'hash del label usava `==` invece di
  `hmac.compare_digest`. Corretti entrambi; resta un residuo dichiarato
  nel commento della funzione: la scansione del separatore
  (`rest.find`) è comunque a tempo variabile — un decode davvero
  costante richiederebbe uno scan bit a bit, fuori scopo qui.
- **Due segnalazioni dello stesso `/code-review` restano intenzionalmente
  non toccate** perché fuori dal perimetro di questo WP4 (codice CA
  preesistente, non parte dei quattro componenti nuovi): un
  `IndexError` non gestito in `issue_certificate_from_csr` se la CSR
  non ha un CN (`src/ca/root_ca.py`), e `CertificateStore._flush`
  che riscrive l'intero `index.txt` a ogni emissione/revoca invece di
  fare append incrementale (`src/ca/store.py`) — un costo O(N²)
  accettabile per il numero di certificati di questo prototipo, non
  per un deployment reale.

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
