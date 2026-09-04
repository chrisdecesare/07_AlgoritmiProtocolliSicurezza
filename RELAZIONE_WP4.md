# Capitolo 4 — WP4: Implementazione

> Bozza pronta per essere adattata al documento LaTeX (`07_APS.pdf`),
> nello stesso stile e con gli stessi riferimenti incrociati (§2.x, §3.x)
> di WP1–WP3. I nomi di file/funzione sono indicativi del codice
> consegnato, da citare in nota o in appendice secondo le convenzioni
> del corso.

## 4.1 Obiettivo e perimetro

Questo capitolo descrive l'implementazione del protocollo definito in
WP2 e analizzato in WP3: un prototipo software, non un'infrastruttura
di rete reale, che realizza tutti e sei gli attori del modello (§1.1) —
CA di Ateneo, Identity Provider, Client dell'elettore, Ballot Server,
Bulletin Board, Commissione di scrutinio — e li fa interagire fra loro
end-to-end, dalla cerimonia di setup (§2.4) allo scrutinio (§2.8).

L'obiettivo del WP4 non è produrre un sistema pronto per la produzione,
ma dimostrare che le scelte progettuali di WP2 sono implementabili
correttamente con le primitive crittografiche del corso, e verificare
sperimentalmente le proprietà di sicurezza analizzate in WP3 (in
particolare I.1, I.2, I.3, C.2, V.1, V.2).

## 4.2 Libreria crittografica e convenzioni

Tutte le primitive crittografiche (RSA, X.509, hashing, firme, RSA-OAEP)
vengono dalla libreria `cryptography`, lo standard de facto in ambito
Python; la logica del protocollo — ruoli, catena di fiducia, stato
delle tabelle `Issued`/`Used`, cerimonie di condivisione della chiave —
è scritta interamente a mano, ed è quella la parte oggetto di
valutazione.

Parametri condivisi da tutti gli attori:

- **RSA 2048 bit, esponente pubblico `e = 65537`**, per ogni coppia di
  chiavi generata nel sistema (§2.5.2 lo richiede esplicitamente per
  l'elettore; qui è stato esteso a tutti gli attori per non avere due
  convenzioni diverse nello stesso prototipo).
- **SHA-256** come unica funzione di hash, usata sia per le firme
  hash-and-sign (§2.2.2) sia come hash interno di OAEP (§2.2.1) sia per
  l'hashing salato delle password (§2.2.5).
- **RSA-OAEP** (MGF1 con SHA-256, label vuota) per la cifratura del
  voto.
- **RSA hash-and-sign** (PKCS#1 v1.5 + SHA-256) per tutte le firme del
  protocollo: token dell'IdP, pacchetto di voto dell'elettore, ricevute
  e teste del Ballot Server, tally della Commissione.

Ogni modulo del codice dichiara nel proprio docstring a quale sezione
del presente documento corrisponde e cosa non garantisce — una scelta
di documentazione, non solo di codice, pensata per rendere tracciabile
ogni corrispondenza fra teoria (WP2) e implementazione (WP4).

## 4.3 Certification Authority (CA)

Realizza l'assunzione di fiducia F.1 (§2.3): una CA di Ateneo
preesistente, qui simulata per rendere eseguibile il resto del sistema.
Segue il modello "Autenticazione → CSR → Emissione → Verifica" con
profili di estensione X.509 differenziati per ruolo (`IDP_TLS`,
`IDP_TOKEN_SIGNING`, `BS_TLS`, `BS_SIGNING`, `COMMISSIONER`), ciascuno
con il proprio Key Usage minimo necessario — realizzazione diretta del
principio di least privilege dichiarato in WP1 (§1.1).

Include un database dei certificati emessi (`index.txt`/`serial`, nel
formato di OpenSSL) e il ciclo di revoca/CRL richiesto da §2.4.2: la
chiave di firma dei token dell'IdP, distinta dalla chiave SSO di
Ateneo, viene revocata a urne chiuse e la sua CRL rigenerata, così che
un token emesso prima della revoca resti crittograficamente valido ma
sia rifiutato dal Ballot Server dopo, dimostrando sperimentalmente il
beneficio di isolamento del rischio motivato in §2.4.2.

## 4.4 Identity Provider (IdP)

Realizza §2.5 (registrazione e autenticazione dell'elettore) e la parte
IdP della chiusura urne (§2.8, passi 2-3).

L'autenticazione implementa esattamente la cerimonia challenge-response
di §2.5.1: salt a 32 byte per credenziale, nonce fresca a 128 bit per
sessione, confronto a tempo costante della risposta (per evitare la
classe di attacchi a canale laterale nota dal caso Xbox 360), backoff
esponenziale dopo `k = 3` tentativi falliti. L'emissione del token segue
i sei passi di §2.5.3, con l'unicità (I.2) garantita dalla tabella
interna `Issued`, mai esposta e cancellata subito dopo la pubblicazione
della lista firmata dei partecipanti (§2.8, passo 2) — la misura di
trasparenza che mitiga, senza prevenirlo, lo scenario limite del ballot
stuffing discusso in §1.2.

La verifica del token lato Ballot Server non si fida di una chiave
pubblica dell'IdP passata "a parole": parte dal certificato X.509,
verifica autenticità/validità/revoca tramite la CA, e solo allora
estrae la chiave con cui controllare la firma — è l'implementazione
concreta della catena di fiducia F.1 su cui poggiano I.1 e V.2.

## 4.5 Client dell'elettore

Realizza §2.5.2 (generazione locale della coppia di chiavi) e §2.6
(espressione del voto). Il client è honest-by-assumption, coerentemente
con F.6 (§2.3): implementa il percorso corretto del protocollo, non una
difesa contro un client compromesso, rischio che WP3 dichiara
esplicitamente non mitigabile lato server (T.2).

Il voto è codificato in forma canonica a lunghezza fissa (§2.2.1): un
singolo byte per `{YES, NO}`, che elimina ogni canale laterale di
lunghezza fra le due opzioni possibili. Il plaintext
`election_id ∥ head_ref ∥ vote_plain` viene cifrato con RSA-OAEP verso
la chiave pubblica della Commissione e il pacchetto firmato con la
chiave privata effimera dell'elettore su
`H(C ∥ token_id ∥ head_ref)`, esattamente come specificato in §2.2.2 e
§2.6, passo 5.

## 4.6 Ballot Server

Realizza §2.7 (registrazione nel Bulletin Board) e la parte Ballot
Server della chiusura urne (§2.8, passi 1, 4-5).

I sei controlli di §2.7 sono eseguiti nell'ordine dichiarato dal
documento, fermandosi al primo fallimento: finestra temporale, validità
del token (verificata tramite la catena di fiducia della CA, non una
chiave "di fiducia"), unicità tramite la tabella `Used` (I.2, secondo
livello di difesa oltre a quello dell'IdP), integrità del pacchetto
tramite la firma dell'elettore (I.3), coerenza della testa `head_ref`
rispetto a una finestra di teste recenti — parametro che il documento
lascia intenzionalmente dichiarato nel manifest e non derivabile
analiticamente (§2.7, nota sul parametro `head_ref`).

Il Ballot Server pubblica inoltre teste periodiche firmate
(`σ_head,k`, §2.7.1), il meccanismo che rende l'archiviazione
indipendente da parte degli osservatori una garanzia effettiva contro
una riscrittura integrale del registro, e la testa finale firmata a
chiusura urne (§2.8, passi 4-5).

## 4.7 Bulletin Board

Realizza §2.7: un registro pubblico append-only con catena di hash
`head_i = H(head_{i-1} ∥ IDseq ∥ C ∥ pk_voter ∥ token_id)`. La catena è
verificabile indipendentemente da chiunque possieda le sole entry
pubbliche e la testa iniziale `head_0` del manifest (§2.4.3),
realizzando concretamente il controllo di V.2 sull'integrità storica
del registro (§3.5.2, punto 3) e il limite dichiarato in §3.4.3: la
catena rileva modifiche parziali, non una riscrittura integrale
coerente, la cui rilevabilità dipende dall'archiviazione indipendente
di §2.7.1 (assunzione F.8).

## 4.8 Commissione di scrutinio e schema a soglia

Realizza la cerimonia di generazione/condivisione della chiave (§2.2.4,
§2.4.1) e lo scrutinio a urne chiuse (§2.8.1, §2.8.2): lo schema di
Shamir (3,5) è implementato su un campo `Z_p` con `p` primo pubblico
maggiore di 2048 bit, garantito superiore a qualunque esponente privato
`d` di una chiave elettorale RSA-2048 (§2.2.3). La condivisione avviene
sull'esponente privato `d`, mai sui fattori del modulo, come richiesto
esplicitamente dal documento.

Poiché lo schema condivide `d` e non i fattori primi del modulo, la
Commissione non dispone — dopo la ricostruzione — di una rappresentazione
della chiave privata utilizzabile con le API ad alto livello delle
librerie crittografiche standard, che richiedono i fattori del modulo.
È stata quindi implementata a mano la primitiva di decifratura
RSA-OAEP secondo lo standard RFC 8017 (RSADP + EME-OAEP-DECODE, §7.1.2,
e la mask generation function MGF1, Appendice B.2.1), operando
direttamente sull'esponentazione modulare `m = c^d mod N` — la
libreria fornisce comunque la funzione di hash e le primitive di
cifratura del lato client, così che la decifratura manuale sia
verificabile per confronto diretto con un ciphertext prodotto dalla
libreria stessa.

In nessun punto del codice la chiave privata `sk_BS` esiste per intero
al di fuori dello scope di una singola funzione: sia in fase di
generazione sia in fase di ricostruzione, la coppia completa non viene
mai restituita al chiamante né conservata in uno stato persistente —
la rappresentazione più diretta, nel linguaggio di implementazione, del
vincolo dichiarato in §2.2.4/§2.8.1 sulla finestra di esistenza della
chiave integra.

Lo scrutinio (§2.8.2) decifra ogni entry del Bulletin Board in ordine,
verifica la coerenza del plaintext (formato canonico, `election_id`
atteso), conta i voti, mescola la lista dei voti decifrati — senza
alcun riferimento a `IDseq` o `pk_voter`, per non compromettere C.2/C.3
— e produce un tally firmato congiuntamente dai commissari partecipanti,
verificabile da chiunque con le sole chiavi pubbliche pubblicate.

## 4.9 Manifest di elezione

Realizza §2.4.3, il documento firmato che fissa prima dell'apertura
delle urne l'intero contesto crittografico dell'elezione e che il testo
descrive come «la radice di fiducia da cui ogni successiva verifica
deriva». I campi implementati sono esattamente le voci elencate in
§2.4.3, nello stesso ordine: identificativo e quesito con le opzioni
canoniche, finestra temporale, `pk_BS` con schema PKE e primo pubblico
`p`, `pk_BS-srv`, `pk_IdP`, elenco dei commissari con i rispettivi
certificati X.509 e parametri `(t, n)`, cardinalità del corpo
elettorale, indirizzi pubblici e certificati di trasporto, `head_0` e
hash del client ufficiale.

La firma segue la prescrizione del documento — tutti i commissari più
la CA di Ateneo — e adotta quindi una soglia deliberatamente più
stringente di quella del tally bundle (§2.8.2, dove bastano i `t`
partecipanti): il manifest si firma durante la cerimonia di §2.2.4, con
i cinque commissari riuniti fisicamente, dove non c'è ragione di
accontentarsi di una maggioranza qualificata. La CA controfirma senza
mai esporre la propria chiave privata, coerentemente con il modo in cui
firma certificati e CRL.

La verifica non si limita alle firme: controlla anche la coerenza
interna del manifest, in particolare che `head_0` sia ricalcolabile
come `H(election_id ∥ timestamp_apertura)` dai campi dichiarati. Un
manifest firmato ma internamente incoerente sarebbe inutilizzabile come
ancora della catena di hash del Bulletin Board, e il momento giusto per
accorgersene è la verifica della radice di fiducia, non l'arrivo della
prima scheda.

È inoltre implementato il controllo di coerenza dell'affluenza (V.2
punto 9): il confronto fra token emessi, schede registrate e cardinalità
dichiarata nel manifest. È la sola mitigazione, dichiaratamente
parziale, che §2.3 attribuisce all'assunzione F.5 sulla correttezza del
registro elettorale — rende rilevabile un'emissione di token oltre il
numero di aventi diritto fissato prima dell'apertura delle urne, non un
ballot stuffing che resti entro quella cardinalità, il quale rimane
rilevabile soltanto a posteriori attraverso la lista firmata dei
partecipanti (§2.8).

Nella demo end-to-end il manifest non è un artefatto decorativo ma la
sorgente effettiva dei parametri: il Ballot Server ne ricava `head_0` e
la finestra temporale, il client di voto la chiave di cifratura, e
l'osservatore preleva dai certificati elencati le chiavi pubbliche con
cui verifica le firme del tally — la catena manifest → certificati →
firme è ciò che rende eseguibile la verifica universale da parte di chi
non ha assistito né alla cerimonia né allo scrutinio.

## 4.10 Verifica sperimentale e test

L'implementazione è accompagnata da una batteria di test automatici
(105 casi), organizzata per proprietà di sicurezza piuttosto che
per solo percorso felice: per ciascun componente sono presenti casi
dedicati a I.1/I.2/I.3 (autenticità, unicità, integrità), C.2
(non-correlabilità), V.1/V.2 (verificabilità individuale e universale),
oltre ai casi di corretto funzionamento.

Una demo eseguibile (`demo_election.py`) mette in scena l'intero
protocollo end-to-end con oggetti crittografici reali che attraversano
tutti gli attori — nessun componente è simulato con un mock — inclusi
tre scenari avversariali osservabili a schermo: un tentativo di
doppio voto con lo stesso token (respinto, I.2), un tentativo di
alterazione in transito di una scheda già firmata (respinto, I.3), e la
verifica indipendente della catena di hash del Bulletin Board da parte
di un "osservatore" che non ha accesso allo stato interno del Ballot
Server. Lo scrutinio finale è eseguito con solo 3 commissari su 5,
dimostrando che la soglia (3,5) di §2.2.3 non richiede la
partecipazione di tutti i membri della Commissione.

## 4.11 Deviazioni dichiarate rispetto al testo di WP2

Coerentemente con la convenzione adottata in tutto il progetto — ogni
scelta implementativa che si discosta dal testo letterale del documento
va dichiarata e motivata — si segnalano due deviazioni minori:

- **La firma del token (`σ_token`) è inclusa nella entry pubblica del
  Bulletin Board**, sebbene la tupla elencata testualmente al passo 7
  di §2.7 non la comprenda. Senza di essa, il controllo di verifica
  universale V.2 (§3.5.2, punto 4: "verificare ogni σtoken con pkIdP")
  non sarebbe eseguibile da un osservatore esterno che non ha assistito
  alla sottomissione della scheda. L'inclusione non ha alcun costo in
  termini di segretezza, poiché l'informazione è già nota al Ballot
  Server al momento dell'accettazione e non introduce alcun legame con
  l'identità reale dell'elettore.
- **La randomness `r_enc` di OAEP non è mai esposta al chiamante**
  nell'implementazione del client, poiché generata internamente dalla
  libreria crittografica ad ogni cifratura. Conseguenza dichiarata: non
  è possibile, con questa particolare interfaccia, riprodurre nel
  codice lo scenario di vendita del voto per ritenzione di `r_enc`
  discusso in T.3 (§3.7) — l'analisi di WP3 resta comunque valida
  indipendentemente da questa scelta implementativa, che riguarda la
  dimostrabilità sperimentale del rischio, non la sua esistenza.

## 4.12 Limiti noti confermati dall'implementazione

L'implementazione non introduce mitigazioni ulteriori rispetto a quanto
dichiarato in WP3 per i rischi non mitigati (T.2, T.3, T.4): un client
compromesso, la vendita volontaria del voto e la correttezza della
decifratura non verificabile universalmente restano, per costruzione,
fuori dal perimetro di ciò che il codice può garantire — coerentemente
con l'analisi secondo cui colmarli richiederebbe strumenti (prove di
corretta decifratura, mixnet verificabili) esplicitamente fuori dal
perimetro del corso.
