"""
Manifest di elezione (§2.4.3) — l'oggetto che fissa, prima dell'apertura
delle urne, l'intero contesto crittografico dell'elezione, e che il
documento descrive come "il primo oggetto scaricato dal client di voto
prima di qualunque interazione con IdP e BS ... la radice di fiducia da
cui ogni successiva verifica deriva".

Senza il manifest ogni parametro pubblico (pk_BS, pk_IdP, pk_BS-srv,
head_0, i parametri (t,n) dello schema a soglia, la cardinalità del
corpo elettorale) arriverebbe a client e osservatori "sulla parola",
cioè dallo stesso canale o dalla stessa entità che si vuole poter
verificare — esattamente l'assunzione debole che §2.4.2 e §3.5.2
rifiutano altrove, dove il Ballot Server non si fida di una pkIdP già
pronta ma parte dal certificato. Il manifest è ciò che rende quei
parametri verificabili in blocco a partire dalla sola fiducia nella CA
(F.1): un solo oggetto firmato, e da lì deriva tutto il resto.

Chi firma. §2.4.3 richiede la firma di *tutti* i commissari più quella
della CA di Ateneo. È una soglia diversa da quella del tally bundle
(§2.8.2), che richiede solo i t commissari partecipanti: qui siamo
prima dell'apertura delle urne, nella cerimonia di §2.2.4 dove i 5
commissari sono riuniti fisicamente, quindi non c'è ragione di
accontentarsi di t. `verify_manifest` applica questa soglia più
stringente (tutti gli n) invece di riusare la logica a soglia della
Commissione.

Cosa NON garantisce: che i valori dichiarati siano quelli "giusti". Il
manifest lega insieme e rende non ripudiabili i parametri pubblicati,
non certifica che la Commissione abbia generato pk_BS onestamente
(F.3) né che il registro elettorale dietro `electorate_size` sia
corretto (F.5) — quest'ultima resta l'assunzione che §2.3 dichiara
mitigata "solo dalla cardinalità dichiarata nel manifest", cioè proprio
da questo campo, che rende almeno *rilevabile* una manipolazione della
cardinalità tramite `check_turnout_consistency`.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Callable, Sequence

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey, RSAPublicKey
from cryptography.hazmat.primitives.serialization import Encoding

from src.bulletin_board.bulletin_board import genesis_head
from src.ca.root_ca import verify_certificate_with_crl
from src.common.hashing import sha256
from src.common.keys import public_key_der
from src.common.signing import sign, verify

# Separazione di dominio: un digest di manifest non deve poter essere
# scambiato per un digest di un altro oggetto firmato del protocollo
# (ricevuta, testa, tally bundle) da chi verifica con la stessa chiave.
MANIFEST_DOMAIN_TAG = b"APS-WP4/election-manifest/v1"


def _field(value: bytes) -> bytes:
    """Campo con prefisso di lunghezza a 4 byte.

    Stessa ragione per cui `ballot_encoding` prefissa `election_id`:
    concatenare campi a lunghezza variabile senza delimitatori rende la
    codifica ambigua, e su un payload *firmato* l'ambiguità è un
    problema di sicurezza, non di parsing — due manifest diversi che
    producono gli stessi byte condividerebbero la stessa firma.
    """
    return len(value).to_bytes(4, "big") + value


def _text(value: str) -> bytes:
    return _field(value.encode("utf-8"))


def _integer(value: int) -> bytes:
    return _field(str(value).encode("ascii"))


def _certificate(certificate: x509.Certificate) -> bytes:
    return _field(certificate.public_bytes(Encoding.DER))


def _public_key(key: RSAPublicKey) -> bytes:
    return _field(public_key_der(key))


@dataclass(frozen=True)
class ElectionManifest:
    """I campi sono esattamente l'elenco puntato di §2.4.3, nello stesso
    ordine, così che la corrispondenza documento ↔ codice sia verificabile
    voce per voce."""

    # Identificativo dell'elezione e oggetto del referendum.
    election_id: str
    question: str
    options: tuple[bytes, ...]  # codifica canonica di {YES, NO} (§2.2.1)

    # Finestra temporale.
    voting_opens_at: datetime
    voting_closes_at: datetime

    # pk_BS + schema PKE adottato + primo pubblico p dello schema a soglia.
    encryption_public_key: RSAPublicKey
    pke_scheme: str
    pke_modulus_bits: int
    pke_hash: str
    shamir_prime: int
    shamir_threshold: int
    shamir_total_shares: int

    # pk_BS-srv, distinta da pk_BS, e pk_IdP.
    bs_signing_public_key: RSAPublicKey
    idp_signing_public_key: RSAPublicKey

    # Elenco dei commissari con i rispettivi certificati X.509.
    commissioner_certificates: tuple[x509.Certificate, ...]

    # Cardinalità del corpo elettorale (F.5).
    electorate_size: int

    # Indirizzi pubblici e certificati di trasporto.
    idp_endpoint: str
    ballot_server_endpoint: str
    bulletin_board_endpoint: str
    idp_tls_certificate: x509.Certificate
    bs_tls_certificate: x509.Certificate

    # Riferimento iniziale del Bulletin Board e tolleranza su head_ref.
    genesis_head: bytes
    head_reference_tolerance: int

    # Hash del client di voto ufficiale.
    voting_client_hash: bytes

    def canonical_bytes(self) -> bytes:
        """Serializzazione canonica: ogni campo a lunghezza prefissata,
        nessun separatore ambiguo, ordine fisso."""
        parts = [
            _field(MANIFEST_DOMAIN_TAG),
            _text(self.election_id),
            _text(self.question),
            _integer(len(self.options)),
            *(_field(option) for option in self.options),
            _text(self.voting_opens_at.isoformat()),
            _text(self.voting_closes_at.isoformat()),
            _public_key(self.encryption_public_key),
            _text(self.pke_scheme),
            _integer(self.pke_modulus_bits),
            _text(self.pke_hash),
            _integer(self.shamir_prime),
            _integer(self.shamir_threshold),
            _integer(self.shamir_total_shares),
            _public_key(self.bs_signing_public_key),
            _public_key(self.idp_signing_public_key),
            _integer(len(self.commissioner_certificates)),
            *(_certificate(certificate) for certificate in self.commissioner_certificates),
            _integer(self.electorate_size),
            _text(self.idp_endpoint),
            _text(self.ballot_server_endpoint),
            _text(self.bulletin_board_endpoint),
            _certificate(self.idp_tls_certificate),
            _certificate(self.bs_tls_certificate),
            _field(self.genesis_head),
            _integer(self.head_reference_tolerance),
            _field(self.voting_client_hash),
        ]
        return b"".join(parts)

    def signed_payload(self) -> bytes:
        """Il digest su cui firmano commissari e CA. Come ovunque nel
        prototipo, chi firma riceve un digest SHA-256 già calcolato."""
        return sha256(self.canonical_bytes())

    def expected_genesis_head(self) -> bytes:
        """head_0 = H(election_id ∥ timestamp_apertura) ricalcolato dai
        campi del manifest stesso (§2.4.3). Serve a `verify_manifest`:
        un `genesis_head` incoerente con l'election_id e l'orario di
        apertura dichiarati renderebbe il manifest inutilizzabile come
        ancora della catena del BB, ed è meglio scoprirlo alla verifica
        della firma che alla prima entry."""
        return genesis_head(self.election_id, self.voting_opens_at.isoformat())


@dataclass(frozen=True)
class SignedElectionManifest:
    """Il manifest pubblicato: i dati più le firme che li rendono non
    ripudiabili. `commissioner_signatures` è nello stesso ordine di
    `manifest.commissioner_certificates`."""

    manifest: ElectionManifest
    commissioner_signatures: tuple[bytes, ...]
    ca_signature: bytes


class ManifestSigningError(Exception):
    """Il materiale fornito non può produrre un manifest verificabile."""


def sign_manifest(
    manifest: ElectionManifest,
    commissioner_signing_keys: Sequence[RSAPrivateKey],
    ca_countersign: Callable[[bytes], bytes],
) -> SignedElectionManifest:
    """Firma congiunta di §2.4.3: tutti i commissari più la CA.

    Le chiavi dei commissari vanno passate nello stesso ordine dei
    certificati elencati nel manifest. Il controllo di corrispondenza
    chiave ↔ certificato non è pedanteria: firmare con una chiave che non
    è quella del certificato pubblicato produrrebbe un manifest
    sintatticamente completo ma che nessun verificatore accetterebbe mai,
    e l'errore si scoprirebbe solo a urne aperte.

    La CA entra come funzione (`UniversityCA.countersign`) e non come
    chiave: skCA non deve uscire dalla CA nemmeno per firmare il
    manifest.
    """
    if len(commissioner_signing_keys) != len(manifest.commissioner_certificates):
        raise ManifestSigningError(
            f"servono esattamente {len(manifest.commissioner_certificates)} chiavi di firma "
            f"(una per commissario elencato nel manifest), ricevute {len(commissioner_signing_keys)}"
        )

    payload = manifest.signed_payload()
    signatures = []
    """
    zip prende due liste iterabili e li mette insieme, ovvero commissioner_signing_keys = [key1, key2 ...] e certificates
    [cert1, cert2...] quindi diventa[ (key1, cert1) ...], enumerate inserisce un contatore all'inizio quindi diventa:
    [(1,(key1, cert1), ...] ad ogni ciclo devo spacchettare il valore per avere i valori singoli 
    """
    for index, (key, certificate) in enumerate(zip(commissioner_signing_keys, manifest.commissioner_certificates), 1):
        """
        Per ogni coppia key.public_key e certificate.public_key
        controlla che la chiave pubblica della chiave di firma 
        sia uguale alla chiave pubblica contenuta nel certificato.
        """
        if public_key_der(key.public_key()) != public_key_der(certificate.public_key()):
            raise ManifestSigningError(
                f"la chiave del commissario in posizione {index} non corrisponde al certificato "
                f"pubblicato nel manifest per quella stessa posizione"
            )
        signatures.append(sign(key, payload))

    return SignedElectionManifest(
        manifest=manifest,
        commissioner_signatures=tuple(signatures),
        ca_signature=ca_countersign(payload),
    )



"""
Verifica la validità del manifest firmato utilizzando il certificato della CA,
opzionalmente (perchè abbiamo messo None) controllando la CRL e usando una data/ora specifica per la verifica.
"""
def verify_manifest(
    signed: SignedElectionManifest,
    ca_certificate: x509.Certificate,
    crl: x509.CertificateRevocationList | None = None,
    now: datetime | None = None,
) -> bool:
    """V.2 punto 2 ("verificare ogni firma del manifest") dal punto di
    vista di chi ha in mano solo artefatti pubblici.

    Controlli, in ordine, fermandosi al primo fallimento:

      1. coerenza interna: head_0 ricalcolabile dai campi dichiarati,
         finestra temporale sensata, (t,n) coerenti fra loro e con il
         numero di commissari elencati;
      2. una firma per commissario elencato;
      3. firma della CA sul digest del manifest;
      4. per ogni commissario: certificato autentico/valido/non revocato
         rispetto alla CA (F.1), Key Usage adeguata alla firma, e firma
         valida sul digest.

    Il punto 4 richiede `digitalSignature` e NON RIPUDIO per la
    stessa ragione spiegata in `verify_token_as_ballot_server`: il solo
    `digitalSignature` è acceso anche sui certificati TLS, quindi
    se ci volessi "accontentare" accetterebbe un manifest firmato con una chiave di
    trasporto invece che con quella personale del commissario.
    """
    manifest = signed.manifest

    # 1. Coerenza interna.
    if manifest.genesis_head != manifest.expected_genesis_head():
        return False
    if manifest.voting_opens_at >= manifest.voting_closes_at:
        return False
    if not (1 <= manifest.shamir_threshold <= manifest.shamir_total_shares):
        return False
    if len(manifest.commissioner_certificates) != manifest.shamir_total_shares:
        return False
    if manifest.electorate_size < 0 or manifest.head_reference_tolerance < 1:
        return False

    # 2. Una firma per commissario: §2.4.3 vuole la firma di tutti perchè sul Manifest voglio che tutti lo accettino,
    #    non di t, quindi threshold come nel tally bundle.
    if len(signed.commissioner_signatures) != len(manifest.commissioner_certificates):
        return False

    payload = manifest.signed_payload()

    # 3. Firma della CA.
    ca_public_key = ca_certificate.public_key()
    if not isinstance(ca_public_key, RSAPublicKey):
        return False
    if not verify(ca_public_key, payload, signed.ca_signature):
        return False

    # 4. Catena di fiducia e firma di ogni commissario.
    """
    Abbina:
    certificato 1 alla firma 1 con zip  e poi controllo con il Certificate Revocation List
    """
    for certificate, signature in zip(manifest.commissioner_certificates, signed.commissioner_signatures):
        if not verify_certificate_with_crl(certificate, ca_certificate, crl, now):
            return False

        """
        Controllo se nel certificato X.509 c'è l'uso della chiave altrimenti fallise il controllo
        """
        try:
            key_usage = certificate.extensions.get_extension_for_class(x509.KeyUsage).value
        except x509.ExtensionNotFound:
            return False
        if not (key_usage.digital_signature and key_usage.content_commitment):
            return False

        commissioner_public_key = certificate.public_key()
        if not isinstance(commissioner_public_key, RSAPublicKey):
            return False
        if not verify(commissioner_public_key, payload, signature):
            return False

    return True


def check_turnout_consistency(manifest: ElectionManifest, tokens_issued: int, ballots_registered: int) -> bool:
    """V.2 punto 9: confronto fra token emessi, schede registrate e
    cardinalità del corpo elettorale dichiarata nel manifest.

    È il controllo che abbiamo descritto in §2.3 dove l'unica mitigazione (parziale)
    dell'assunzione F.5 sulla correttezza del registro elettorale: non
    dimostra che il registro sia onesto, ma rende rilevabile il caso in
    cui i token emessi eccedano gli aventi diritto dichiarati prima
    dell'apertura delle urne — cioè la manipolazione della cardinalità
    di cui parla §1.2 a proposito del ballot stuffing.

    Non rileva il ballot stuffing "entro la cardinalità" (token emessi
    per astenuti reali): quello resta rilevabile solo a posteriori dalla
    lista firmata dei partecipanti di §2.8, come il documento dichiara.
    """
    if tokens_issued < 0 or ballots_registered < 0:
        return False
    if tokens_issued > manifest.electorate_size:
        return False
    return ballots_registered <= tokens_issued
