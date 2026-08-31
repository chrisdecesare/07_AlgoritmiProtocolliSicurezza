"""
Bulletin Board — registro pubblico append-only (§2.7): la catena di
hash head_i = H(head_{i-1} ∥ IDseq ∥ C ∥ pk_voter ∥ token_id) rende
rilevabile ogni modifica parziale a una entry passata — cambiare
un'entry i cambia head_i e quindi ogni head successivo (§3.4.3).

Come discusso in §2.7.1 e ribadito in §3.4.3/F.8, la catena di hash da
sola rileva solo modifiche *parziali*: un BS disonesto che riscrivesse
l'intero registro da zero produrrebbe una catena internamente coerente
ma diversa da quella osservata da terzi. La contromisura (archiviazione
periodica delle teste firmate da osservatori indipendenti) sta nel
Ballot Server, che possiede la chiave di firma; qui c'è solo la
struttura dati e la sua verifica interna (`verify_hash_chain`, V.2
punto 3).

`append()` è pubblico ma va chiamato solo dal Ballot Server
("scrivibile solo dal BS", §2.3) — qui, come in `CertificateStore`
della CA, la restrizione è di disegno/convenzione, non imposta a
livello di linguaggio.
"""
from __future__ import annotations

from dataclasses import dataclass

from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey

from src.common.hashing import sha256
from src.common.keys import public_key_der


@dataclass(frozen=True)
class BulletinBoardEntry:
    """Una entry del BB (§2.7, passo 7). `token_signature` (σ_token) non
    è nella tupla elencata testualmente al passo 7, ma senza di essa il
    controllo V.2 punto 4 di WP3 ("verificare ogni σtoken con pkIdP")
    non sarebbe eseguibile da un osservatore esterno che non abbia
    assistito alla sottomissione — la includo qui, deviazione dichiarata
    dal testo letterale di §2.7 per rendere possibile la verifica
    universale che WP3 promette. Non costa nulla in segretezza: è
    un'informazione già nota al BS al momento dell'accettazione."""

    id_seq: int
    ciphertext: bytes
    voter_public_key: RSAPublicKey
    token_id: bytes
    token_signature: bytes
    head_ref: bytes
    voter_signature: bytes
    head: bytes


def genesis_head(election_id: str, opening_timestamp: str) -> bytes:
    """head_0 = H(election_id ∥ timestamp_apertura) (§2.4.3), radice
    della catena, calcolato e pubblicato nel manifest prima
    dell'apertura delle urne."""
    return sha256(election_id.encode("utf-8"), opening_timestamp.encode("utf-8"))


def compute_next_head(
    previous_head: bytes, id_seq: int, ciphertext: bytes, voter_public_key: RSAPublicKey, token_id: bytes
) -> bytes:
    """head_i = H(head_{i-1} ∥ IDseq ∥ C ∥ pk_voter ∥ token_id) (§2.7, passo 6)."""
    return sha256(
        previous_head,
        id_seq.to_bytes(8, "big"),
        ciphertext,
        public_key_der(voter_public_key),
        token_id,
    )


class BulletinBoard:
    """Registro append-only di una singola elezione. `genesis` è head_0,
    calcolato dal manifest prima che arrivi la prima scheda."""

    def __init__(self, genesis: bytes):
        self._genesis = genesis
        self._entries: list[BulletinBoardEntry] = []

    @property
    def genesis(self) -> bytes:
        return self._genesis

    @property
    def current_head(self) -> bytes:
        return self._entries[-1].head if self._entries else self._genesis

    @property
    def entries(self) -> tuple[BulletinBoardEntry, ...]:
        return tuple(self._entries)

    def next_sequence_number(self) -> int:
        return len(self._entries) + 1

    def append(
        self,
        ciphertext: bytes,
        voter_public_key: RSAPublicKey,
        token_id: bytes,
        token_signature: bytes,
        head_ref: bytes,
        voter_signature: bytes,
    ) -> BulletinBoardEntry:
        """Solo il Ballot Server dovrebbe chiamarlo, dopo aver già
        eseguito tutti i controlli di §2.7 (validità token, unicità,
        integrità, coerenza della testa) — qui non si ripete nulla di
        quello, ci si limita a calcolare la nuova testa e ad accodare."""
        id_seq = self.next_sequence_number()
        new_head = compute_next_head(self.current_head, id_seq, ciphertext, voter_public_key, token_id)
        entry = BulletinBoardEntry(
            id_seq=id_seq,
            ciphertext=ciphertext,
            voter_public_key=voter_public_key,
            token_id=token_id,
            token_signature=token_signature,
            head_ref=head_ref,
            voter_signature=voter_signature,
            head=new_head,
        )
        self._entries.append(entry)
        return entry


def verify_hash_chain(genesis: bytes, entries: tuple[BulletinBoardEntry, ...]) -> bool:
    """Ricalcolo indipendente della catena di hash (§3.5.2, V.2 punto
    3): chiunque, dati genesis + entries pubbliche, può verificare che
    ogni head sia coerente con la precedente senza fidarsi del BS."""
    previous_head = genesis
    for entry in entries:
        expected_head = compute_next_head(
            previous_head, entry.id_seq, entry.ciphertext, entry.voter_public_key, entry.token_id
        )
        if expected_head != entry.head:
            return False
        previous_head = entry.head
    return True
