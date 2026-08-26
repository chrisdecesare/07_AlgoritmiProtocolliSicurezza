"""
`index.txt` + `serial` + `crlnumber`, lo "storage" della CA nel Lab 4:
senza questi file non ci sarebbero né serial univoci né revoca/CRL.

Il formato di `index.txt` è quello vero di `openssl ca`, sei campi
separati da TAB:

    <stato>  <scadenza>  <revoca>  <serial>  <file>  <subject DN>

stato V/R/E, date in UTCTime ASN.1, serial esadecimale, campo file
sempre "unknown". L'ho tenuto identico a quello del laboratorio apposta,
per poterlo confrontare riga per riga.

`directory=None` tiene tutto in memoria (comodo per test e demo); passando
una cartella si ottengono gli stessi tre file su disco, leggibili con un
editor qualsiasi — proprio come nel Lab.
"""
from __future__ import annotations

import datetime
import pathlib
from dataclasses import dataclass

from cryptography import x509

# Il laboratorio inizializza il file `serial` con "1000" (esadecimale).
FIRST_SERIAL = 0x1000
# Idem per `crlnumber`, che numera progressivamente le CRL emesse.
FIRST_CRL_NUMBER = 0x1000

_UTCTIME = "%y%m%d%H%M%SZ"


def _format_time(moment: datetime.datetime) -> str:
    """Data in UTCTime ASN.1 (`YYMMDDHHMMSSZ`), come nelle righe di index.txt."""
    return moment.astimezone(datetime.timezone.utc).strftime(_UTCTIME)


@dataclass
class IndexEntry:
    """Una riga di `index.txt`."""

    status: str  # 'V' valid, 'R' revoked, 'E' expired
    expires_at: datetime.datetime
    revoked_at: datetime.datetime | None
    serial: int
    subject: str  # DN in forma OpenSSL, es. /C=IT/O=Ateneo/CN=idp.unisa.it

    def to_line(self) -> str:
        revoked = _format_time(self.revoked_at) if self.revoked_at is not None else ""
        return "\t".join(
            [
                self.status,
                _format_time(self.expires_at),
                revoked,
                f"{self.serial:X}",
                "unknown",
                self.subject,
            ]
        )


def openssl_dn(name: x509.Name) -> str:
    """DN in notazione OpenSSL (`/C=IT/O=.../CN=...`). `rfc4514_string()`
    darebbe l'ordine inverso separato da virgole, ma `index.txt` vuole
    questo formato."""
    return "".join(f"/{attribute.rfc4514_attribute_name}={attribute.value}" for attribute in name)


class CertificateStore:
    """`index.txt` + `serial` + `crlnumber` di una CA. Ogni CA ha il suo
    store, come nel Lab dove root e intermedia hanno ciascuna la propria
    copia dei tre file."""

    def __init__(self, directory: pathlib.Path | None = None):
        self._directory = directory
        self._entries: list[IndexEntry] = []
        self._next_serial = FIRST_SERIAL
        self._next_crl_number = FIRST_CRL_NUMBER

        if directory is not None:
            directory.mkdir(parents=True, exist_ok=True)
            self._flush()

    # ------------------------------------------------------------------ #
    # serial
    # ------------------------------------------------------------------ #

    def next_serial(self) -> int:
        """Prossimo numero di serie, progressivo e non casuale (è così che
        funziona il file `serial` del Lab). Deve essere univoco per CA
        perché è quello che identifica un certificato in una CRL."""
        serial = self._next_serial
        self._next_serial += 1
        self._write("serial", f"{self._next_serial:X}\n")
        return serial

    def next_crl_number(self) -> int:
        """Consuma e restituisce il prossimo numero di CRL (file `crlnumber`)."""
        number = self._next_crl_number
        self._next_crl_number += 1
        self._write("crlnumber", f"{self._next_crl_number:X}\n")
        return number

    # ------------------------------------------------------------------ #
    # index.txt
    # ------------------------------------------------------------------ #

    def record(self, certificate: x509.Certificate) -> IndexEntry:
        """Registra un certificato appena emesso con stato `V` (valid)."""
        entry = IndexEntry(
            status="V",
            expires_at=certificate.not_valid_after_utc,
            revoked_at=None,
            serial=certificate.serial_number,
            subject=openssl_dn(certificate.subject),
        )
        self._entries.append(entry)
        self._flush()
        return entry

    def revoke(self, serial: int, when: datetime.datetime | None = None) -> IndexEntry:
        """Marca come revocato (`R`) il certificato con quel serial —
        `openssl ca -revoke`. Revocare due volte lo stesso certificato è
        un errore, non un no-op: se succede vuol dire che chi chiama ha
        perso traccia dello stato dei propri certificati."""
        entry = self.find(serial)
        if entry is None:
            raise KeyError(f"nessun certificato con serial {serial:#x} in index.txt")
        if entry.status == "R":
            raise ValueError(f"il certificato {serial:#x} risulta già revocato")

        entry.status = "R"
        entry.revoked_at = when or datetime.datetime.now(datetime.timezone.utc)
        self._flush()
        return entry

    def find(self, serial: int) -> IndexEntry | None:
        return next((entry for entry in self._entries if entry.serial == serial), None)

    def is_revoked(self, serial: int) -> bool:
        entry = self.find(serial)
        return entry is not None and entry.status == "R"

    @property
    def entries(self) -> tuple[IndexEntry, ...]:
        return tuple(self._entries)

    @property
    def revoked(self) -> tuple[IndexEntry, ...]:
        return tuple(entry for entry in self._entries if entry.status == "R")

    def index_txt(self) -> str:
        """Contenuto di `index.txt`, nel formato del tool `openssl ca`."""
        return "".join(f"{entry.to_line()}\n" for entry in self._entries)

    # ------------------------------------------------------------------ #
    # Persistenza su disco (solo se è stata data una directory)
    # ------------------------------------------------------------------ #

    def _write(self, filename: str, content: str) -> None:
        if self._directory is not None:
            (self._directory / filename).write_text(content, encoding="ascii")

    def _flush(self) -> None:
        self._write("index.txt", self.index_txt())
        self._write("serial", f"{self._next_serial:X}\n")
        self._write("crlnumber", f"{self._next_crl_number:X}\n")
