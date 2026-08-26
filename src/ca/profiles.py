"""
Profili di estensioni X.509, presi dalle sezioni di `openssl.cnf` del Lab
4. Il laboratorio sceglie le estensioni al momento della firma con
`openssl ca -extensions <sezione>` (v3_ca, v3_intermediate_ca,
server_cert, usr_cert); qui ogni sezione diventa un `ExtensionProfile`
con gli stessi flag, così la CA si limita a selezionarlo invece di
costruire le estensioni inline ogni volta.

Manca `v3_intermediate_ca` di proposito: il Lab usa una CA a due livelli
(root + intermedia), ma §2.3 assume una sola CA di Ateneo, quindi
aggiungere un'intermedia vorrebbe dire inventare fiducia che il documento
non prevede.

Ho anche aggiunto un profilo che il Lab non ha, `signing_cert`: le
chiavi di firma di IdP e BS non devono mai cifrare nulla, quindi è
`usr_cert` meno `keyEncipherment` — l'unica differenza dal laboratorio,
e va nella direzione più restrittiva, non il contrario.
"""
from __future__ import annotations

from dataclasses import dataclass
import enum

from cryptography import x509
from cryptography.x509.oid import ExtendedKeyUsageOID


class EntityRole(enum.Enum):
    """Ruoli per cui la CA emette certificati (§2.3, §2.4). Ognuno ha il
    suo Key Usage: dare più permessi del necessario romperebbe il least
    privilege su cui si regge la separazione IdP/BS."""

    IDP_TLS = "idp_tls"                # canale autenticato elettore <-> IdP
    IDP_TOKEN_SIGNING = "idp_signing"  # pkIdP, firma dei token di voto (§2.4.2)
    BS_TLS = "bs_tls"                  # canale autenticato elettore <-> BS
    BS_SIGNING = "bs_signing"          # pkBS-server, firma ricevute/teste BB
    COMMISSIONER = "commissioner"      # firma manifest + cifratura share Shamir


@dataclass(frozen=True)
class ExtensionProfile:
    """Una sezione di `openssl.cnf`, come dato invece che come voce di
    file. `name` è il nome della sezione originale, giusto per poter
    risalire a quale parte del .cnf del Lab corrisponde."""

    name: str
    basic_constraints: x509.BasicConstraints
    key_usage: x509.KeyUsage
    extended_key_usage: x509.ExtendedKeyUsage | None = None

    @property
    def is_ca(self) -> bool:
        return self.basic_constraints.ca


def _key_usage(**enabled: bool) -> x509.KeyUsage:
    """
    `x509.KeyUsage` vuole tutti e nove i flag ad ogni chiamata, mentre in
    openssl.cnf si scrive solo quello che si accende
    (`keyUsage = critical, digitalSignature, keyEncipherment`). Questo
    helper fa la stessa cosa: passa solo i flag `True` che ti servono.
    """
    defaults = dict(
        digital_signature=False,
        content_commitment=False,   # nonRepudiation in openssl.cnf
        key_encipherment=False,
        data_encipherment=False,
        key_agreement=False,
        key_cert_sign=False,
        crl_sign=False,
        encipher_only=False,
        decipher_only=False,
    )
    unknown = set(enabled) - set(defaults)
    if unknown:
        raise ValueError(f"Flag KeyUsage inesistenti: {sorted(unknown)}")
    return x509.KeyUsage(**{**defaults, **enabled})


# [ v3_ca ] del Lab 4: basicConstraints CA:true, keyUsage digitalSignature
# + cRLSign + keyCertSign. Ho aggiunto `pathlen:0`, che il Lab non mette
# (lì la root firma un'intermedia): qui c'è una sola CA, quindi pathlen:0
# blocca esplicitamente la creazione di sotto-CA. cRLSign serve perché la
# CA deve poter firmare la CRL quando revoca la chiave dell'IdP (§2.4.2).
V3_CA = ExtensionProfile(
    name="v3_ca",
    basic_constraints=x509.BasicConstraints(ca=True, path_length=0),
    key_usage=_key_usage(digital_signature=True, crl_sign=True, key_cert_sign=True),
)

# [ server_cert ] del Lab 4: CA:FALSE, digitalSignature + keyEncipherment,
# serverAuth. Ometto nsCertType/nsComment: sono estensioni Netscape ormai
# ignorate da qualsiasi verificatore.
SERVER_CERT = ExtensionProfile(
    name="server_cert",
    basic_constraints=x509.BasicConstraints(ca=False, path_length=None),
    key_usage=_key_usage(digital_signature=True, key_encipherment=True),
    extended_key_usage=x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]),
)

# [ usr_cert ] del Lab 4: CA:FALSE, nonRepudiation + digitalSignature +
# keyEncipherment, clientAuth + emailProtection.
USR_CERT = ExtensionProfile(
    name="usr_cert",
    basic_constraints=x509.BasicConstraints(ca=False, path_length=None),
    key_usage=_key_usage(
        digital_signature=True, content_commitment=True, key_encipherment=True
    ),
    extended_key_usage=x509.ExtendedKeyUsage(
        [ExtendedKeyUsageOID.CLIENT_AUTH, ExtendedKeyUsageOID.EMAIL_PROTECTION]
    ),
)

# signing_cert: usr_cert senza keyEncipherment, per chiavi che devono solo
# firmare (vedi il docstring in cima al file).
SIGNING_CERT = ExtensionProfile(
    name="signing_cert",
    basic_constraints=x509.BasicConstraints(ca=False, path_length=None),
    key_usage=_key_usage(digital_signature=True, content_commitment=True),
    extended_key_usage=x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH]),
)


PROFILE_FOR_ROLE: dict[EntityRole, ExtensionProfile] = {
    EntityRole.IDP_TLS: SERVER_CERT,
    EntityRole.BS_TLS: SERVER_CERT,
    EntityRole.IDP_TOKEN_SIGNING: SIGNING_CERT,
    EntityRole.BS_SIGNING: SIGNING_CERT,
    EntityRole.COMMISSIONER: USR_CERT,
}


def profile_for_role(role: EntityRole) -> ExtensionProfile:
    """Sezione di `openssl.cnf` da usare per il ruolo dato."""
    try:
        return PROFILE_FOR_ROLE[role]
    except KeyError:
        raise ValueError(f"Ruolo non riconosciuto: {role}") from None
