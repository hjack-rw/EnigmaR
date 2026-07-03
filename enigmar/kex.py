"""
Diffie-Hellman key exchange, so two parties agree a shared secret over a PUBLIC
channel with nothing pre-shared — then feed it to `Channel` as the keyfile.

    a = Handshake(); b = Handshake()
    ka = a.shared(b.public)          # both sides compute the same 32-byte key
    kb = b.shared(a.public)          # ka == kb, never transmitted
    alice = Channel("", keyfile=ka, alphabet=Alphabet.of_bytes())
    bob   = Channel("", keyfile=kb, alphabet=Alphabet.of_bytes())

The secret is `g^(ab) mod p`; an eavesdropper sees g, p, g^a, g^b and still can't
get it (discrete log is infeasible for this 2048-bit group). Pure stdlib — Python
does the big-integer `pow` natively.

CAVEAT — this is UNAUTHENTICATED DH: it stops a passive eavesdropper, NOT an active
man-in-the-middle (who runs two exchanges, one with each side). For real use you must
authenticate the public keys (known/pinned keys, or sign them). And this is homemade,
unreviewed crypto — for real secrets use X25519/libsodium. Learning / sharing-for-fun
is the intended scope.
"""
import hashlib
import os

# RFC 3526 group 14 — a 2048-bit MODP safe prime, generator 2 (canonical chunks).
_P_HEX = "".join((
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1",
    "29024E088A67CC74020BBEA63B139B22514A08798E3404DD",
    "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245",
    "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED",
    "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D",
    "C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F",
    "83655D23DCA3AD961C62F356208552BB9ED529077096966D",
    "670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B",
    "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9",
    "DE2BCBF6955817183995497CEA956AE515D2261898FA0510",
    "15728E5A8AACAA68FFFFFFFFFFFFFFFF",
))
P = int(_P_HEX, 16)
G = 2
_PLEN = (P.bit_length() + 7) // 8         # bytes to hold a value mod P


class Handshake:
    """One party's half of a DH exchange. Keep it for one exchange (ephemeral)."""

    def __init__(self, priv: int | None = None):
        # Private exponent: 256 random bits is ample for a 2048-bit group.
        self._priv = priv if priv is not None else int.from_bytes(os.urandom(32), "big")
        self.public = pow(G, self._priv, P)          # send this in the clear

    def shared(self, their_public: int) -> bytes:
        """The 32-byte shared key from the peer's public value. Same on both sides,
        never transmitted. Use it as a keyfile. UNAUTHENTICATED (MITM — see module doc)."""
        if not 1 < their_public < P - 1:
            raise ValueError("invalid peer public key")
        secret = pow(their_public, self._priv, P)
        return hashlib.sha256(secret.to_bytes(_PLEN, "big")).digest()


class Identity:
    """A long-term identity keypair — the trust anchor. Share/pin `.public` with the
    peer out of band (verify the fingerprint); that pinned key is what authenticates
    the handshake. Keep the object (its private half) secret and long-lived."""

    def __init__(self, priv: int | None = None):
        self._priv = priv if priv is not None else int.from_bytes(os.urandom(32), "big")
        self.public = pow(G, self._priv, P)


def _check(pub: int) -> None:
    if not 1 < pub < P - 1:
        raise ValueError("invalid public key")


def authenticated_key(my_id: "Identity", my_eph: "Handshake",
                      their_id_pub: int, their_eph_pub: int, *, initiator: bool) -> bytes:
    """Authenticated session key (3-DH / mini-X3DH). Mixes the ephemeral DH with two
    identity-bound DHs, so a man-in-the-middle who lacks an identity private key derives
    a different key and fails the Channel MAC. `their_id_pub` must be the peer's *pinned*
    identity key. Both sides pass matching `initiator` roles (one True, one False)."""
    _check(their_id_pub)
    _check(their_eph_pub)

    def dh(base: int, exp: int) -> int:
        return pow(base, exp, P)

    t3 = dh(their_eph_pub, my_eph._priv)                 # ephemeral <-> ephemeral
    if initiator:
        t1 = dh(their_eph_pub, my_id._priv)              # my id  <-> their ephemeral
        t2 = dh(their_id_pub, my_eph._priv)              # my eph <-> their id
    else:
        t1 = dh(their_id_pub, my_eph._priv)              # their id  <-> my ephemeral
        t2 = dh(their_eph_pub, my_id._priv)              # their eph <-> my id
    h = hashlib.sha256()
    for t in (t1, t2, t3):
        h.update(t.to_bytes(_PLEN, "big"))
    return h.digest()
