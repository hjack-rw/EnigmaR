"""
End-to-end session over the engine — a Signal-style double ratchet.

A symmetric ratchet gives a fresh key per message (forward secrecy); a DH ratchet
runs automatically each time the conversation turns (each message carries the
sender's current DH public), folding a fresh DH secret into the root for
post-compromise security. Out-of-order and skipped messages are handled by caching
their keys (bounded by MAX_SKIP).

    root = authenticated_key(...)                 # same on both sides from the handshake
    alice = Session.initiator(root, bob_eph.public)   # bob_eph = Bob's handshake ephemeral
    bob   = Session.responder(root, bob_eph)          # ...its keypair, reused as Bob's DHs
    blob  = alice.send(b"hi");  bob.receive(blob)  # -> b"hi"

`to_dict()` / `from_dict()` serialise the whole ratchet state so a CLI can persist it
between invocations. Homemade and unreviewed — for real secrets use libsignal.
"""
import base64
import hashlib
import hmac

from .cipher import Channel
from .kex import P, Handshake
from .machine import Alphabet

_BYTES = Alphabet.of_bytes()
_FAST_KDF = 2 ** 8            # message keys are already full-entropy; cheap KDF is fine
_PLEN = (P.bit_length() + 7) // 8
MAX_SKIP = 256               # cap on cached out-of-order message keys


def _hmac(key: bytes, *parts: bytes) -> bytes:
    m = hmac.new(key, digestmod=hashlib.sha256)
    for p in parts:
        m.update(p)
    return m.digest()


def _kdf_rk(rk: bytes, dh_out: bytes):
    """Root KDF: (new root key, chain key) from the old root and a DH output."""
    return _hmac(rk, dh_out, b"rk"), _hmac(rk, dh_out, b"ck")


def _kdf_ck(ck: bytes):
    """Chain KDF: (next chain key, message key) — one-way, so it only moves forward."""
    return _hmac(ck, b"ck"), _hmac(ck, b"mk")


def _dh(keypair: Handshake, their_pub: int) -> bytes:
    return pow(their_pub, keypair._priv, P).to_bytes(_PLEN, "big")


class Session:
    """Double ratchet. Build with `initiator()` / `responder()`, not directly."""

    def __init__(self):
        self.dhs = None          # our current DH keypair (Handshake)
        self.dhr = None          # their current DH public (int) or None
        self.rk = b""            # root key
        self.cks = None          # sending chain key or None
        self.ckr = None          # receiving chain key or None
        self.ns = self.nr = self.pn = 0
        self.skipped = {}        # (their_dh_pub, n) -> message key

    # --- construction ---------------------------------------------------------
    @classmethod
    def initiator(cls, root: bytes, peer_dh_pub: int) -> "Session":
        s = cls()
        s.dhs = Handshake()
        s.dhr = peer_dh_pub
        s.rk, s.cks = _kdf_rk(root, _dh(s.dhs, s.dhr))
        return s

    @classmethod
    def responder(cls, root: bytes, dh_keypair: Handshake) -> "Session":
        s = cls()
        s.dhs = dh_keypair
        s.rk = root
        return s

    # --- messaging ------------------------------------------------------------
    def send(self, data: bytes) -> str:
        self.cks, mk = _kdf_ck(self.cks)
        header = (self.dhs.public.to_bytes(_PLEN, "big")
                  + self.pn.to_bytes(4, "big") + self.ns.to_bytes(4, "big"))
        self.ns += 1
        nonce, ct, tag = self._channel(mk).send(data)
        body = bytes.fromhex(nonce) + bytes.fromhex(tag) + ct
        return base64.b64encode(header + body).decode()

    def receive(self, blob: str) -> bytes:
        raw = base64.b64decode(blob)
        dh_pub = int.from_bytes(raw[:_PLEN], "big")
        pn = int.from_bytes(raw[_PLEN:_PLEN + 4], "big")
        n = int.from_bytes(raw[_PLEN + 4:_PLEN + 8], "big")
        body = raw[_PLEN + 8:]

        cached = self.skipped.pop((dh_pub, n), None)
        if cached is not None:
            return self._open(cached, body)
        if dh_pub != self.dhr:
            self._skip(pn)
            self._dh_ratchet(dh_pub)
        self._skip(n)
        self.ckr, mk = _kdf_ck(self.ckr)
        self.nr += 1
        return self._open(mk, body)

    # --- ratchet internals ----------------------------------------------------
    def _skip(self, until: int) -> None:
        if self.ckr is None:
            return
        if until - self.nr > MAX_SKIP:
            raise ValueError("too many skipped messages")
        while self.nr < until:
            self.ckr, mk = _kdf_ck(self.ckr)
            self.skipped[(self.dhr, self.nr)] = mk
            self.nr += 1

    def _dh_ratchet(self, their_dh_pub: int) -> None:
        self.pn, self.ns, self.nr = self.ns, 0, 0
        self.dhr = their_dh_pub
        self.rk, self.ckr = _kdf_rk(self.rk, _dh(self.dhs, self.dhr))
        self.dhs = Handshake()
        self.rk, self.cks = _kdf_rk(self.rk, _dh(self.dhs, self.dhr))

    def _channel(self, key: bytes) -> Channel:
        return Channel("", keyfile=key, kdf_n=_FAST_KDF, alphabet=_BYTES)

    def _open(self, mk: bytes, body: bytes) -> bytes:
        nonce, tag, ct = body[:16].hex(), body[16:48].hex(), body[48:]
        return self._channel(mk).receive(nonce, ct, tag)

    # --- persistence (for a CLI that runs across processes) -------------------
    def to_dict(self) -> dict:
        return {
            "dhs_priv": format(self.dhs._priv, "x"), "dhs_pub": format(self.dhs.public, "x"),
            "dhr": None if self.dhr is None else format(self.dhr, "x"),
            "rk": self.rk.hex(),
            "cks": None if self.cks is None else self.cks.hex(),
            "ckr": None if self.ckr is None else self.ckr.hex(),
            "ns": self.ns, "nr": self.nr, "pn": self.pn,
            "skipped": {f"{k[0]:x}:{k[1]}": v.hex() for k, v in self.skipped.items()},
        }

    @classmethod
    def from_dict(cls, d: dict) -> "Session":
        s = cls()
        s.dhs = Handshake(int(d["dhs_priv"], 16))
        s.dhr = None if d["dhr"] is None else int(d["dhr"], 16)
        s.rk = bytes.fromhex(d["rk"])
        s.cks = None if d["cks"] is None else bytes.fromhex(d["cks"])
        s.ckr = None if d["ckr"] is None else bytes.fromhex(d["ckr"])
        s.ns, s.nr, s.pn = d["ns"], d["nr"], d["pn"]
        for k, v in d["skipped"].items():
            pub, n = k.split(":")
            s.skipped[(int(pub, 16), int(n))] = bytes.fromhex(v)
        return s
