"""
Sealed-code logic for the browser demo, running the REAL enigmar engine.

The format-preserving step is enigmar.FPE, which derives and runs an actual
Enigma (rotors, reflector, plugboard) keyed by the passphrase and the per-code
nonce, then combines by modular add over the code's own alphabet. The serial
rides in the clear as that nonce, so every code drives a different machine (no
shared keystream). An HMAC-SHA256 tag inside the code does the sealing.

Demo tuning: the passphrase stretch is swapped from scrypt (2**16, ~tens of ms
of memory-hard work per call) to pbkdf2 so the whole thing stays snappy inside
Pyodide/WASM. Only the key-stretch changes; the rotor engine is the real thing.
"""
import hmac
import hashlib

import enigmar.cipher as _cipher


def _demo_kdf(passphrase, salt, *, n=None, dklen=64):
    # Pyodide's hashlib ships without the OpenSSL-backed KDFs (no pbkdf2_hmac,
    # no scrypt), so stretch with plain sha256 in counter mode. Light on purpose:
    # this is a demo and the key isn't secret in the browser anyway. Deterministic,
    # so mint and check agree.
    if isinstance(passphrase, str):
        passphrase = passphrase.encode()
    base = passphrase + b"|" + salt
    out, block = b"", 0
    while len(out) < dklen:
        h = base + block.to_bytes(4, "big")
        for _ in range(1000):
            h = hashlib.sha256(h).digest()
        out += h
        block += 1
    return out[:dklen]


_cipher._scrypt = _demo_kdf   # patch before any machine is derived

from enigmar import FPE  # noqa: E402

ALPH = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"   # 32, no I/L/O/U
N = 32
W_ID, W_DISC, W_EXP, W_SER, W_TAG = 3, 1, 3, 3, 5
W_SEC = W_ID + W_DISC + W_EXP    # 7  — permuted payload
W_BODY = W_SEC + W_TAG           # 12 — permuted body (payload + tag)
W_CODE = W_SER + W_BODY          # 15 — clear nonce + body


def _enc_int(v, w):
    o = ""
    for _ in range(w):
        o = ALPH[v % N] + o
        v //= N
    return o


def _dec_int(s):
    v = 0
    for c in s:
        v = v * N + ALPH.index(c)
    return v


def _tag(key, msg):
    b = hmac.new((key + "|mac").encode(), msg.encode(), hashlib.sha256).digest()
    return _enc_int(int.from_bytes(b[:4], "big") % (N ** W_TAG), W_TAG)


def _fpe(key, nonce):
    return FPE(key, ALPH, nonce=nonce)


def _group(s):
    return "-".join(s[i:i + 5] for i in range(0, len(s), 5))


def mint(key, cid, disc, exp, ser, brand=""):
    key, brand = str(key), str(brand).upper()
    cid, disc, exp, ser = int(cid), int(disc), int(exp), int(ser)
    nonce = _enc_int(ser, W_SER)                                   # clear per-code nonce
    payload = _enc_int(cid, W_ID) + _enc_int(disc, W_DISC) + _enc_int(exp, W_EXP)
    body = payload + _tag(key, brand + "|" + nonce + payload)     # brand is bound into the tag
    sealed = _fpe(key, nonce).encrypt(body)                       # real Enigma runs here
    return _group(nonce + sealed)


def check(key, code, brand=""):
    key, code, brand = str(key), str(code), str(brand).upper()
    raw = "".join(c for c in code.upper() if c in ALPH)
    if len(raw) != W_CODE:
        return None
    nonce = raw[:W_SER]
    body = _fpe(key, nonce).decrypt(raw[W_SER:])
    payload, t = body[:W_SEC], body[W_SEC:]
    if t != _tag(key, brand + "|" + nonce + payload):            # wrong brand -> tag mismatch
        return None
    return {
        "id": _dec_int(payload[:3]),
        "discount": _dec_int(payload[3:4]),
        "expiry": _dec_int(payload[4:7]),
        "serial": _dec_int(nonce),
        "brand": brand,
    }
