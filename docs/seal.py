"""
Sealed-code logic for the browser demo, running the REAL enigmar engine.

Two schemes live here so the demo can switch between them and show the contrast:

  - "classic": a per-code serial rides in the clear as the FPE nonce, with an
    HMAC tag encrypted next to the payload. Simple, but the serial leaks and the
    nonce is reusable.
  - "siv": enigmar.SealedCode — RFC 5297 deterministic AE, where the HMAC tag
    doubles as the nonce. Nothing rides in the clear (the serial is encrypted
    too) and there is no nonce left to reuse.

Both drive the same Enigma (rotors, reflector, plugboard) through enigmar.FPE and
seal with HMAC-SHA256; only the sealing construction differs. Everything is
client-side.

Demo tuning: the passphrase stretch is swapped from scrypt (2**16, memory-hard)
to a light sha256 counter-mode KDF so the whole thing stays snappy inside
Pyodide/WASM, which ships no OpenSSL-backed KDFs. Only the key-stretch changes;
the rotor engine and the sealing constructions are the real thing.
"""
import hmac
import hashlib

import enigmar.cipher as _cipher
import enigmar.sealed as _sealed


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


# Patch the KDF in BOTH namespaces that resolve it: cipher (machine derivation,
# looked up at call time) and sealed (the MAC key, bound at import). Before any
# machine or SealedCode is built.
_cipher._scrypt = _demo_kdf
_sealed._scrypt = _demo_kdf

from enigmar import FPE, SealedCode, DEFAULT_ALPHABET as ALPH  # noqa: E402

N = len(ALPH)                                    # 32, no I/L/O/U
# id · discount · expiry · serial — a 15-symbol code either way.
FIELDS = {"id": 3, "discount": 1, "expiry": 3, "serial": 3}
W_ID, W_DISC, W_EXP, W_SER = 3, 1, 3, 3
W_TAG = 5
W_SEC = W_ID + W_DISC + W_EXP                     # 7  — classic payload
W_CODE = W_TAG + sum(FIELDS.values())            # 15 — both schemes


# -- classic: clear nonce + encrypted tag ---------------------------------------

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


def _group(s):
    return "-".join(s[i:i + 5] for i in range(0, len(s), 5))


def _mint_classic(key, cid, disc, exp, ser, brand=""):
    key, brand = str(key), str(brand).upper()
    nonce = _enc_int(int(ser), W_SER)                              # clear per-code nonce
    payload = _enc_int(int(cid), W_ID) + _enc_int(int(disc), W_DISC) + _enc_int(int(exp), W_EXP)
    body = payload + _tag(key, brand + "|" + nonce + payload)      # brand bound into the tag
    sealed = FPE(key, ALPH, nonce=nonce).encrypt(body)            # real Enigma runs here
    return _group(nonce + sealed)


def _check_classic(key, code, brand=""):
    key, brand = str(key), str(brand).upper()
    raw = "".join(c for c in str(code).upper() if c in ALPH)
    if len(raw) != W_CODE:
        return None
    nonce = raw[:W_SER]
    body = FPE(key, ALPH, nonce=nonce).decrypt(raw[W_SER:])
    payload, t = body[:W_SEC], body[W_SEC:]
    if t != _tag(key, brand + "|" + nonce + payload):
        return None
    return {"id": _dec_int(payload[:3]), "discount": _dec_int(payload[3:4]),
            "expiry": _dec_int(payload[4:7]), "serial": _dec_int(nonce), "brand": brand}


# -- siv: enigmar.SealedCode (RFC 5297) -----------------------------------------

def _codes(key):
    return SealedCode(str(key), FIELDS, tag_width=W_TAG)          # -> 15-symbol code


def _mint_siv(key, cid, disc, exp, ser, brand=""):
    return _codes(key).mint(id=int(cid), discount=int(disc), expiry=int(exp),
                            serial=int(ser), brand=str(brand))


def _check_siv(key, code, brand=""):
    return _codes(key).check(str(code), brand=str(brand))


# -- dispatch -------------------------------------------------------------------

_MINT = {"classic": _mint_classic, "siv": _mint_siv}
_CHECK = {"classic": _check_classic, "siv": _check_siv}


def mint(key, cid, disc, exp, ser, brand="", scheme="siv"):
    return _MINT[scheme](key, cid, disc, exp, ser, brand)


def check(key, code, brand="", scheme="siv"):
    return _CHECK[scheme](key, code, brand)
