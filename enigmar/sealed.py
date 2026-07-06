"""
SIV-style sealed codes — deterministic authenticated encryption over `FPE`.

Not a new cipher. This is RFC 5297 / Rogaway–Shrimpton 2006 deterministic AE
("SIV", misuse-resistant authenticated encryption) applied to a short,
format-preserving code. The engine underneath is the same Enigma (through
`FPE`); only the *sealing construction* changes from the clear-nonce+tag scheme
in `docs/seal.py`.

The move: the authentication tag doubles as the IV. `tag = HMAC(key, brand‖plaintext)`,
then the plaintext is FPE-encrypted under that tag as the per-code nonce. Three
consequences fall straight out of that, and they are the whole reason this exists:

  1. nothing rides in the clear — every field (serial included) is encrypted,
     where the clear-nonce scheme leaks its nonce field in plaintext;
  2. there is no nonce to reuse, so the two-time-pad footgun (same nonce → same
     keystream) that `cipher.StreamCipher` warns about is gone *by construction*;
  3. minting is deterministic: identical `(key, brand, fields)` give one code.
     That is the SIV trade-off — a repeat leaks only equality, never plaintext.

Everything is format-preserving: `mint` returns a grouped base-`N` string, `check`
returns the fields or `None`. Field widths and the tag width are configured up
front; the tag width is the forgery-resistance knob — `T` symbols over an
`N`-symbol alphabet give ~`N**-T` success per blind forgery attempt.

    codes = SealedCode("passphrase",
                       {"id": 3, "discount": 1, "expiry": 3, "serial": 3})
    code = codes.mint(id=42, discount=15, expiry=9000, serial=25846, brand="SUMMER")
    codes.check(code, brand="SUMMER")     # -> {"id": 42, "discount": 15, ...}
    codes.check(code, brand="HARVEST")    # -> None  (brand bound into the tag)

Same cost-not-impossibility caveat as the rest of the library: the tag length and
the passphrase are the security parameters, not the rotor wiring.
"""
from __future__ import annotations

import hmac
import hashlib

from .cipher import _scrypt, _SCRYPT_N
from .fpe import FPE

# base-32, dropping I/L/O/U so codes stay unambiguous when read aloud or typed.
DEFAULT_ALPHABET = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"


class SealedCode:
    """A keyed factory for SIV-sealed, format-preserving codes.

    `fields` is an ordered mapping name -> width (symbols); their order and widths
    fix the layout on both mint and check. `tag_width` symbols of HMAC are the
    forgery-resistance knob. `**fpe_opts` are forwarded to `FPE` / `derive_machine`
    (alphabet dynamics, `kdf_n`, etc.); the same options must be used to mint and
    to check, exactly as with the engine elsewhere.
    """

    def __init__(self, passphrase, fields, *, alphabet: str = DEFAULT_ALPHABET,
                 tag_width: int = 5, kdf_n: int = _SCRYPT_N,
                 mac_salt: bytes = b"enigmar-sealed-mac", group: int = 5, **fpe_opts):
        self._pass = str(passphrase)
        self._fields = list(fields.items())
        if not self._fields:
            raise ValueError("a sealed code needs at least one field")
        self._alph = alphabet if isinstance(alphabet, str) else alphabet.symbols
        self._members = set(self._alph)
        self.N = len(self._alph)
        self.tag_width = tag_width
        self._group = group
        self._pay_w = sum(w for _, w in self._fields)
        self._fpe_opts = dict(fpe_opts, kdf_n=kdf_n)
        # MAC key is independent of the machine: derived from the passphrase under
        # its own salt (mirrors Channel), so authentication never shares state with
        # the keystream. Derived once per factory, not per code.
        self._mackey = _scrypt(self._pass, mac_salt, n=kdf_n, dklen=32)

    # -- symbol <-> int over this alphabet ---------------------------------

    def _enc_int(self, v: int, w: int) -> str:
        if v < 0 or v >= self.N ** w:
            raise ValueError(f"value {v} does not fit in {w} base-{self.N} symbols")
        out = ""
        for _ in range(w):
            out = self._alph[v % self.N] + out
            v //= self.N
        return out

    def _dec_int(self, s: str) -> int:
        v = 0
        for c in s:
            v = v * self.N + self._alph.index(c)
        return v

    def _grouped(self, s: str) -> str:
        g = self._group
        return "-".join(s[i:i + g] for i in range(0, len(s), g)) if g else s

    # -- SIV core ----------------------------------------------------------

    def _tag(self, brand: str, payload: str) -> str:
        """The synthetic IV: HMAC over brand ‖ plaintext, folded into `tag_width`
        symbols. Brand is bound here, so a code only verifies under its own brand."""
        digest = hmac.new(self._mackey, (brand + "|" + payload).encode(),
                          hashlib.sha256).digest()
        v = int.from_bytes(digest, "big") % (self.N ** self.tag_width)
        return self._enc_int(v, self.tag_width)

    def _fpe(self, tag: str) -> FPE:
        return FPE(self._pass, self._alph, nonce=tag, **self._fpe_opts)

    def mint(self, *, brand: str = "", **values) -> str:
        """Seal the given field values into one code. Deterministic in
        `(key, brand, values)`."""
        brand = str(brand).upper()
        missing = [name for name, _ in self._fields if name not in values]
        if missing:
            raise ValueError(f"missing fields: {', '.join(missing)}")
        payload = "".join(self._enc_int(int(values[name]), w) for name, w in self._fields)
        tag = self._tag(brand, payload)              # tag = SIV over the plaintext
        ciphertext = self._fpe(tag).encrypt(payload)  # tag doubles as the nonce/IV
        return self._grouped(tag + ciphertext)

    def check(self, code, *, brand: str = ""):
        """Verify and open a code. Returns the field dict, or `None` if the tag
        does not verify (tampered, wrong key, or wrong/omitted brand)."""
        brand = str(brand).upper()
        raw = "".join(c for c in str(code).upper() if c in self._members)
        if len(raw) != self.tag_width + self._pay_w:
            return None
        tag, ciphertext = raw[:self.tag_width], raw[self.tag_width:]
        payload = self._fpe(tag).decrypt(ciphertext)
        if not hmac.compare_digest(tag, self._tag(brand, payload)):
            return None
        out, i = {}, 0
        for name, w in self._fields:
            out[name] = self._dec_int(payload[i:i + w])
            i += w
        out["brand"] = brand
        return out
