"""
Format-preserving encryption (FPE) over a character domain.

The one thing this engine does that a generic stream cipher doesn't: the
ciphertext keeps the input's own shape. A 16-digit card becomes another
16-digit number; a sentence of known words becomes another such sentence.
That falls straight out of the additive keystream — over an alphabet of N
symbols, `StreamCipher` maps each symbol to another symbol of the same
alphabet, same length. FPE is then just three rules on top:

  1. encrypt only the characters that belong to the format's charset;
  2. pass every other character (separators, fixed punctuation) through
     unchanged and in place — dashes, spaces and dots keep their positions;
  3. optionally hold a prefix/suffix fixed and recompute a check digit, so a
     structurally-checked field (Luhn card, PESEL, IBAN) stays valid by
     construction rather than by luck.

This is a *showcase*, not a security primitive — same cost-not-impossibility
caveat as the rest of the library, plus the usual FPE caveat that a small
domain is a small keyspace. Reversible, deterministic, keyed.
"""
from __future__ import annotations

from .machine import Alphabet
from .cipher import StreamCipher


class FPE:
    """A keyed, reversible, shape-preserving mapping over a character domain.

    Only characters in `charset` are encrypted; anything else is a separator
    and passes through untouched. `keep_prefix` / `keep_suffix` freeze that
    many leading / trailing *payload* symbols (separators don't count), e.g.
    the birth-date head of a PESEL or the `+CC` of a phone number. `checksum`,
    if given, marks the last payload symbol as derived (not encrypted): after
    the rest is transformed it is recomputed from the preceding payload
    symbols, so the output validates by construction.

        fpe = FPE("hunter2", "0123456789")
        tok = fpe.encrypt("4111 1111 1111 1111")   # spaces preserved
        fpe.decrypt(tok)                            # -> original

    `checksum` is a callable taking the list of preceding payload symbols (as
    single-character strings) and returning the one check character.
    """

    def __init__(self, passphrase, charset, *, nonce: str = "fpe",
                 keep_prefix: int = 0, keep_suffix: int = 0, checksum=None, **opts):
        self.charset = charset if isinstance(charset, str) else charset.symbols
        self._members = set(self.charset)
        self._sc = StreamCipher.from_passphrase(
            passphrase, nonce=nonce, alphabet=Alphabet(self.charset), **opts)
        self.keep_prefix = keep_prefix
        self.keep_suffix = keep_suffix
        self.checksum = checksum

    # -- core --------------------------------------------------------------

    def _transform(self, text: str, *, decrypt: bool) -> str:
        chars = list(text)
        # String positions of the payload (in-charset) symbols, in order.
        payload = [i for i, c in enumerate(chars) if c in self._members]
        p = len(payload)
        has_check = self.checksum is not None
        lo = self.keep_prefix
        hi = p - self.keep_suffix - (1 if has_check else 0)   # exclusive
        if hi < lo:
            raise ValueError(
                f"nothing left to encrypt: {p} payload symbols, "
                f"keep_prefix={self.keep_prefix} keep_suffix={self.keep_suffix} "
                f"checksum={'on' if has_check else 'off'}")

        window = [payload[k] for k in range(lo, hi)]          # positions to (de)cipher
        sub = "".join(chars[i] for i in window)
        out = self._sc.decrypt(sub) if decrypt else self._sc.encrypt(sub)
        for i, ch in zip(window, out):
            chars[i] = ch

        if has_check:
            check_at = payload[p - 1 - self.keep_suffix]
            preceding = [chars[payload[k]] for k in range(p - 1 - self.keep_suffix)]
            chars[check_at] = self.checksum(preceding)
        return "".join(chars)

    def encrypt(self, text: str) -> str:
        return self._transform(text, decrypt=False)

    def decrypt(self, text: str) -> str:
        return self._transform(text, decrypt=True)
