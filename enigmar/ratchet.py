"""
Symmetric key ratchet — a fresh key per message from one shared root.

    r = Ratchet(root)          # both sides, same root -> same sequence
    k0 = r.next()              # message 0 key
    k1 = r.next()              # message 1 key ...

Each `next()` derives a message key from the current chain key, then advances the
chain (HMAC-SHA256) and overwrites the old chain key. Because HMAC is one-way:
- past chain keys can't be recovered from the current one -> forward secrecy
  (delete state and old messages stay locked even if the key later leaks);
- a leaked message key reveals nothing about the chain or other messages.

This is the symmetric half of a double ratchet. Feed each message key to a Channel
(or use it as the keyfile) so every message rides its own key.
"""
import hashlib
import hmac


class Ratchet:
    def __init__(self, root: bytes):
        if not isinstance(root, (bytes, bytearray)) or len(root) < 16:
            raise ValueError("root must be at least 16 bytes of key material")
        self._ck = hmac.new(b"enigmar-ratchet", bytes(root), hashlib.sha256).digest()

    def _kdf(self, tag: bytes) -> bytes:
        return hmac.new(self._ck, tag, hashlib.sha256).digest()

    def next(self) -> bytes:
        """The next 32-byte message key. Advances the chain; the previous chain key
        is overwritten and unrecoverable."""
        message_key = self._kdf(b"msg")
        self._ck = self._kdf(b"chain")
        return message_key
