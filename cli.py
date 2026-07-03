"""
EnigmaR command-line interface. Pure stdlib, one file.

    echo -n "secret" | python cli.py encrypt -p hunter2 > msg.er
    python cli.py decrypt -p hunter2 < msg.er
    python cli.py rng -p hunter2 -n 32              # reproducible random bytes (hex)

Passphrase: -p/--pass, or the ENIGMAR_PASS env var, or an interactive prompt.
Add --keyfile FILE for a second secret, --chaos for every keyed dynamic.
encrypt/decrypt run byte mode (any binary) and are authenticated (encrypt-then-MAC):
the output blob is base64( nonce | tag | ciphertext ); decrypt verifies before output.
"""
import argparse
import base64
import getpass
import os
import sys

from cipher import Channel, StreamCipher
from machine import Alphabet


def _passphrase(args) -> str:
    if args.pass_:
        return args.pass_
    env = os.environ.get("ENIGMAR_PASS")
    if env:
        return env
    return getpass.getpass("passphrase: ")


def _keyfile(args) -> bytes:
    if not args.keyfile:
        return b""
    with open(args.keyfile, "rb") as f:
        return f.read()


def _opts(args) -> dict:
    o = {"alphabet": Alphabet.of_bytes(), "keyfile": _keyfile(args)}
    if getattr(args, "chaos", False):
        o["chaos"] = True
    return o


def cmd_encrypt(args) -> int:
    data = sys.stdin.buffer.read()
    ch = Channel(_passphrase(args), **_opts(args))
    nonce, ct, tag = ch.send(data)
    blob = bytes.fromhex(nonce) + bytes.fromhex(tag) + ct
    sys.stdout.write(base64.b64encode(blob).decode() + "\n")
    return 0


def cmd_decrypt(args) -> int:
    blob = base64.b64decode(sys.stdin.buffer.read())
    nonce, tag, ct = blob[:16].hex(), blob[16:48].hex(), blob[48:]
    ch = Channel(_passphrase(args), **_opts(args))
    try:
        sys.stdout.buffer.write(ch.receive(nonce, ct, tag))
    except ValueError as e:
        sys.stderr.write(f"error: {e}\n")
        return 1
    return 0


def cmd_rng(args) -> int:
    sc = StreamCipher.from_passphrase(_passphrase(args), nonce=args.nonce,
                                      alphabet=Alphabet.of_bytes(), keyfile=_keyfile(args))
    out = sc.keystream(args.n)
    sys.stdout.write(out.hex() + "\n") if not args.raw else sys.stdout.buffer.write(out)
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="enigmar", description="EnigmaR cipher / reproducible RNG")
    sub = p.add_subparsers(dest="cmd", required=True)

    def common(sp):
        sp.add_argument("-p", "--pass", dest="pass_", help="passphrase (else ENIGMAR_PASS or prompt)")
        sp.add_argument("--keyfile", help="path to a second-secret keyfile")

    e = sub.add_parser("encrypt", help="encrypt stdin -> base64 blob")
    common(e); e.add_argument("--chaos", action="store_true"); e.set_defaults(fn=cmd_encrypt)
    d = sub.add_parser("decrypt", help="decrypt a base64 blob from stdin")
    common(d); d.add_argument("--chaos", action="store_true"); d.set_defaults(fn=cmd_decrypt)
    r = sub.add_parser("rng", help="reproducible random bytes from the passphrase")
    common(r)
    r.add_argument("-n", type=int, default=32, help="number of bytes")
    r.add_argument("--nonce", default="", help="nonce for a distinct reproducible stream")
    r.add_argument("--raw", action="store_true", help="raw bytes instead of hex")
    r.set_defaults(fn=cmd_rng)
    return p


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    return args.fn(args)


if __name__ == "__main__":
    raise SystemExit(main())
