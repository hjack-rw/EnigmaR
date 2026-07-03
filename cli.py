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
import json
import os
import socket
import sys
import threading

from enigmar import Channel, StreamCipher, Alphabet
from enigmar import Identity, Handshake, authenticated_key, Session


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


# --- chat: a double-ratchet session persisted across invocations ------------
# Handshake (X3DH-style): both make an identity; Bob publishes a prekey bundle;
# Alice `start`s from it (emitting a hello bundle); Bob `accept`s it. Then both
# `send` / `recv` — each call loads the ratchet state, advances it, saves it back.
# Identity/prekey files hold private keys; bundles hold only public values.

def _save(path: str, obj: dict) -> None:
    with open(path, "w") as f:
        json.dump(obj, f)


def _load(path: str) -> dict:
    with open(path) as f:
        return json.load(f)


def cmd_id(args) -> int:
    idn = Identity()
    _save(args.out, {"priv": format(idn._priv, "x"), "pub": format(idn.public, "x")})
    sys.stderr.write(f"identity -> {args.out}  (public {format(idn.public, 'x')[:20]}…)\n")
    return 0


def cmd_prekey(args) -> int:
    idn = _load(args.id)
    eph = Handshake()
    _save(args.out, {"eph_priv": format(eph._priv, "x")})
    _save(args.bundle, {"id_pub": idn["pub"], "eph_pub": format(eph.public, "x")})
    sys.stderr.write(f"prekey -> {args.out}; share bundle -> {args.bundle}\n")
    return 0


def cmd_start(args) -> int:                       # initiator (Alice)
    me, peer = _load(args.id), _load(args.peer)
    id_a, ea = Identity(int(me["priv"], 16)), Handshake()
    id_b_pub, eb_pub = int(peer["id_pub"], 16), int(peer["eph_pub"], 16)
    root = authenticated_key(id_a, ea, id_b_pub, eb_pub, initiator=True)
    _save(args.state, Session.initiator(root, eb_pub).to_dict())
    _save(args.hello, {"id_pub": me["pub"], "eph_pub": format(ea.public, "x")})
    sys.stderr.write(f"session -> {args.state}; send hello -> {args.hello}\n")
    return 0


def cmd_accept(args) -> int:                      # responder (Bob)
    me, pre, peer = _load(args.id), _load(args.prekey), _load(args.peer)
    id_b, eb = Identity(int(me["priv"], 16)), Handshake(int(pre["eph_priv"], 16))
    id_a_pub, ea_pub = int(peer["id_pub"], 16), int(peer["eph_pub"], 16)
    root = authenticated_key(id_b, eb, id_a_pub, ea_pub, initiator=False)
    _save(args.state, Session.responder(root, eb).to_dict())
    sys.stderr.write(f"session -> {args.state}\n")
    return 0


def cmd_send(args) -> int:
    sess = Session.from_dict(_load(args.state))
    data = args.message.encode() if args.message is not None else sys.stdin.buffer.read()
    blob = sess.send(data)
    _save(args.state, sess.to_dict())
    sys.stdout.write(blob + "\n")
    return 0


def cmd_recv(args) -> int:
    sess = Session.from_dict(_load(args.state))
    blob = args.blob if args.blob else sys.stdin.read().strip()
    try:
        data = sess.receive(blob)
    except (ValueError, KeyError) as e:
        sys.stderr.write(f"error: {e}\n")
        return 1
    _save(args.state, sess.to_dict())
    sys.stdout.buffer.write(data)
    return 0


# --- chat over a real socket ------------------------------------------------
# `listen` binds and waits; `connect` dials in. They run the X3DH handshake over
# the wire, then a live double-ratchet conversation: type a line to send, incoming
# lines print. Pass --id FILE (from `chat identity`) to authenticate with a pinned
# identity; without it a fresh identity is made and the exchange is unauthenticated.

def _identity(args) -> "Identity | None":
    if not getattr(args, "id", None):
        return None
    d = _load(args.id)
    return Identity(int(d["priv"], 16))


def _handshake_over(f, initiator: bool, me) -> Session:
    me = me or Identity()
    if initiator:                                    # dial-in side is the initiator
        peer = json.loads(f.readline())              # responder's prekey bundle
        eph = Handshake()
        root = authenticated_key(me, eph, int(peer["id_pub"], 16), int(peer["eph_pub"], 16),
                                 initiator=True)
        sess = Session.initiator(root, int(peer["eph_pub"], 16))
        f.write(json.dumps({"id_pub": format(me.public, "x"),
                            "eph_pub": format(eph.public, "x")}) + "\n"); f.flush()
    else:                                            # listening side is the responder
        eph = Handshake()
        f.write(json.dumps({"id_pub": format(me.public, "x"),
                            "eph_pub": format(eph.public, "x")}) + "\n"); f.flush()
        peer = json.loads(f.readline())              # initiator's hello
        root = authenticated_key(me, eph, int(peer["id_pub"], 16), int(peer["eph_pub"], 16),
                                 initiator=False)
        sess = Session.responder(root, eph)
    return sess


def _chat_loop(f, sess: Session) -> None:
    lock = threading.Lock()

    def rx():
        for line in f:
            line = line.strip()
            if not line:
                continue
            with lock:
                try:
                    msg = sess.receive(line).decode(errors="replace")
                except Exception as e:               # noqa: BLE001 - report and keep going
                    msg = f"[undecryptable: {e}]"
            sys.stdout.write(f"\rpeer> {msg}\nyou> "); sys.stdout.flush()

    threading.Thread(target=rx, daemon=True).start()
    sys.stdout.write("secure channel up — type to send, Ctrl-D / /q to quit\nyou> ")
    sys.stdout.flush()
    for line in sys.stdin:
        line = line.rstrip("\n")
        if line in ("/q", "/quit"):
            break
        with lock:
            blob = sess.send(line.encode())
        f.write(blob + "\n"); f.flush()
        sys.stdout.write("you> "); sys.stdout.flush()


def cmd_listen(args) -> int:
    srv = socket.socket()
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((args.host, args.port)); srv.listen(1)
    sys.stderr.write(f"listening on {args.host}:{args.port} …\n")
    conn, addr = srv.accept()
    sys.stderr.write(f"peer connected from {addr[0]}:{addr[1]}\n")
    f = conn.makefile("rw", encoding="utf-8", newline="\n")
    _chat_loop(f, _handshake_over(f, initiator=False, me=_identity(args)))
    return 0


def cmd_connect(args) -> int:
    f = socket.create_connection((args.host, args.port)).makefile("rw", encoding="utf-8", newline="\n")
    _chat_loop(f, _handshake_over(f, initiator=True, me=_identity(args)))
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

    chat = sub.add_parser("chat", help="double-ratchet session (persisted state files)")
    cs = chat.add_subparsers(dest="chatcmd", required=True)
    c_id = cs.add_parser("identity", help="make an identity keypair")
    c_id.add_argument("--out", required=True); c_id.set_defaults(fn=cmd_id)
    c_pre = cs.add_parser("prekey", help="publish a prekey bundle (responder)")
    c_pre.add_argument("--id", required=True); c_pre.add_argument("--out", required=True)
    c_pre.add_argument("--bundle", required=True); c_pre.set_defaults(fn=cmd_prekey)
    c_st = cs.add_parser("start", help="start a session from a peer's prekey (initiator)")
    c_st.add_argument("--id", required=True); c_st.add_argument("--peer", required=True)
    c_st.add_argument("--state", required=True); c_st.add_argument("--hello", required=True)
    c_st.set_defaults(fn=cmd_start)
    c_ac = cs.add_parser("accept", help="accept a peer's hello (responder)")
    c_ac.add_argument("--id", required=True); c_ac.add_argument("--prekey", required=True)
    c_ac.add_argument("--peer", required=True); c_ac.add_argument("--state", required=True)
    c_ac.set_defaults(fn=cmd_accept)
    c_sd = cs.add_parser("send", help="encrypt a message (advances the ratchet)")
    c_sd.add_argument("--state", required=True); c_sd.add_argument("message", nargs="?")
    c_sd.set_defaults(fn=cmd_send)
    c_rc = cs.add_parser("recv", help="decrypt a blob (arg or stdin)")
    c_rc.add_argument("--state", required=True); c_rc.add_argument("blob", nargs="?")
    c_rc.set_defaults(fn=cmd_recv)
    c_ls = cs.add_parser("listen", help="live socket chat: wait for a peer (responder)")
    c_ls.add_argument("--host", default="127.0.0.1"); c_ls.add_argument("--port", type=int, default=9999)
    c_ls.add_argument("--id"); c_ls.set_defaults(fn=cmd_listen)
    c_cn = cs.add_parser("connect", help="live socket chat: dial a peer (initiator)")
    c_cn.add_argument("--host", default="127.0.0.1"); c_cn.add_argument("--port", type=int, default=9999)
    c_cn.add_argument("--id"); c_cn.set_defaults(fn=cmd_connect)
    return p


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    return args.fn(args)


if __name__ == "__main__":
    raise SystemExit(main())
