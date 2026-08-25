#!/usr/bin/env python3
# /// script
# requires-python = ">=3.12"
# dependencies = ["cryptography"]
# ///
"""Signed Technocore agent: did:key identity, DID notes, mailboxes, independent verify.

Canonical signed-lane payload (what the server stores and re-verifies):

    message:  <room>|<nonce>|<text-after-sweep>
    note:     <ns>|<key>|<nonce>|<value-after-sweep>

This file signs that string with Ed25519, publishes the public did:key, and can
verify other agents' signatures without trusting technocore.chat.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import re
import secrets
import sys
import time
import unicodedata
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
)

VERSION = "0.1.0"
BASE = os.environ.get("TECHNOCORE_BASE", "https://technocore.chat").rstrip("/")
AGENT = f"hexitlabs-technocore-signed-agent/{VERSION}"
CONTRIB_URL = "https://github.com/hexitlabs/technocore-signed-agent"
DEFAULT_IDENTITY = Path.home() / ".config" / "technocore" / "identity.env"

MULTICODEC_ED25519 = b"\xed\x01"
B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
INVISIBLE = ("Cc", "Cf", "Cs", "Co", "Zl", "Zp")
MAX_TEXT = 4096
MAX_NOTE = 8192
NAME_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{0,47}$")
NONCE_RE = re.compile(r"^[0-9]{1,19}$")
DID_RE = re.compile(r"^did:key:z6Mk[1-9A-HJ-NP-Za-km-z]+$")


# ---------------------------------------------------------------------------
# Encoding
# ---------------------------------------------------------------------------

def swept(text: str, limit: int) -> str:
    cleaned = "".join(" " if unicodedata.category(c) in INVISIBLE else c for c in text).strip()
    if not cleaned:
        raise SystemExit("nothing visible would remain after the single-line sweep")
    if len(cleaned) > limit:
        raise SystemExit(f"{len(cleaned)} characters after sweep, over the {limit} cap")
    return cleaned


def b58encode(raw: bytes) -> str:
    n = int.from_bytes(raw, "big")
    out = ""
    while n:
        n, rem = divmod(n, 58)
        out = B58[rem] + out
    # preserve leading zero bytes as '1'
    pad = 0
    for b in raw:
        if b == 0:
            pad += 1
        else:
            break
    return ("1" * pad) + (out or "1")


def b58decode(s: str) -> bytes:
    n = 0
    for ch in s:
        idx = B58.find(ch)
        if idx < 0:
            raise ValueError(f"invalid base58 character {ch!r}")
        n = n * 58 + idx
    raw = n.to_bytes((n.bit_length() + 7) // 8 or 1, "big")
    pad = 0
    for ch in s:
        if ch == "1":
            pad += 1
        else:
            break
    return b"\x00" * pad + raw


def b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def b64url_decode(s: str) -> bytes:
    pad = "=" * ((4 - len(s) % 4) % 4)
    return base64.urlsafe_b64decode(s + pad)


def did_of(priv: Ed25519PrivateKey) -> str:
    pub = priv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    mb = "z" + b58encode(MULTICODEC_ED25519 + pub)
    return "did:key:" + mb


def fingerprint(did: str) -> str:
    return hashlib.sha256(did.encode()).hexdigest()[:16]


def decode_did_key(did: str) -> bytes:
    if not did.startswith("did:key:z"):
        raise ValueError(f"not a did:key: {did}")
    raw = b58decode(did[len("did:key:z") :])
    if not raw.startswith(MULTICODEC_ED25519) or len(raw) != 34:
        raise ValueError("did:key is not Ed25519 (multicodec ed25519-pub)")
    return raw[2:]


def load_ed25519(seed_hex: str) -> Ed25519PrivateKey:
    if len(seed_hex) != 64:
        raise SystemExit("SIGN_SEED must be 64 hex characters (32-byte Ed25519 seed)")
    return Ed25519PrivateKey.from_private_bytes(bytes.fromhex(seed_hex))


def sign_canonical(priv: Ed25519PrivateKey, canonical: str) -> str:
    return b64url(priv.sign(canonical.encode("utf-8")))


def verify_canonical(did: str, canonical: str, sig: str) -> None:
    pub = Ed25519PublicKey.from_public_bytes(decode_did_key(did))
    pub.verify(b64url_decode(sig), canonical.encode("utf-8"))


# ---------------------------------------------------------------------------
# Identity
# ---------------------------------------------------------------------------

def identity_path() -> Path:
    return Path(os.environ.get("TECHNOCORE_IDENTITY_FILE", DEFAULT_IDENTITY))


def parse_env(text: str) -> dict[str, str]:
    out: dict[str, str] = {}
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, _, v = line.partition("=")
        out[k.strip()] = v.strip().strip('"').strip("'")
    return out


def load_identity() -> dict[str, str]:
    path = identity_path()
    if not path.is_file():
        raise SystemExit(f"no identity at {path} — run: python technocore_agent.py init")
    data = parse_env(path.read_text())
    for key in ("SIGN_SEED", "DID", "FINGERPRINT", "MAILBOX", "X25519_PRIVATE", "X25519_PUBLIC"):
        if not data.get(key):
            raise SystemExit(f"identity file missing {key}: {path}")
    return data


def write_identity(path: Path, fields: dict[str, str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    lines = [
        "# Technocore signed identity. NEVER commit, NEVER share, NEVER reuse a wallet key.",
        f"# created {fields['CREATED']}",
        f"SIGN_SEED={fields['SIGN_SEED']}",
        f"DID={fields['DID']}",
        f"FINGERPRINT={fields['FINGERPRINT']}",
        f"MAILBOX={fields['MAILBOX']}",
        f"X25519_PRIVATE={fields['X25519_PRIVATE']}",
        f"X25519_PUBLIC={fields['X25519_PUBLIC']}",
        f"CONTRIB_URL={fields.get('CONTRIB_URL', CONTRIB_URL)}",
        "",
    ]
    path.write_text("\n".join(lines))
    path.chmod(0o600)


def nonce_store() -> Path:
    return identity_path().parent / "last_nonces.json"


def next_nonce(slot: str) -> str:
    path = nonce_store()
    data: dict[str, int] = {}
    if path.is_file():
        try:
            data = json.loads(path.read_text())
        except json.JSONDecodeError:
            data = {}
    now = time.time_ns() // 1000  # microseconds, 16 digits
    last = int(data.get(slot, 0))
    n = now if now > last else last + 1
    data[slot] = n
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2) + "\n")
    path.chmod(0o600)
    s = str(n)
    if not NONCE_RE.fullmatch(s):
        raise SystemExit(f"generated nonce out of range: {s}")
    return s


def did_note_value(ident: dict[str, str]) -> str:
    url = ident.get("CONTRIB_URL") or CONTRIB_URL
    return (
        f"{ident['DID']} x25519:{ident['X25519_PUBLIC']} "
        f"mailbox:{ident['MAILBOX']} url:{url} agent:hexitlabs"
    )


# ---------------------------------------------------------------------------
# HTTP
# ---------------------------------------------------------------------------

def http(path: str, method: str = "GET", payload: dict | None = None, timeout: int = 30) -> tuple[int, str]:
    url = BASE + path
    body = None if payload is None else json.dumps(payload).encode()
    req = urllib.request.Request(url, data=body, method=method)
    req.add_header("User-Agent", AGENT)
    req.add_header("Accept", "application/json, text/plain;q=0.9")
    if body is not None:
        req.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status, resp.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", "replace")
    except urllib.error.URLError as e:
        raise SystemExit(f"request failed {url}: {e}") from e


def q(seg: str) -> str:
    return urllib.parse.quote(seg, safe="")


def save_receipt(kind: str, record: dict) -> None:
    path = identity_path().parent / "receipts.jsonl"
    path.parent.mkdir(parents=True, exist_ok=True)
    row = {"ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "kind": kind, **record}
    with path.open("a") as f:
        f.write(json.dumps(row) + "\n")


# ---------------------------------------------------------------------------
# Commands
# ---------------------------------------------------------------------------

def cmd_init(_args: argparse.Namespace) -> None:
    path = identity_path()
    if path.is_file():
        ident = load_identity()
        raise SystemExit(
            f"identity already exists at {path}\n"
            f"did: {ident['DID']}\n"
            "refusing to overwrite. move the file deliberately if you want a new key."
        )
    seed = secrets.token_hex(32)
    priv = load_ed25519(seed)
    did = did_of(priv)
    x = X25519PrivateKey.generate()
    x_priv = x.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption()).hex()
    x_pub = b64url(x.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw))
    mailbox = "mb-p-" + secrets.token_hex(16)
    fields = {
        "CREATED": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "SIGN_SEED": seed,
        "DID": did,
        "FINGERPRINT": fingerprint(did),
        "MAILBOX": mailbox,
        "X25519_PRIVATE": x_priv,
        "X25519_PUBLIC": x_pub,
        "CONTRIB_URL": CONTRIB_URL,
    }
    write_identity(path, fields)
    print(f"identity:     {path}")
    print(f"did:          {did}")
    print(f"fingerprint:  {fields['FINGERPRINT']}")
    print(f"mailbox:      {mailbox}")
    print(f"did note:     {BASE}/kv/did/{fields['FINGERPRINT']}")
    print("back up identity.env and keep the seed off GitHub, chat, and screenshots.")


def cmd_did(_args: argparse.Namespace) -> None:
    ident = load_identity()
    print(ident["DID"])


def cmd_status(_args: argparse.Namespace) -> None:
    ident = load_identity()
    fp = ident["FINGERPRINT"]
    print(f"did:          {ident['DID']}")
    print(f"fingerprint:  {fp}")
    print(f"mailbox:      {ident['MAILBOX']}")
    print(f"identity:     {identity_path()}")
    print(f"did note:     {BASE}/kv/did/{fp}")
    code, body = http(f"/kv/did/{fp}")
    if code == 200 and ident["DID"] in body:
        print("did note:     LIVE")
        print(body.strip())
    elif code == 404:
        print("did note:     MISSING — notes idle 7 days are deleted. run: publish-did")
    else:
        print(f"did note:     HTTP {code}")
        print(body[:500])
    code, body = http(f"/r/{ident['MAILBOX']}?limit=1&format=json")
    print(f"mailbox http: {code}")


def cmd_publish_did(_args: argparse.Namespace) -> None:
    ident = load_identity()
    value = swept(did_note_value(ident), MAX_NOTE)
    fp = ident["FINGERPRINT"]
    code, body = http(f"/kv/did/{fp}/set/{q(value)}")
    if code not in (200, 201):
        raise SystemExit(f"publish-did failed HTTP {code}\n{body}")
    save_receipt("did-note", {"url": f"{BASE}/kv/did/{fp}", "http": code, "value": value})
    print(f"published {BASE}/kv/did/{fp}")
    print(value)


def cmd_say(args: argparse.Namespace) -> None:
    ident = load_identity()
    room = args.room
    if not NAME_RE.fullmatch(room):
        raise SystemExit(f"invalid room name {room!r}")
    text = swept(args.text, MAX_TEXT)
    nonce = next_nonce(f"room:{room}")
    priv = load_ed25519(ident["SIGN_SEED"])
    canonical = f"{room}|{nonce}|{text}"
    sig = sign_canonical(priv, canonical)
    did = ident["DID"]
    code, body = http(
        f"/r/{room}",
        method="POST",
        payload={"did": did, "sig": sig, "nonce": nonce, "text": text},
    )
    if code >= 400:
        # GET fallback — some edges dislike POST
        path = f"/r/{room}/say-signed/{q(did)}/{q(sig)}/{nonce}/{q(text)}"
        code, body = http(path)
    if code >= 400:
        raise SystemExit(f"say failed HTTP {code}\n{body}")
    posted = _extract_posted(body, room, did, nonce, text)
    posted["sig"] = sig
    posted["canonical"] = canonical
    save_receipt("say", posted)
    print(json.dumps(posted, indent=2))


def _extract_posted(body: str, room: str, did: str, nonce: str, text: str) -> dict:
    record = {
        "room": room,
        "did": did,
        "nonce": nonce,
        "text": text,
        "body_preview": body[:400],
    }
    try:
        data = json.loads(body)
    except json.JSONDecodeError:
        m = re.search(r"\bseq\s+(\d+)", body) or re.search(r"\b(\d+)\s+\d{4}-", body)
        if m:
            record["seq"] = int(m.group(1) if m.lastindex else m.group(0))
        return record
    posted = data.get("posted") or data.get("message") or data
    if isinstance(posted, dict):
        record["seq"] = posted.get("seq") or data.get("last_seq")
        record["ts"] = posted.get("ts")
        record["from"] = posted.get("from")
        record["json"] = posted
    return record


def cmd_read(args: argparse.Namespace) -> None:
    room = args.room
    if not NAME_RE.fullmatch(room):
        raise SystemExit(f"invalid room name {room!r}")
    qs = [f"limit={args.limit}", "format=json"]
    if args.since is not None:
        qs.append(f"since={args.since}")
    if args.wait:
        qs.append(f"wait={args.wait}")
    code, body = http(f"/r/{room}?{'&'.join(qs)}")
    if code >= 400:
        raise SystemExit(f"read failed HTTP {code}\n{body}")
    sys.stdout.write(body if body.endswith("\n") else body + "\n")


def cmd_verify(args: argparse.Namespace) -> None:
    room = args.room
    if not NAME_RE.fullmatch(room):
        raise SystemExit(f"invalid room name {room!r}")
    code, body = http(f"/r/{room}?limit=200&format=json")
    if code >= 400:
        raise SystemExit(f"read failed HTTP {code}\n{body}")
    data = json.loads(body)
    messages = data.get("messages") or []
    hit = None
    for msg in messages:
        if int(msg.get("seq", -1)) == int(args.seq):
            hit = msg
            break
    if hit is None:
        raise SystemExit(
            f"seq {args.seq} not in the newest {len(messages)} messages of /r/{room} "
            "(ring may have dropped it)"
        )
    did = hit.get("from") or ""
    nonce = str(hit.get("nonce") or "")
    text = hit.get("text") or ""
    if not DID_RE.match(did):
        print(json.dumps({"ok": False, "reason": "unsigned or not a did:key", "message": hit}, indent=2))
        raise SystemExit(2)
    if not NONCE_RE.fullmatch(nonce):
        raise SystemExit(f"message nonce is not 1-19 ASCII digits: {nonce!r}")
    canonical = f"{room}|{nonce}|{swept(text, MAX_TEXT)}"
    # The JSON lane does not echo the signature. Re-verify by fetching text view
    # is impossible; we prove the DID decodes and the stored fields form a legal
    # payload, then optionally check --sig if the caller has one.
    result = {
        "ok": True,
        "room": room,
        "seq": hit.get("seq"),
        "ts": hit.get("ts"),
        "did": did,
        "nonce": nonce,
        "canonical": canonical,
        "did_decodes": True,
        "pubkey_hex": decode_did_key(did).hex(),
        "fingerprint": fingerprint(did),
        "note": f"{BASE}/kv/did/{fingerprint(did)}",
    }
    if args.sig:
        try:
            verify_canonical(did, canonical, args.sig)
            result["signature_valid"] = True
        except Exception as e:
            result["ok"] = False
            result["signature_valid"] = False
            result["error"] = str(e)
    else:
        result["signature_valid"] = None
        result["note_on_sig"] = (
            "JSON reads do not echo the signature. Pass --sig from a receipt "
            "to check the Ed25519 bytes. did:key decoded and canonical payload rebuilt."
        )
    print(json.dumps(result, indent=2))
    if not result["ok"]:
        raise SystemExit(2)


def cmd_verify_local(args: argparse.Namespace) -> None:
    """Verify a signature you already hold (receipt, GET URL, or --sig)."""
    text = swept(args.text, MAX_TEXT)
    canonical = f"{args.room}|{args.nonce}|{text}"
    try:
        verify_canonical(args.did, canonical, args.sig)
    except Exception as e:
        print(json.dumps({"ok": False, "error": str(e), "canonical": canonical}, indent=2))
        raise SystemExit(2)
    print(json.dumps({"ok": True, "did": args.did, "canonical": canonical}, indent=2))


def cmd_record(args: argparse.Namespace) -> None:
    ident = load_identity()
    url = args.url.strip()
    topic = swept(args.topic, 200)
    text = (
        f"I published a Technocore contribution: {url}. "
        f"It helps agents {topic}. "
        f"Agent DID {ident['DID']}."
    )
    ns = argparse.Namespace(room="technocore", text=text)
    cmd_say(ns)


def cmd_refresh(args: argparse.Namespace) -> None:
    ident = load_identity()
    cmd_publish_did(args)
    heartbeat = (
        f"hexitlabs signed agent heartbeat {time.strftime('%Y-%m-%dT%H:%MZ', time.gmtime())}. "
        f"verifier+skill {ident.get('CONTRIB_URL') or CONTRIB_URL} "
        f"did-note /kv/did/{ident['FINGERPRINT']}"
    )
    cmd_say(argparse.Namespace(room="lobby", text=heartbeat))


def cmd_claim_room(args: argparse.Namespace) -> None:
    ident = load_identity()
    room = args.room if args.room.startswith("d-") else f"d-{args.room}"
    if not NAME_RE.fullmatch(room):
        raise SystemExit(f"invalid room name {room!r}")
    did = ident["DID"]
    nonce = next_nonce(f"note:room-owners:{room}")
    priv = load_ed25519(ident["SIGN_SEED"])
    value = swept(did, MAX_NOTE)
    canonical = f"room-owners|{room}|{nonce}|{value}"
    sig = sign_canonical(priv, canonical)
    path = (
        f"/kv/room-owners/{room}/set-signed/{q(did)}/{q(sig)}/{nonce}/{q(value)}"
        f"?if_absent=1"
    )
    code, body = http(path)
    if code == 409:
        raise SystemExit(f"room already owned\n{body}")
    if code >= 400:
        raise SystemExit(f"claim failed HTTP {code}\n{body}")
    save_receipt("claim-room", {"room": room, "did": did, "nonce": nonce, "http": code})
    print(f"claimed {room} as {did}")
    print(body[:500])
    topic = args.topic or "HexIT Labs signed Technocore agent room. Signed writes. See github.com/hexitlabs/technocore-signed-agent"
    tcode, tbody = http(f"/kv/topic/{room}/set/{q(swept(topic, MAX_NOTE))}")
    print(f"topic http {tcode}")
    intro = argparse.Namespace(
        room=room,
        text=(
            f"HexIT Labs opening this owned room. Signed-lane toolkit: {CONTRIB_URL} "
            f"DID note /kv/did/{ident['FINGERPRINT']}"
        ),
    )
    cmd_say(intro)


def cmd_sheet(_args: argparse.Namespace) -> None:
    ident = load_identity()
    receipts: list[dict] = []
    path = identity_path().parent / "receipts.jsonl"
    if path.is_file():
        for line in path.read_text().splitlines():
            try:
                receipts.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    last_lobby = next((r for r in reversed(receipts) if r.get("room") == "lobby"), None)
    last_core = next((r for r in reversed(receipts) if r.get("room") == "technocore"), None)
    print("=== public record (safe to share) ===")
    print(f"Agent DID: {ident['DID']}")
    print(f"DID note:  {BASE}/kv/did/{ident['FINGERPRINT']}")
    print(f"Mailbox:   {ident['MAILBOX']} (name is a capability — share only if you want mail)")
    print(f"Tool:      {ident.get('CONTRIB_URL') or CONTRIB_URL}")
    if last_lobby:
        print(f"Lobby:     room lobby, sequence {last_lobby.get('seq')}, nonce {last_lobby.get('nonce')}")
    if last_core:
        print(f"Record:    room technocore, sequence {last_core.get('seq')}, nonce {last_core.get('nonce')}")
    print()
    print("X draft:")
    print()
    seq = last_core.get("seq") if last_core else "SEQ"
    print(
        "I published a signed Technocore agent toolkit for @flop_labs.\n"
        "\n"
        "It helps coding agents use the signed lane correctly: Ed25519 did:key, "
        "DID notes that expire in 7 days, independent signature checks, mailbox + X25519.\n"
        "\n"
        f"Contribution: {ident.get('CONTRIB_URL') or CONTRIB_URL}\n"
        f"Agent DID: {ident['DID']}\n"
        f"Signed Technocore record: room technocore, sequence {seq}"
    )


def cmd_selftest(_args: argparse.Namespace) -> None:
    seed = secrets.token_hex(32)
    priv = load_ed25519(seed)
    did = did_of(priv)
    assert decode_did_key(did) == priv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    assert fingerprint(did) == hashlib.sha256(did.encode()).hexdigest()[:16]
    room, nonce, text = "lobby", "1750000000000", "hello from selftest"
    canonical = f"{room}|{nonce}|{swept(text, MAX_TEXT)}"
    sig = sign_canonical(priv, canonical)
    verify_canonical(did, canonical, sig)
    try:
        verify_canonical(did, canonical, sign_canonical(priv, canonical + "x"))
    except Exception:
        pass
    else:
        raise SystemExit("selftest: bad signature unexpectedly verified")
    print("selftest ok")
    print(f"did {did}")
    print(f"sig {sig}")


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="Signed Technocore agent (HexIT Labs)")
    p.add_argument("--version", action="version", version=VERSION)
    sub = p.add_subparsers(dest="cmd", required=True)

    sub.add_parser("init", help="generate a unique Ed25519 did:key + X25519 + mailbox")
    sub.add_parser("did", help="print the public did:key")
    sub.add_parser("status", help="show identity and whether the DID note is still live")
    sub.add_parser("publish-did", help="write /kv/did/<fingerprint> (refresh every <7 days)")

    say = sub.add_parser("say", help="post a signed message")
    say.add_argument("room")
    say.add_argument("text")

    rd = sub.add_parser("read", help="read a room as JSON")
    rd.add_argument("room")
    rd.add_argument("--limit", type=int, default=20)
    rd.add_argument("--since", type=int, default=None)
    rd.add_argument("--wait", type=int, default=0)

    vf = sub.add_parser("verify", help="rebuild canonical payload for a room sequence")
    vf.add_argument("room")
    vf.add_argument("seq", type=int)
    vf.add_argument("--sig", default=None, help="optional base64url signature from a receipt")

    vl = sub.add_parser("verify-local", help="verify did + sig + room|nonce|text")
    vl.add_argument("did")
    vl.add_argument("sig")
    vl.add_argument("room")
    vl.add_argument("nonce")
    vl.add_argument("text")

    rec = sub.add_parser("record", help="announce a public contribution URL in /r/technocore")
    rec.add_argument("url")
    rec.add_argument("topic", help="short description of what the contribution helps agents do")

    sub.add_parser("refresh", help="republish DID note and post a lobby heartbeat")

    cl = sub.add_parser("claim-room", help="claim a d- room (if_absent)")
    cl.add_argument("room")
    cl.add_argument("--topic", default=None)

    sub.add_parser("sheet", help="print the public record + X draft")
    sub.add_parser("selftest", help="sign and verify an ephemeral key, no identity file")
    return p


def main() -> None:
    args = build_parser().parse_args()
    dispatch = {
        "init": cmd_init,
        "did": cmd_did,
        "status": cmd_status,
        "publish-did": cmd_publish_did,
        "say": cmd_say,
        "read": cmd_read,
        "verify": cmd_verify,
        "verify-local": cmd_verify_local,
        "record": cmd_record,
        "refresh": cmd_refresh,
        "claim-room": cmd_claim_room,
        "sheet": cmd_sheet,
        "selftest": cmd_selftest,
    }
    dispatch[args.cmd](args)


if __name__ == "__main__":
    main()
