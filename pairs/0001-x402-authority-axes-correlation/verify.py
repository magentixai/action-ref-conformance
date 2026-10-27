#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Verifier for pair 0001: an x402 authority mandate (PR #3220 at 72c3704) with an AXES correlation record
(axes:x402_correlation@1). Python standard library only, no network.

    python3 verify.py

Criterion: the evidence record references the authority and lets a verifier recompute the binding; it never
re-asserts the authority as its own. For each vector, in order:

  1. the referenced mandate's issuer signature verifies (Ed25519 over "x402-mandate/1\\n" || JCS(mandate));
  2. the record's mandate_hash is that mandate's digest (#3220 section 5);
  3. the record carries no mandate member and no mandate object (it references, never re-asserts);
  4. SHA-256("x402-mandate-binding/1\\n" || "sha256:" + mandate_hash || "\\n" || paymentId) equals the record's
     nonce (#3220 section 7);
  5. the record's nonce is the nonce in the signed payment authorization presented;
  6. correlation_hash = SHA-256(JCS(correlation_core)) (axes:x402_correlation@1).

Separately, it reports the #3220 section 6 single-payment authority verdict (checks 1 and 3 to 7) from the
record's payment fields and a fixed verifier clock. Authority belongs to the x402 side; it never decides the
criterion verdict.

Exit 0 when every vector matches MANIFEST.json, both verdicts are seen and every declared reason is exercised;
1 on a conformance failure; 2 if the suite itself is broken.
"""
from __future__ import annotations

import base64
import hashlib
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

HERE = Path(__file__).resolve().parent
MANDATE_TAG = b"x402-mandate/1\n"
BINDING_TAG = b"x402-mandate-binding/1\n"
MANDATE_MEMBERS = {"issuer", "subject", "cap", "perPayment", "recipients", "accountant", "purpose", "notAfter", "parent", "mandate"}


class Reject(Exception):
    pass


# ---------- RFC 8785, for the scope this pair uses: ASCII member names, no floats (checked, not assumed)

def _scope(v):
    if isinstance(v, float):
        raise Reject("malformed_input")
    if isinstance(v, dict):
        for k, x in v.items():
            if not k.isascii():
                raise Reject("malformed_input")
            _scope(x)
    elif isinstance(v, list):
        for x in v:
            _scope(x)


def jcs(v) -> bytes:
    _scope(v)
    return json.dumps(v, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


# ---------- Ed25519 verification (RFC 8032 section 5.1.7), affine arithmetic

P = 2 ** 255 - 19
L = 2 ** 252 + 27742317777372353535851937790883648493
D = -121665 * pow(121666, -1, P) % P


def _add(a, b):
    (x1, y1), (x2, y2) = a, b
    t = D * x1 * x2 * y1 * y2 % P
    return ((x1 * y2 + x2 * y1) * pow(1 + t, -1, P) % P, (y1 * y2 + x1 * x2) * pow(1 - t, -1, P) % P)


def _mul(k, pt):
    acc = (0, 1)
    while k:
        if k & 1:
            acc = _add(acc, pt)
        pt = _add(pt, pt)
        k >>= 1
    return acc


def _decode(b: bytes):
    if len(b) != 32:
        return None
    y = int.from_bytes(b, "little") & ((1 << 255) - 1)
    sign = b[31] >> 7
    if y >= P:
        return None
    xx = (y * y - 1) * pow(D * y * y + 1, -1, P) % P
    x = pow(xx, (P + 3) // 8, P)
    if (x * x - xx) % P:
        x = x * pow(2, (P - 1) // 4, P) % P
    if (x * x - xx) % P:
        return None
    if x == 0 and sign:
        return None
    if x & 1 != sign:
        x = P - x
    return (x, y)


def _encode(pt) -> bytes:
    x, y = pt
    return (y | ((x & 1) << 255)).to_bytes(32, "little")


BASE = _decode((4 * pow(5, -1, P) % P).to_bytes(32, "little"))


def ed25519_verify(pub: bytes, msg: bytes, sig: bytes) -> bool:
    if len(sig) != 64:
        return False
    a, r = _decode(pub), _decode(sig[:32])
    s = int.from_bytes(sig[32:], "little")
    if a is None or r is None or s >= L:
        return False
    h = int.from_bytes(hashlib.sha512(sig[:32] + pub + msg).digest(), "little") % L
    return _encode(_mul(s, BASE)) == _encode(_add(r, _mul(h, a)))


def b64u_decode(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


# ---------- the criterion

def walk_keys(v):
    if isinstance(v, dict):
        for k, x in v.items():
            yield k
            yield from walk_keys(x)
    elif isinstance(v, list):
        for x in v:
            yield from walk_keys(x)


def check_criterion(v: dict) -> None:
    env, rec, auth = v["mandate_envelope"], v["axes_record"], v["payment_authorization"]
    mandate = env.get("mandate")
    if not isinstance(mandate, dict) or env.get("alg") != "Ed25519":
        raise Reject("mandate_signature_invalid")
    if not ed25519_verify(b64u_decode(mandate["issuer"]), MANDATE_TAG + jcs(mandate), b64u_decode(env["sig"])):
        raise Reject("mandate_signature_invalid")
    digest_hex = hashlib.sha256(MANDATE_TAG + jcs(mandate)).hexdigest()
    if rec.get("mandate_hash_algorithm") != "SHA-256" or rec.get("mandate_hash") != digest_hex:
        raise Reject("mandate_reference_mismatch")
    if MANDATE_MEMBERS & set(walk_keys(rec)):
        raise Reject("reasserts_authority")
    core = rec.get("correlation_core") or {}
    payment_id = rec.get("payment_identifier_id")
    if "payment_identifier_id" in core and core["payment_identifier_id"] != payment_id:
        raise Reject("binding_mismatch")
    binding = "0x" + hashlib.sha256(BINDING_TAG + ("sha256:" + digest_hex + "\n" + str(payment_id)).encode("utf-8")).hexdigest()
    if str(core.get("authorization_nonce_id", "")).lower() != binding:
        raise Reject("binding_mismatch")
    if str(auth.get("nonce", "")).lower() != binding:
        raise Reject("payload_nonce_mismatch")
    if hashlib.sha256(jcs(core)).hexdigest() != rec.get("correlation_hash"):
        raise Reject("correlation_hash_mismatch")


# ---------- #3220 section 6, reported beside the criterion

def authority_verdict(v: dict, clock: str) -> str:
    env, core = v["mandate_envelope"], v["axes_record"].get("correlation_core") or {}
    m = env.get("mandate") or {}
    try:
        if not ed25519_verify(b64u_decode(m["issuer"]), MANDATE_TAG + jcs(m), b64u_decode(env["sig"])):
            return "refuse"
        legs = core.get("payment_legs") or []
        amount = int(core["total_amount_value"])
        in_scope = m["recipients"] == ["*"] or all(leg["pay_to_id"] in m["recipients"] for leg in legs)
        expired = datetime.fromisoformat(clock.replace("Z", "+00:00")) >= datetime.fromisoformat(m["notAfter"].replace("Z", "+00:00"))
        ok = (core.get("payer_id") == m["subject"] and core.get("asset_id") == m["asset"] and legs and in_scope
              and amount <= int(m["cap"]) and ("perPayment" not in m or amount <= int(m["perPayment"])) and not expired)
        return "accept" if ok else "refuse"
    except (KeyError, ValueError, TypeError, Reject):
        return "refuse"


def main() -> int:
    manifest = json.loads((HERE / "MANIFEST.json").read_text(encoding="utf-8"))
    reasons = set(manifest["reject_reasons"])
    seen_verdicts, seen_reasons, failures = set(), set(), 0
    for entry in manifest["vectors"]:
        v = json.loads((HERE / "vectors" / entry["file"]).read_text(encoding="utf-8"))
        try:
            check_criterion(v)
            verdict, reason = "PASS", None
        except Reject as r:
            verdict, reason = "REJECT", str(r)
        except Exception:
            verdict, reason = "REJECT", "malformed_input"
        authority = authority_verdict(v, manifest["verifier_clock"])
        ok = verdict == entry["expect"] and reason == entry["reason"] and (
            entry["authority_expect"] is None or authority == entry["authority_expect"])
        failures += not ok
        seen_verdicts.add(verdict)
        if reason:
            seen_reasons.add(reason)
        print("%-4s %-48s %-6s %-26s authority=%s" % ("ok" if ok else "FAIL", entry["file"], verdict, reason or "", authority))
    if seen_verdicts != {"PASS", "REJECT"} or not reasons <= seen_reasons:
        print("SUITE BROKEN: verdicts seen %s; reasons not exercised %s" % (sorted(seen_verdicts), sorted(reasons - seen_reasons)))
        return 2
    print("%d/%d vectors match MANIFEST.json; both verdicts seen; all %d reasons exercised"
          % (len(manifest["vectors"]) - failures, len(manifest["vectors"]), len(reasons)))
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
