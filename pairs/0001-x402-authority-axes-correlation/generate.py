#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Regenerate inputs/ and vectors/ for pair 0001 (development tool; verify.py needs none of this).

Needs: cryptography (Ed25519), eth-account (EIP-712 / EIP-3009 signing), jcs, and a checkout of
magentixai/axes for its correlation recipe:

    python generate.py --axes PATH_TO_AXES_CHECKOUT

Every key comes from a public label, SHA-256("axes-cec-pair-1:<label>"), so the output is byte-for-byte
reproducible. These are test keys; they hold nothing.
"""
import argparse
import base64
import copy
import hashlib
import json
import os
import sys

import jcs
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization
from eth_account import Account
from eth_account.messages import encode_typed_data

HERE = os.path.dirname(os.path.abspath(__file__))
MANDATE_TAG = b"x402-mandate/1\n"
BINDING_TAG = b"x402-mandate-binding/1\n"


def seed(label):
    return hashlib.sha256(("axes-cec-pair-1:" + label).encode()).digest()


def b64u(b):
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def ed_key(label):
    k = Ed25519PrivateKey.from_private_bytes(seed(label))
    pub = k.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return k, b64u(pub)


def write(rel, obj):
    path = os.path.join(HERE, rel)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8", newline="\n") as f:
        json.dump(obj, f, indent=1, ensure_ascii=False)
        f.write("\n")


def mandate_digest(mandate):
    return "sha256:" + hashlib.sha256(MANDATE_TAG + jcs.canonicalize(mandate)).hexdigest()


def binding(digest, payment_id):
    return "0x" + hashlib.sha256(BINDING_TAG + (digest + "\n" + payment_id).encode("utf-8")).hexdigest()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--axes", required=True, help="path to a magentixai/axes checkout")
    a = ap.parse_args()
    sys.path.insert(0, os.path.join(a.axes, "tools", "x402"))
    import x402_correlation as xc

    issuer, issuer_pub = ed_key("issuer")
    _, accountant_pub = ed_key("accountant")
    payer = Account.from_key(seed("payer"))
    payee = Account.from_key(seed("payee")).address
    asset = "0x036CbD53842c5426634e7929541eC2318f3dCF7e"  # USDC on Base Sepolia
    network, chain_id, payment_id = "eip155:84532", 84532, "pay-001"

    # x402 side, built per PR #3220 section 3 and 4 at 72c3704 for this payment.
    mandate = {
        "v": "x402-mandate/1",
        "issuer": issuer_pub,
        "subject": payer.address.lower(),
        "asset": asset.lower(),
        "cap": "1000000",
        "perPayment": "250000",
        "recipients": [payee.lower()],
        "accountant": accountant_pub,
        "purpose": "CEC pair 0001: x402 authority mandate with an AXES correlation record",
        "notAfter": "2027-01-01T00:00:00Z",
        "nonce": "axes-cec-pair-1-mandate-001",
    }
    sig = b64u(issuer.sign(MANDATE_TAG + jcs.canonicalize(mandate)))
    envelope = {"mandate": mandate, "alg": "Ed25519", "sig": sig}
    digest = mandate_digest(mandate)
    nonce = binding(digest, payment_id)

    accepted = {"scheme": "exact", "network": network, "amount": "10000", "asset": asset, "payTo": payee,
                "maxTimeoutSeconds": 120, "extra": {"name": "USDC", "version": "2"}}
    resource = {"url": "https://seller.example/premium-data", "description": "Premium data", "mimeType": "application/json"}
    server_salt = hashlib.sha256(seed("server-salt")).hexdigest()
    client_salt = hashlib.sha256(seed("client-salt")).hexdigest()
    evidence_offer = {"offered": ["axes:x402_correlation@1"], "required": False, "correlationSalt": server_salt}
    payment_required = {"x402Version": 2, "resource": resource, "accepts": [accepted],
                        "extensions": {"evidence": {"info": evidence_offer}}}
    authorization = {"from": payer.address, "to": payee, "value": "10000",
                     "validAfter": "1792800000", "validBefore": "1792800600", "nonce": nonce}
    typed = {
        "types": {
            "EIP712Domain": [{"name": "name", "type": "string"}, {"name": "version", "type": "string"},
                             {"name": "chainId", "type": "uint256"}, {"name": "verifyingContract", "type": "address"}],
            "TransferWithAuthorization": [{"name": "from", "type": "address"}, {"name": "to", "type": "address"},
                                          {"name": "value", "type": "uint256"}, {"name": "validAfter", "type": "uint256"},
                                          {"name": "validBefore", "type": "uint256"}, {"name": "nonce", "type": "bytes32"}],
        },
        "primaryType": "TransferWithAuthorization",
        "domain": {"name": "USDC", "version": "2", "chainId": chain_id, "verifyingContract": asset},
        "message": {"from": payer.address, "to": payee, "value": 10000, "validAfter": 1792800000,
                    "validBefore": 1792800600, "nonce": bytes.fromhex(nonce[2:])},
    }
    eip3009_sig = "0x" + payer.sign_message(encode_typed_data(full_message=typed)).signature.hex().removeprefix("0x")
    payment_payload = {"x402Version": 2, "resource": resource, "accepted": accepted,
                       "payload": {"signature": eip3009_sig, "authorization": authorization},
                       "extensions": {"evidence": {"info": dict(evidence_offer, chosen="axes:x402_correlation@1", clientSalt=client_salt)},
                                      "payment-identifier": {"info": {"id": payment_id}}}}

    # AXES side, produced by the AXES correlation recipe itself.
    core = xc.build_core(payment_required, payment_payload)
    record = {
        "correlation_recipe_ref": "axes:x402_correlation@1",
        "correlation_hash": xc.correlation_hash(core),
        "correlation_hash_algorithm": "SHA-256",
        "mandate_hash": digest.split(":", 1)[1],
        "mandate_hash_algorithm": "SHA-256",
        "payment_identifier_id": payment_id,
        "nonce_derivation_type": xc.nonce_derivation_type(nonce, digest, payment_id),
        "correlation_core": core,
    }

    write("inputs/mandate_envelope.json", envelope)
    write("inputs/payment_required.json", payment_required)
    write("inputs/payment_payload.json", payment_payload)
    write("inputs/axes_correlation_record.json", record)

    # The pinned x402 vectors and the AXES record built against them earlier.
    vec = json.load(open(os.path.join(HERE, "vendor", "x402-pr3220-72c3704", "authority-vectors.json"), encoding="utf-8"))
    vec_envelope = {"mandate": vec["modelA"]["mandate"], "alg": vec["modelA"]["alg"], "sig": vec["modelA"]["sig"]}
    vec_payload = json.load(open(os.path.join(HERE, "vendor", "axes-a38b3e2", "payment_payload_mandate_bound.json"), encoding="utf-8"))
    vec_record = json.load(open(os.path.join(HERE, "vendor", "axes-a38b3e2", "correlation_mandate_bound.json"), encoding="utf-8"))

    def case(name, env, rec, payload, failure_mode=None, note=""):
        v = {"id": name, "mandate_envelope": env, "axes_record": rec, "payment_authorization": payload["payload"]["authorization"]}
        if failure_mode:
            v["failure_mode"] = failure_mode
        if note:
            v["note"] = note
        return v

    def rehash(rec):
        rec["correlation_hash"] = xc.correlation_hash(rec["correlation_core"])
        return rec

    vectors = []
    vectors.append(("pos_0001-coherent-mandate.json", "PASS", None, "accept", case(
        "0001-coherent-mandate", envelope, record, payment_payload,
        note="A mandate built per #3220 sections 3 and 4 for this payment. The criterion holds and the section 6 authority check accepts.")))
    vectors.append(("pos_0002-x402-vector-mandate.json", "PASS", None, "refuse", case(
        "0002-x402-vector-mandate", vec_envelope, vec_record, vec_payload,
        note="The #3220 modelA vector mandate at 72c3704 and the AXES record built against it (axes a38b3e2). The binding recomputes and the record does not re-assert the mandate, so the criterion holds. The section 6 authority check refuses: the vector mandate's subject, asset and recipients are abstract identifiers, not this payment's. A matching binding is not an authorisation, as #3220 section 6 itself says.")))

    r = copy.deepcopy(record); r["cap"] = mandate["cap"]; r["recipients"] = mandate["recipients"]
    vectors.append(("neg_0003-record-reasserts-cap-and-scope.json", "REJECT", "reasserts_authority", None, case(
        "0003-record-reasserts-cap-and-scope", envelope, r, payment_payload, "reasserts_authority",
        "The record copies the mandate's cap and recipient scope as its own fields.")))
    r = copy.deepcopy(record); r["mandate"] = mandate
    vectors.append(("neg_0004-record-embeds-mandate.json", "REJECT", "reasserts_authority", None, case(
        "0004-record-embeds-mandate", envelope, r, payment_payload, "reasserts_authority",
        "The record carries the mandate object itself instead of referencing it.")))
    r = copy.deepcopy(record); r["mandate_hash"] = vec["modelA"]["digest"].split(":", 1)[1]
    vectors.append(("neg_0005-reference-to-another-mandate.json", "REJECT", "mandate_reference_mismatch", None, case(
        "0005-reference-to-another-mandate", envelope, r, payment_payload, "mandate_reference_mismatch",
        "The record's mandate_hash names a different mandate (the #3220 vector mandate) from the one presented.")))
    bad = copy.deepcopy(envelope); bad["sig"] = ("B" if bad["sig"][0] != "B" else "C") + bad["sig"][1:]
    vectors.append(("neg_0006-mandate-signature-invalid.json", "REJECT", "mandate_signature_invalid", None, case(
        "0006-mandate-signature-invalid", bad, record, payment_payload, "mandate_signature_invalid",
        "The referenced mandate's issuer signature does not verify.")))
    r = copy.deepcopy(record); r["payment_identifier_id"] = "pay-002"; r["correlation_core"]["payment_identifier_id"] = "pay-002"
    vectors.append(("neg_0007-binding-mismatch-payment-id.json", "REJECT", "binding_mismatch", None, case(
        "0007-binding-mismatch-payment-id", envelope, rehash(r), payment_payload, "binding_mismatch",
        "The record names paymentId pay-002; the nonce binds pay-001.")))
    stripped_nonce = "0x" + hashlib.sha256(BINDING_TAG + (digest.split(":", 1)[1] + "\n" + payment_id).encode()).hexdigest()
    p = copy.deepcopy(payment_payload); p["payload"]["authorization"]["nonce"] = stripped_nonce
    r = copy.deepcopy(record); r["correlation_core"]["authorization_nonce_id"] = stripped_nonce
    vectors.append(("neg_0008-binding-prefix-stripped.json", "REJECT", "binding_mismatch", None, case(
        "0008-binding-prefix-stripped", envelope, rehash(r), p, "binding_mismatch",
        "The nonce was derived with the sha256: prefix stripped from mandateDigest, which #3220 section 7 forbids.")))
    other = "0x" + hashlib.sha256(seed("unrelated-nonce")).hexdigest()
    p = copy.deepcopy(payment_payload); p["payload"]["authorization"]["nonce"] = other
    vectors.append(("neg_0009-record-not-this-payment.json", "REJECT", "payload_nonce_mismatch", None, case(
        "0009-record-not-this-payment", envelope, record, p, "payload_nonce_mismatch",
        "The record's nonce is the binding, but the signed authorization presented carries a different nonce.")))
    r = copy.deepcopy(record); r["correlation_core"]["total_amount_value"] = "1"
    vectors.append(("neg_0010-core-altered-hash-not-recomputed.json", "REJECT", "correlation_hash_mismatch", None, case(
        "0010-core-altered-hash-not-recomputed", envelope, r, payment_payload, "correlation_hash_mismatch",
        "The correlation core was edited after hashing; correlation_hash no longer recomputes.")))

    manifest = {
        "pair": "0001-x402-authority-axes-correlation",
        "criterion": "The evidence record references the authority and lets a verifier recompute the binding; it never re-asserts the authority as its own.",
        "reject_reasons": {
            "reasserts_authority": "the evidence record carries mandate members or the mandate itself, instead of referencing it by digest",
            "mandate_reference_mismatch": "the record's mandate_hash is not the digest of the referenced mandate",
            "mandate_signature_invalid": "the referenced mandate's issuer signature does not verify",
            "binding_mismatch": "the binding recomputed from the referenced mandate and the record's paymentId is not the record's nonce",
            "payload_nonce_mismatch": "the record's nonce is not the nonce in the signed payment authorization",
            "correlation_hash_mismatch": "correlation_hash does not recompute from the record's correlation core",
        },
        "authority_note": "authority_expect is the #3220 section 6 single-payment verdict (checks 1, 3 to 7), reported beside the criterion and never part of it: authority belongs to the x402 side.",
        "verifier_clock": "2026-10-27T00:00:00Z",
        "vectors": [],
    }
    for fname, expect, reason, authority, v in vectors:
        write("vectors/" + fname, v)
        manifest["vectors"].append({"file": fname, "expect": expect, "reason": reason, "authority_expect": authority})
    write("MANIFEST.json", manifest)
    print("wrote inputs/ and %d vectors" % len(vectors))


if __name__ == "__main__":
    main()
