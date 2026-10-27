# Pair 0001: x402 authority mandate with an AXES correlation record

**Status: proposed. Not merged until a committer other than its author reruns it from these bytes (GOVERNANCE rule 1).**

## Criterion

As proposed in issue #2 and supported there by kenneives and giskard09:

> The evidence record references the authority and lets a verifier recompute the binding; it never re-asserts the authority as its own.

## Where each side comes from (GOVERNANCE rule 2)

| Side | Specification and revision | Produced by | Bytes in this folder |
|---|---|---|---|
| x402 authority | x402-foundation/x402 PR #3220, `authority` extension, **unmerged**, pinned at head `72c3704dfb89851fb7b1f0dca4d327b804faee5c` (unchanged since 8 Sep 2026): `specs/extensions/authority.md` (git blob `5c503d1`) and `specs/extensions/authority-vectors.json` (git blob `5e653af`). If the PR changes or merges, this pair is re-pinned. | Specification and vectors: whawk46 (PR author). The coherent mandate in `inputs/`: magentixai, built per sections 3 and 4 of the pinned text. | `vendor/x402-pr3220-72c3704/authority-vectors.json`, unchanged, SHA-256 `3400298752208280fd84e5941c6fd2b20df6d3603903c418902b0b6030974e00`. Apache-2.0, as the x402 repository. |
| AXES correlation record | magentixai/axes at `a38b3e2`: recipe `axes:x402_correlation@1` (`tools/x402/x402_correlation.py`). | magentixai. | `inputs/axes_correlation_record.json` (produced here by the AXES tool), and `vendor/axes-a38b3e2/` (the record and payment built in October against the #3220 vector mandate, unchanged; SHA-256 `81116c5f…5119` and `330ba1b2…0b7`). Apache-2.0. |

## Runs

| Run | By | Independent of the author? | Result |
|---|---|---|---|
| `python3 verify.py` on Windows, Python 3.12, 27 Oct 2026 | magentixai | No (author run) | 10/10 vectors match `MANIFEST.json` |
| Rerun from the published bytes | *open: a committer other than magentixai* | Yes | *pending* |

The author run also cross-checked:
- the standard-library Ed25519 in `verify.py` accepts the signature #3220 publishes for its model A vector mandate;
- the standard-library RFC 8785 in `verify.py` matches the `jcs` package on every record and the mandate;
- the EIP-3009 signature in `inputs/payment_payload.json` recovers the payer (eth-account);
- the AXES command-line tool reproduces the correlation hash;
- `generate.py` regenerates `inputs/`, `vectors/` and `MANIFEST.json` byte for byte.

## What a verifier checks

`verify.py` uses the Python standard library only and has no network access. For each vector, in order:

1. The referenced mandate's issuer signature verifies (Ed25519 over `"x402-mandate/1\n" || JCS(mandate)`, #3220 section 4).
2. The record's `mandate_hash` is that mandate's digest (#3220 section 5).
3. The record carries no mandate member and no mandate object. This is the "never re-asserts" half of the criterion.
4. The binding recomputed from the referenced mandate and the record's `paymentId` equals the record's nonce (#3220 section 7). The `sha256:` prefix is kept in the preimage.
5. The record's nonce is the nonce in the signed payment authorization presented.
6. `correlation_hash` recomputes as SHA-256 over the RFC 8785 bytes of the record's correlation core.

Separately, it reports the #3220 section 6 single-payment authority verdict (checks 1 and 3 to 7, verifier clock fixed at 2026-10-27T00:00:00Z). That verdict belongs to the x402 side and never decides the criterion.

## Vectors

| Vector | Expect | Reason | Authority (informative) |
|---|---|---|---|
| `pos_0001-coherent-mandate` | PASS | | accept |
| `pos_0002-x402-vector-mandate` | PASS | | refuse |
| `neg_0003-record-reasserts-cap-and-scope` | REJECT | `reasserts_authority` | accept |
| `neg_0004-record-embeds-mandate` | REJECT | `reasserts_authority` | accept |
| `neg_0005-reference-to-another-mandate` | REJECT | `mandate_reference_mismatch` | accept |
| `neg_0006-mandate-signature-invalid` | REJECT | `mandate_signature_invalid` | refuse |
| `neg_0007-binding-mismatch-payment-id` | REJECT | `binding_mismatch` | accept |
| `neg_0008-binding-prefix-stripped` | REJECT | `binding_mismatch` | accept |
| `neg_0009-record-not-this-payment` | REJECT | `payload_nonce_mismatch` | accept |
| `neg_0010-core-altered-hash-not-recomputed` | REJECT | `correlation_hash_mismatch` | accept |

**Why `pos_0002` passes the criterion while authority refuses.** It uses #3220's own model A vector mandate and the AXES record built against it.
- The binding recomputes and the record references the mandate only by digest, so the criterion holds.
- The vector mandate's subject, asset and recipients are abstract identifiers (an Ed25519 key string, `FCUSD`, `merchant.example`), not this payment's, so section 6 refuses.
- That separation is the point: section 6 itself says a matching binding slot "MUST NOT be presented as proof of an authorized action".

**`pos_0001`** is the coherent case: a mandate built per sections 3 and 4 for this payment, for which the criterion and the authority check both pass.

## Limits and findings

- **No settled artifact.** The AXES record is built from the signed payment authorization, before settlement. #3220 section 6 requires a settled payment's fields to come from the decoded settled artifact. That decode-and-compare step is out of scope for this pair.
- **Address spelling (#3220 ambiguity).** Section 6 requires `payer` to equal the mandate `subject` and the asset to match exactly, but the text does not fix how an EVM address is spelled (lowercase or EIP-55 checksum). This pair writes both the mandate and the AXES record in lowercase hex and compares them as written. A verifier that compares a checksummed decode against a lowercase subject would refuse the same payment. Worth a sentence in #3220.
- **#3220 section 19 is deferred.** How the mandate travels in x402 messages is not yet specified there, so this pair presents the mandate envelope beside the record, as a verifier would hold it.

## Regenerating

`generate.py` (development tool; needs `cryptography`, `eth-account` and `jcs`, and a magentixai/axes checkout) rebuilds `inputs/`, `vectors/` and `MANIFEST.json`:

```
python generate.py --axes PATH_TO_AXES_CHECKOUT
```

All keys come from public labels, `SHA-256("axes-cec-pair-1:<label>")`. They are test keys and hold nothing.
