# Evaluation

Everything here is produced by a script in the repository and re-run by CI. Where a number was measured once, on one machine, it says so.

| Script | What it measures | Needs |
|---|---|---|
| `tools/evaluate.py` | DKIM, Ed25519, RSA, SPF, Public Suffix List and robustness, against independent implementations | the dev extras, no network |
| `tools/live_check.py` | SPF, DMARC and DKIM keys against the real Internet's DNS | working DNS |

The independent implementations are `dkimpy` 1.1.8 (DKIM sign and verify), `pyspf` 2.0.14 (SPF), `cryptography` (RSA and Ed25519 signatures), and the Public Suffix List's own conformance file.

## 1. DKIM against dkimpy

150 random messages (folded and repeated headers, spaces and tabs at line ends, empty bodies, 0 to 3 blank lines at the end) were signed by dkimpy in all four canonicalisation modes with a 2,048-bit key. Each was then verified undamaged and damaged in five ways. For every one of the 900 verdicts mailhdr and dkimpy had to agree.

| Case | Messages | mailhdr says pass | mailhdr says fail |
|---|---|---|---|
| undamaged | 150 | 150 | 0 |
| one body letter changed | 132 | 0 | 132 |
| a line appended to the body | 150 | 0 | 150 |
| one letter of a signed header changed | 127 | 0 | 127 |
| one letter of the signature changed | 150 | 0 | 150 |
| spaces added at the end of the last line | 132 | 70 | 62 |

The last row is the useful one: relaxed body canonicalisation must ignore the change and simple must not, and both implementations split the 132 the same way. Result: **900 of 900 verdicts agree** (seeds 1, 2 and 3 all agree; the table is seed 1). Damages that cannot be applied to a message (a body with no letters) are not counted.

Also tested, in `tests/`: a header added above a signed one is caught when the signer listed it twice in `h=`; expired and future signatures; `l=` bodies with appended text (flagged); every way a signature or key record can be wrong has its own named result (`fail`, `policy`, `permerror`, `temperror`); revoked keys; two key records at one name; `rsa-sha1` refused by policy (RFC 8301); keys under 1,024 bits refused and 1,024-bit keys accepted with a warning; and a 2006-style Bleichenbacher forgery with exponent 3, which fails because the whole padded block is rebuilt and compared byte for byte.

## 2. Signature maths against `cryptography`

| Primitive | Cases | Correct |
|---|---|---|
| Ed25519, random messages 0 to 300 bytes: good signature, one flipped bit, changed message | 200 | 200 |
| RSA-1024 / 2048 / 3072 / 4096, SHA-256: good signature, one flipped bit, changed digest | 40 each | 160 of 160 |
| Ed25519, RFC 8032 section 7.1 test vectors 1 and 2 | 2 | 2 |

The Ed25519 here is plain Python (about 2.7 ms per verification, fine for a few signatures per message). I could not fetch the RFC 8463 appendix example message verbatim, so there is no known-answer test for it; the Ed25519 DKIM path is checked against dkimpy-made signatures instead.

## 3. SPF against pyspf

300 random zones (`include`, `redirect`, `a`, `mx` with CIDR lengths, `exists`, `ip4`, `ip6`, mixed qualifiers, a record that fails with a temporary DNS error now and then), each evaluated for 6 client addresses (IPv4 and IPv6) by both implementations.

| | |
|---|---|
| zones used / skipped (see below) | 252 / 48 |
| evaluations compared | 1,512 |
| same result word | **1,512** |
| results seen | pass 527, neutral 267, fail 187, softfail 196, permerror 226, temperror 109 |

Plus RFC 7208's own macro table (section 7.4: `%{ir}.%{v}._spf.%{d2}` and the rest) and tests for the 10-lookup and 2-void-lookup limits, include loops, `ptr` validation and the `exp=` explanation.

**Differences found while building this, and what was done:**
- *Self-include.* pyspf rejects a record that includes its own domain even if an earlier term already matched. RFC 7208 4.6 stops at the first match, so mailhdr does not. 48 of the 300 random zones contain this and are excluded rather than hidden; `tests/test_spf.py` pins mailhdr's behaviour.
- *MX order.* The first version stopped looking at MX hosts after the first match, so a record near the void-lookup limit gave a different answer depending on host order (pyspf resolves them all). mailhdr now resolves all of them first. Found by the random comparison, seed 91.

## 4. Public Suffix List

The list is bundled (snapshot 2026-11-06). The matcher passes **78 of 78** cases of the project's own conformance file, including wildcard and exception rules and internationalised names.

## 5. Robustness and speed

5,000 messages made by damaging the sample messages (random bytes, inserted fragments such as `=?utf-8?q?`, `%{`, `(`, control characters, deleted stretches) went through the whole analysis: 4,997 were analysed, 3 were refused as "not an email", **0 raised**. Parser tests also cover mbox lines, LF, CR and CRLF endings, folding, size limits, and 300 random byte strings. The HTML report was tested with `<script>` and `<img onerror>` in the headers (escaped, and a Content-Security-Policy forbids scripts); the text report strips terminal escape sequences.

Median times on the machine that built this (a cloud VM, Python 3.13), one message:

| Step | Time |
|---|---|
| parse | 0.014 ms |
| DKIM, RSA-2048 (key from a zone file) | 0.24 ms |
| Ed25519 verification | 2.8 ms |
| whole analysis (parse, path, DKIM, SPF, DMARC, findings) | 0.8 ms, with DNS answers from a file; real DNS adds the lookups |

## 6. What the tests do not show

- The comparisons use zones and messages made by the same author as the code. Agreement with two independent implementations is evidence the rules were read the same way, not proof that the rules match every real mail server.
- Real mail flow (forwarders, lists, odd Received formats) is only represented by the hand-written formats in `tests/test_received.py`. The Received parser is tolerant, and what it cannot read is left empty, never guessed.
- The look-alike finder's quality is not measured: it is a heuristic with a small brand list.
