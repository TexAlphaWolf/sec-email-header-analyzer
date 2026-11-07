# Limitations

- **A saved message is not the message that was delivered.** Mail clients that re-save or forward can change bytes, which breaks DKIM for reasons that have nothing to do with forgery. Use the original source ("show original" / "view source").
- **The connecting IP is a guess unless you give it.** SPF needs the address of the server that handed the message to *your* mail server. mailhdr takes the topmost Received header's address and says so; use `--ip` when you know better. Forwarded mail and mailing lists fail SPF legitimately.
- **DNS is checked now, not then.** Keys and policies change; a message that passed last year may not verify today (a rotated DKIM key, for instance). Save the zone data you need and use `--zone` to re-run later.
- **Received headers below your own servers can be invented.** The path is only as honest as its most recent trusted hop.
- **Authentication-Results is read, not trusted.** It is shown next to mailhdr's own result; a mismatch is a finding.
- **Look-alike detection is heuristic.** It knows a short list of brands (`--brands FILE` replaces it), one-letter typos, common look-alike letters, and mixed alphabets. It will miss a clever domain, and flag some harmless ones.
- **Not implemented:** ARC, BIMI, DKIM `z=` (copied headers) and the local part of `i=` are ignored, DKIM `l=` is verified but only warned about, SPF `exp=` text is read but only for the top-level record, DMARC reports (rua/ruf) are never sent or fetched, and DNSSEC is not checked.
- **Unterminated last line.** A body that ends without a line break and with trailing spaces: the RFC's wording is ambiguous, and `dkimpy` and mailhdr canonicalise it differently. mailhdr gives it the same bytes as the properly terminated line (which is what was on the wire). Mail that crossed SMTP always ends in CRLF, so this only touches hand-edited copies.
- **Self-including SPF.** `pyspf` rejects a record that includes its own domain even when an earlier term already matched; mailhdr follows RFC 7208 4.6 and stops at the first match. The difference is listed in the tests.
- **SPF void lookups of MX hosts count** toward the limit of 2, and every MX host is resolved before matching, so the result does not depend on host order.
- **The Public Suffix List is a snapshot** (see `mailhdr --version` output in JSON reports). Update it by replacing `src/mailhdr/data/public_suffix_list.dat` (Mozilla, MPL-2.0).
