# Security policy

mailhdr reads email that may be hostile and DNS answers that anyone can publish. Two kinds of problem matter:

- **A message or DNS record that makes the analysis misjudge**: a forged signature that verifies, a record that makes SPF or DMARC give the wrong answer, a look-alike domain that goes unflagged.
- **Input that makes it crash, hang, flood DNS, or inject text into a report** (terminal escapes, HTML).

Please report either through GitHub's **private vulnerability reporting** (Security tab, "Report a vulnerability") rather than a public issue. You will get an answer within a few days.

What the code does about it: sizes and counts are capped (message, headers, signatures, SPF lookups, key sizes); DER from DNS is read strictly; RSA signatures are checked by rebuilding the whole padded block and comparing it byte for byte; reports strip control characters and the HTML report escapes everything and forbids scripts with a Content-Security-Policy. `tools/evaluate.py` runs thousands of damaged messages through the whole analysis and none may raise.

Supported: the latest release.
