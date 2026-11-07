# Changelog

## 1.0.0

First release. Parses a `.eml` and rebuilds the delivery path from the Received headers; re-checks DKIM (RSA and Ed25519 written without a crypto library), SPF (RFC 7208) and DMARC (with the bundled Public Suffix List); flags spoofing signs (display-name tricks, look-alike and mixed-script domains, Reply-To and Return-Path mismatches, forged Authentication-Results, odd clocks). Text, JSON and HTML reports. DNS from the network or from a saved JSON zone file.
