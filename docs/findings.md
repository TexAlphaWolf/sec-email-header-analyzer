# Findings

Each finding has a severity and a stable code (the `code` field in JSON output). The verdict adds points: high 5, medium 2, low 1, info 0. **5 or more is HIGH, 2 or more is MEDIUM, otherwise LOW.**

A finding is a sign, not a proof. Mailing services legitimately use their own bounce domains, and a message can be forged and still show none of these.

| Code | Severity | What it means |
|---|---|---|
| `no-from` | high | No From header |
| `multiple-from` | high | Several From headers: a mail app may show one and checks apply to another |
| `multiple-from-addresses` | medium | The From header holds more than one address |
| `no-date`, `no-message-id` | low | Header missing; real servers add them |
| `multiple-date`, `multiple-message-id` | medium | Header appears more than once |
| `no-received` | low | No Received headers at all |
| `date-bad`, `date-future`, `date-far` | low | Date unreadable, in the future, or more than two days from delivery |
| `display-name-address` | high | The display name shows an address that is not the real one |
| `display-name-brand` | medium | The display name mentions a guarded brand but the address is elsewhere |
| `from-homoglyph` | high | The From domain is built from look-alike characters of a guarded domain |
| `from-mixed-script` | high | One label mixes alphabets (Latin with Cyrillic, say) |
| `from-typosquat` | medium | One character away from a guarded domain |
| `from-brand-in-domain` | medium | Contains a guarded brand name but is not that domain |
| `from-idn` | low | Internationalised (xn--) domain |
| `reply-to-differs` | medium | Replies would go to another organisation's domain |
| `reply-to-subdomain` | info | Reply-To is at a different subdomain of the same organisation |
| `return-path-differs` | low | The bounce address is at another domain (normal for mailing services) |
| `no-return-path` | info | No Return-Path (a saved copy may lack it) |
| `path` | low | A problem in the delivery path: clocks going backwards, a slow hop (over 1 hour), a server that says it received from someone other than the previous hop |
| `private-origin` | info | Every address in the path is private or local |
| `offline` | info | Authentication was not re-checked |
| `dkim-fail`, `dkim-policy` | medium | A signature did not verify, or was refused by policy (rsa-sha1, key under 1024 bits) |
| `dkim-permerror`, `dkim-temperror` | low | A signature could not be checked (no key, malformed, DNS trouble) |
| `dkim-warning` | low | A passing signature with a caveat: weak 1024-bit key, `l=` body limit, test key |
| `no-dkim` | low | No signature |
| `spf-fail` | high | The connecting server is not allowed to send for the domain |
| `spf-softfail` | medium | Probably not allowed |
| `spf-none`, `spf-neutral`, `spf-permerror`, `spf-temperror` | low | No policy, no opinion, or the record could not be evaluated |
| `spf-unchecked` | info | Needs the connecting IP and a sender address |
| `dmarc-fail` | high if the domain asks for quarantine or reject, medium if `p=none` | No aligned DKIM or SPF pass |
| `dmarc-none` | low | The From domain publishes no DMARC policy |
| `dmarc-permerror`, `dmarc-temperror` | low | Record unusable, or DNS trouble |
| `dmarc-note` | info | `p=none`, `pct` below 100, and similar remarks |
| `claimed-pass` | high | An Authentication-Results header says pass where mailhdr gets something else |
| `claimed-fail` | low | A header says fail where mailhdr gets pass |
| `many-auth-results` | info | Several Authentication-Results headers: only your own server's can be trusted |

DNS trouble is never scored above low: a timeout says nothing about the message.
