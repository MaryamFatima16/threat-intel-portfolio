# Storm-1865 — Hospitality Phishing Campaign Analysis

A breakdown of a Booking.com impersonation campaign tracked by Microsoft as Storm-1865. The campaign uses ClickFix social engineering to steal hotel staff credentials.

This is an independent analysis I put together based on publicly available reporting and OSINT research. Companion non-technical version is in this repo as well.

Author: Maryam Fatima A

Public reference: Microsoft MSTIC blog on Storm-1865 (March 2025)

---

## Quick numbers

- 812 URLs analysed
- 770 unique hostnames
- 41 TLDs observed
- 7 URLs with confirmed live PII exfiltration
- 83 URLs carry the `?t=g` tracking parameter

---

## 1. Summary

Storm-1865 is an ongoing phishing operation targeting the hospitality sector by impersonating Booking.com. Lures are sent to hotel staff and the kit captures credentials, card data. I analysed 812 URLs across 770 domains. Seven of those URLs were caught with victim PII still sitting in their query strings, which means real guests were compromised.

The two things that stood out to me during the analysis: how heavily the operators rely on `booking.<filler>` subdomain tricks (almost 200 URLs use this pattern), and how clearly automated their kit deployment is, the URL paths and shared infrastructure point to a templated, scalable setup rather than hand-built pages.

---

## 2. MITRE ATT&CK mapping

ATT&CK v14 (Enterprise).

| Technique | Name | Tactic | What was observed |
|---|---|---|---|
| T1566.002 | Spearphishing Link | Initial Access | Booking.com-themed lures — reservation, payment, guest review |
| T1204.001 | Malicious Link | Execution | Victim clicks lure, lands on credential harvest page |
| T1059 | Command and Scripting | Execution | ClickFix variant — fake CAPTCHA, Win+R command execution |
| T1027 | Obfuscated Files / Info | Defense Evasion | Multi-layer JS obfuscation in the kit |
| T1036 | Masquerading | Defense Evasion | Subdomain abuse, Punycode, typosquats, character substitution |
| T1056 | Input Capture | Credential Access | Fake Booking.com overlay captures creds and card data |
| T1111 | MFA Interception | Credential Access | Tycoon 2FA AiTM intercepts session tokens in real time |
| T1041 | Exfil Over C2 Channel | Exfiltration | PII observed in query strings on confirmed live URLs |

---

## 3. Attack flow

**Initial access.** Spearphishing email impersonating Booking.com. Common lure themes are reservation confirmation, payment verification, check-in alerts, and guest reviews. The targets are hotel staff because those accounts have access to booking systems and loyalty programs.

**Execution.** Two variants. The standard one drops the victim straight onto a credential harvesting page. The ClickFix variant is more interesting, the page shows a fake browser verification prompt and walks the user through pressing Win+R and pasting a command, which fetches and runs a secondary payload.

**Defense evasion.** Kit JavaScript is obfuscated in multiple layers. Domain masquerading is the main evasion play.

**Credential access.** The fake page captures username, password, and card details.

**Exfiltration.** Stolen data goes to attacker infrastructure. Seven URLs in the dataset have PII (firstname, lastname, email, phone) still sitting in their query strings — strong evidence that real victims interacted with the pages.

---

## 4. Infrastructure analysis

### 4.1 TLD distribution

`.com` dominates at 508 URLs. The rest is a mix of cheap and abuse-friendly TLDs.

| TLD | Count |
|---|---|
| .com | 508 |
| .shop | 44 |
| .live | 31 |
| .help | 26 |
| .world | 25 |
| .life / .cfd / .icu / .click / .buzz / .sbs / .top | high-abuse cluster |

### 4.2 Subdomain patterns

| Pattern | Count |
|---|---|
| `booking.` | 198 |
| `id-.` | 36 |
| `property.` | 26 |
| `booking*.` | 22 |
| `booklng.` (typo) | 8 |
| `reserve.` | 6 |

### 4.3 Path structure

- `/p/<NUM>` — 435 URLs (53%)
- `/<NUM>` — 229 URLs (28%)
- `/q/<NUM>` — 38 URLs
- `/3dsecure/<NUM>`, `/pay/<NUM>`, `/secure-checkout/<NUM>`, `/order/<token>`

Numeric tokens in the paths act as per-victim identifiers — meaning the operator can correlate each session back to the lure email that generated it.

### 4.4 Shared infrastructure

A handful of domains carry a disproportionate share of URLs. These are the high-value pivot points.

| Domain | URL count |
|---|---|
| apprv-rooms-4246.com | 24 |
| emailsecureverification.com | 8 |
| approved-apartement-id612367.life | 4 |
| approve.78156-operation.com | 4 |
| cloud-approve7359146.shop | 3 |

Randomised subdomains on shared hosting (`*.japn-htel.com`, `*.sdf-mlup-<NUM>.com`) suggest automated kit deployment. New pages can be spun up fast, which explains why the campaign keeps regenerating after takedowns.

### 4.5 PII exfiltration

Seven URLs had PII baked into the query string:

```
/3dsecure/<NUM>?firstname=...&lastname=...&email=...&phone=...
/pay/<NUM>?firstname=...&lastname=...&email=...&phone=...
```

This is direct evidence of live victim compromise, not just theoretical capability.

### 4.6 Campaign tracking

83 URLs contain `?t=g`. Best interpretation: the operator is running campaign analytics, probably A/B testing lure variants or tracking conversion per template.

---

## 5. Brand impersonation techniques

| Technique | Examples |
|---|---|
| Subdomain impersonation | `booking.<domain>` / `booking.com-<token>.<tld>` |
| Typosquatting | `booklng`, `booklnq`, `bookng` |
| Punycode homograph | `xn--booking*.ws` |
| Character substitution | `h0tel`, `appr0ve`, `conflr` |

---

## 6. Detection guidance

### 6.1 YARA — domain and URL patterns

Hunting rule. Test against a clean corpus before pushing to production — the path and tracking-parameter conditions can hit benign traffic in some environments.

```yara
rule STORM1865_BookingImpersonation
{
    meta:
        description = "STORM-1865 Booking.com impersonation - domain and URL patterns"
        author      = "Maryam Fatima A"
        campaign    = "STORM-1865"

    strings:
        $sub   = /booking\.[a-z0-9\-]{4,}\.(shop|live|help|world|life|cfd|icu|click|buzz|sbs|top)/i
        $typo1 = "booklng." nocase
        $typo2 = "bookng."  nocase
        $pii   = /\/3dsecure\/[0-9]+\?firstname=/
        $track = "?t=g"
        $path  = /\/p\/[0-9]{4,}/

    condition:
        $sub or (1 of ($typo*)) or $pii or ($path and $track)
}
```
### 6.2 Email gateway

- Flag links with a `booking.` subdomain on a non-Booking.com TLD
- Flag sender domains matching `booking.com-*`
- Flag any link with `xn--` Punycode in the href
- Flag URLs containing `/3dsecure/` or `/secure-checkout/` paired with hospitality keywords

---

## Notes

This analysis is based on publicly available reporting and OSINT research. No employer-proprietary data, internal telemetry, or non-public IOCs are included. Shared under TLP:CLEAR.
