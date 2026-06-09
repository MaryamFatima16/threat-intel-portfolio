# Storm-1865 — ClickFix Hospitality Phishing Campaign

Investigation into Storm-1865, a financially motivated threat actor running ClickFix
social engineering campaigns against hospitality booking platforms in 2025.

## What's in here
- `storm1865_stix.json` — STIX 2.1 bundle I structured from the investigation. Covers the threat actor, campaign, 2 TTPs, Lumma Stealer payload, one IOC pattern, and relationships.
- `CTI-Technical_Report.md` — Technical threat intelligence report 
- `CTI-Non_Technical_Report.md` — Non-Technical threat intelligence report 
## How the campaign works

Storm-1865 sends phishing emails impersonating Booking.com. The links go to fake login
pages using Punycode lookalike domains — the kind that look legitimate at a glance in
a browser URL bar.

Once on the page, victims see a fake CAPTCHA or browser-fix popup that tells them to
open their Run dialog and paste in a command. That command is PowerShell. Because the
victim runs it themselves, most email gateway and sandbox controls miss it entirely.

The PowerShell downloads and executes Lumma Stealer, which harvests browser credentials,
session cookies, and PII — then exfiltrates everything to attacker infrastructure.

## STIX 2.1 objects

| Type | Name |
|------|------|
| `threat-actor` | Storm-1865 |
| `campaign` | ClickFix Hospitality Phishing 2025 |
| `attack-pattern` | T1566.003 — Phishing via spoofed booking platform |
| `attack-pattern` | T1059.001 — User-executed PowerShell via ClickFix |
| `malware` | Lumma Stealer |
| `indicator` | Punycode lookalike domains |
| `relationship` | campaign attributed-to threat-actor |
| `relationship` | campaign uses malware |

## MITRE ATT&CK
- T1566.003 — Phishing via spoofed service
- T1059.001 — Command and Scripting Interpreter: PowerShell

## Why this matters for hospitality sector
The campaign specifically targets booking platforms and hotel staff — making it
directly relevant to any organisation running guest-facing reservation systems.
Session cookie theft via Lumma Stealer means standard MFA doesn't protect you
if the cookie is already stolen.

## Author
Maryam Fatima — [github.com/maryamfatima16](https://github.com/maryamfatima16)
