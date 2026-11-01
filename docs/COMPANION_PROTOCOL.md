# Companion protocol (mobile tiers)

This document specifies how a phone would talk to a desktop MYAV. **No mobile app exists
yet.** This is a design contract, published early so that an app can be built against
something stable and so that the security properties are reviewed before code exists.

If you are looking for a phone app, there is none. [PLATFORMS.md](PLATFORMS.md) §6–7
explains why the tiers are shaped this way.

---

## 1. Why a companion, not a port

A phone cannot do what a desktop can:

| Constraint | Android | iOS |
|---|---|---|
| Watch another app's file writes | Only with Device Owner / privileged app | Impossible |
| Read arbitrary shared storage | With restricted `MANAGE_EXTERNAL_STORAGE` | Impossible |
| Run a persistent background scanner | Heavily restricted by Doze | Impossible |
| Quarantine another app's file | Generally no | No |

Porting the desktop engine would produce a product that *looks* like protection and is
not. The companion model is honest: the phone asks a MYAV instance it trusts, and shows
the answer. The heavy lifting stays where it is permitted.

---

## 2. The three tiers

| Tier | Name | What runs where | Ships? |
|---|---|---|---|
| **T0** | On-device hash lookup | App computes SHA-256 locally; asks a paired desktop for a verdict on that hash | Planned |
| **T1** | On-device scan of picked files | App copies the picked file into its sandbox, scans it with an embedded engine, quarantines inside the sandbox | Research |
| **T2** | Full device protection | Requires platform privileges a normal app does not have | Out of scope |

T0 is the realistic first product. T1 is a research direction. T2 is stated so nobody
promises it later by accident.

---

## 3. Transport

### 3.1 Default: local network, explicit pairing

- The desktop runs `myav companion serve --listen 127.0.0.1:8765` **only on loopback by
  default**. To reach a phone, the operator must explicitly opt into a LAN bind.
- Transport is **TLS 1.3** with a self-signed certificate generated on first run. The
  certificate fingerprint is displayed as a short code for out-of-band comparison.
- Pairing is a one-time exchange: the phone scans a QR code containing the desktop's
  address, certificate fingerprint, and a single-use pairing token valid for 120 seconds.
- After pairing, the phone holds a per-device token; the desktop stores its hash only.

There is no cloud relay, no account, and no third-party server. If the phone and the
desktop cannot reach each other, the companion does nothing — by design.

### 3.2 What is never sent

| Data | Allowed? |
|---|---|
| File contents | **Never** (T0/T1 both) |
| File name | Never |
| Full path | Never |
| SHA-256 hash | Yes (T0) — this is the query |
| Verdict + engine summary | Yes (response) |
| Device name chosen by the user | Yes, for the pairing list |
| Location, contacts, identifiers | Never |

The same privacy rule as the desktop applies: a hash is a fingerprint, and it is the
minimum needed to answer "do you know this file?".

---

## 4. Messages

All messages are JSON over HTTPS. Version is in the path so a future protocol can coexist.

### 4.1 `POST /v1/pair`

Request (from the QR code, no prior trust):

```json
{
  "token": "single-use-token-from-qr",
  "device_name": "Rodolfo's phone",
  "device_public_key": "base64-ed25519-public-key"
}
```

Response:

```json
{
  "device_id": "c1f0…",
  "desktop_name": "rodolfo-laptop",
  "protocol": "1.0"
}
```

Errors: `401` invalid or expired token, `429` too many attempts (lockout for 15 minutes).

### 4.2 `POST /v1/lookup` (T0)

Request:

```json
{
  "sha256": "a3f1…9c2e",
  "size": 1048576,
  "first_seen": "2026-11-01T12:00:00Z"
}
```

`size` and `first_seen` are optional context for the report; the verdict does not depend
on them.

Response:

```json
{
  "sha256": "a3f1…9c2e",
  "verdict": "MALICIOUS",
  "confidence": "signature",
  "engines": [
    {"name": "clamav", "status": "MALICIOUS", "signature": "Win.Trojan.Agent-1234567"},
    {"name": "yara", "status": "CLEAN"},
    {"name": "virustotal", "status": "SKIPPED", "detail": "not configured"}
  ],
  "degraded": [],
  "checked_at": "2026-11-01T12:00:03Z",
  "cache": {"hit": false, "ttl_seconds": 86400}
}
```

The response is deliberately a **subset** of the desktop verdict: no paths, no quarantine
IDs, no report text. The phone does not need them and must not receive them.

### 4.3 `POST /v1/scan` (T1, research only)

Not implemented. Reserved so that a future protocol version does not break T0 clients.
A T1 request would upload a file, which contradicts §3.2; it therefore requires a separate,
explicitly consented protocol version and is out of scope for v1.

### 4.4 `GET /v1/health`

```json
{"status": "ok", "engine": "myav 0.1.0", "protocol": "1.0", "signatures_age_hours": 4}
```

Unauthenticated on loopback; authenticated on a LAN bind.

---

## 5. Verdict semantics on the phone

The phone must not invent confidence. Mapping is fixed:

| Desktop verdict | Phone shows | Phone must not show |
|---|---|---|
| `MALICIOUS` | "Known malware. Do not open." | A red shield implying it blocked anything |
| `SUSPICIOUS` | "Suspicious. Treat with caution." | "Infected" |
| `CLEAN` | "No known malware found." | "Safe" |
| `UNKNOWN` | "Could not check. This is not a pass." | A green check |

That last row is the whole point. A phone that shows a green tick for UNKNOWN is worse
than a phone with no app.

---

## 6. Failure behaviour

| Situation | Required behaviour |
|---|---|
| Desktop unreachable | Show "not checked", never a cached CLEAN for a different hash |
| Certificate changed | Refuse to connect until the user re-pairs; show the new fingerprint |
| Token rejected | Clear the pairing, require a new QR scan |
| Rate limited (`429`) | Back off, show "try again later", do not retry in a tight loop |
| Desktop says `UNKNOWN` | Show UNKNOWN, with the reason string |
| Hash mismatch after local recompute | Abort; never send a hash you did not compute from the file |

---

## 7. Threat model for the companion

| # | Threat | Mitigation |
|---|---|---|
| C1 | Rogue desktop impersonates the user's MYAV | TLS certificate fingerprint compared out of band at pairing |
| C2 | Rogue phone queries the desktop | Single-use pairing token, per-device token, lockout after failed attempts |
| C3 | Passive LAN observer learns hashes | TLS 1.3; no plaintext fallback |
| C4 | Hashes logged by the desktop | Companion lookups are stored in the normal scan history **without** the originating device's network address |
| C5 | Phone reports a false CLEAN | The phone renders the desktop's verdict verbatim; UNKNOWN is never green |
| C6 | Stolen phone keeps access | Per-device token can be revoked on the desktop; list with `myav companion devices` |
| C7 | QR code shoulder-surfing | Token expires in 120 seconds and is single-use |
| C8 | Desktop exposed to the internet by mistake | Loopback bind by default; LAN bind requires an explicit flag and prints a warning |

---

## 8. CLI surface (desktop side, planned)

```text
myav companion serve [--listen 127.0.0.1:8765] [--lan]
myav companion devices            list paired devices
myav companion revoke <device-id> revoke one device
myav companion pair               print a new single-use QR/token
```

These commands are specified here and are **not implemented**. `myav companion` does not
exist in the current CLI; running it will produce a usage error. This document is the
contract the implementation must satisfy.

---

## 9. What this protocol deliberately does not do

- It does not let the phone scan files on the desktop.
- It does not let the phone browse the desktop's quarantine or reports.
- It does not push alerts; polling only.
- It does not work across the internet.
- It does not make the phone protected against malware that never reaches the desktop.

Each of those is a real product someone might want. None is in scope, and adding one would
require a new protocol version and a new threat-model review.

---

## Summary

The companion model exists so that MYAV can be honest on mobile: **the phone asks, the
desktop answers, and the answer is only ever as confident as the evidence.** Hash in,
verdict out, nothing else.
