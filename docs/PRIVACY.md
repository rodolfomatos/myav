# Privacy — what leaves your computer

Short answer: **nothing, unless you turn on VirusTotal, and even then only a hash.**

This page lists every network destination MYAV can contact, what it sends, why, and how
to stop it. There is no telemetry, no analytics, no crash reporting, no update phone-home
and no account.

---

## 1. The default: fully offline

With a fresh install and no VirusTotal key, MYAV makes **zero network requests during a
scan**. Detection is ClamAV signatures plus local YARA rules, both read from disk.

You can prove this yourself. Run a scan with the network interface down:

```bash
myav scan ~/Downloads
```

It works exactly the same. Nothing times out, nothing degrades, nothing waits on a remote
service. That is the "local-first" claim in practice.

---

## 2. Every possible network destination

| Destination | When | What is sent | Default | Can it reveal file contents? |
|---|---|---|---|---|
| **ClamAV mirror** (`database.clamav.net` and mirrors) | `freshclam`, daily at 02:30, or `sudo myav update-signatures` | Standard HTTP(S) request for signature archive; mirror sees your IP and the file name requested | On (this is how signatures stay current) | No |
| **GitHub** (`api.github.com`, `codeload.github.com`) | `myav rules fetch`, once, and only after `--accept-license` | Request for the pinned commit and tarball of `Neo23x0/signature-base`; GitHub sees your IP | Off until you run it | No |
| **VirusTotal** (`www.virustotal.com`) | Only if `virustotal.enabled` is true **and** a key is set | The 64-character SHA-256 hash in the URL path, plus your API key in a header | **Off** | No — hash only |
| **None** | Normal scanning, quarantine, reports, scheduling | — | — | — |

There is no fifth row. MYAV does not contact:

- an update server run by this project (there isn't one);
- a "reputation cloud" for YARA rules;
- a licensing server;
- a telemetry endpoint;
- Google Analytics or any equivalent.

---

## 3. VirusTotal in detail (the only meaningful disclosure)

### What is sent

```http
GET https://www.virustotal.com/api/v3/files/<sha256> HTTP/1.1
x-apikey: <your key>
```

That is the entire request. The hash is the file's SHA-256 fingerprint.

### What is not sent

- the file itself;
- the file name;
- the folder path;
- the file size;
- your username or machine name;
- the scan report;
- anything from your other files.

MYAV has no code path that uploads a file. The VirusTotal engine is a `GET` on a hash. If
you want to upload a file to VirusTotal, you do it in a browser, consciously, not through
MYAV.

### What the disclosure actually means

A hash is a fingerprint. If VirusTotal already knows the file, the lookup adds almost no
new information — they already had it.

If VirusTotal **does not** know the file, your request tells them: *someone, somewhere,
just looked up this fingerprint*. They do not learn who you are, but they learn the file
exists and that it is being checked. Combined with timing and IP address, that is a small
but non-zero disclosure.

This is why the feature is:

1. **off by default**;
2. **opt-in with a key you create yourself**;
3. **documented here in plain language** rather than buried in a legal page.

### How to be certain nothing is sent

Leave the key empty. The engine reports `not configured (optional)` and is skipped; the
report says so.

To turn it off after configuring it, edit `~/.config/myav/config.toml`:

```toml
[virustotal]
enabled = false
```

or remove the `[virustotal]` section entirely.

To disable it for one scan without editing anything, quarantine the config temporarily:

```bash
mv ~/.config/myav/config.toml ~/.config/myav/config.toml.off
myav scan ~/Downloads
mv ~/.config/myav/config.toml.off ~/.config/myav/config.toml
```

---

## 4. ClamAV signature updates

`freshclam` is ClamAV's own updater. It asks a mirror for the newest signature database.
The mirror sees:

- your IP address;
- the standard HTTPS metadata (user agent, timestamp);
- which file it served (a fixed signature archive name).

It does **not** see your files, your hashes, or your scan results. This is the same
mechanism every ClamAV installation uses and is not specific to MYAV.

If you want a fully offline install, you can update signatures on another machine and copy
`/var/lib/clamav/*` across. MYAV does not provide tooling for that, but nothing prevents
it.

---

## 5. YARA rule download

`myav rules fetch --accept-license` makes two requests:

1. `api.github.com` — to resolve the latest commit of the rule repository;
2. `codeload.github.com` — to download that commit's tarball.

GitHub sees your IP and the public repository you requested. That is all. The archive is
verified against the commit and its SHA-256 is recorded in `PROVENANCE.json`, so you can
audit exactly what was downloaded.

After the fetch, YARA runs entirely locally. Rules are never re-downloaded automatically;
`--update` is required.

---

## 6. What is stored on your disk, and who can read it

| Path | Contents | Permissions |
|---|---|---|
| `~/.config/myav/config.toml` | Settings; may contain the VirusTotal key | `0600` (owner only) |
| `~/.local/state/myav/state.db` | Scan history, paths scanned, verdicts, quarantine metadata, startup baseline, VT cache | `0700` directory |
| `~/.local/state/myav/reports/` | Markdown reports, including file paths and verdicts | `0700` directory |
| `~/.local/state/myav/logs/` | Scheduler logs | `0700` directory |
| `~/.local/share/myav/quarantine/` | Quarantined payloads, mode `0000`, random `.bin` names | `0700` directory |
| `~/.local/share/myav/rules/` | Fetched YARA rules and provenance | `0700` directory |
| `~/.cache/myav/` | Compiled YARA cache | `0700` directory |

MYAV enforces `0600` on the config file and `0700` on every directory it owns. It
**refuses to read** a config file that other users can read, because that would mean an
exposed API key.

These files are readable by root, by design. On a machine where root is hostile, no
user-space tool can help you; that is a threat model boundary, not a MYAV bug (see
[THREAT_MODEL.md](THREAT_MODEL.md) §C).

### What is *not* stored

- file contents (except quarantined payloads, which you chose to keep);
- your browser history or anything outside the scan scope;
- environment variables;
- clipboard contents;
- screenshots;
- a list of installed software (beyond the startup-entry inventory, which is the
  feature you asked for).

---

## 7. Reports contain paths — treat them as sensitive

A report is a list of files you scanned and what MYAV thought of them. That can reveal
project names, client names, or the fact that you downloaded a particular file.

Before sharing a report publicly (for example in a bug report), redact:

- absolute paths that contain your username;
- file names that identify a person or client.

MYAV does not redact paths automatically, because doing so would make the report less
useful for its main purpose. Redaction is a human decision.

---

## 8. Quarantine and privacy

A quarantined file is stored on your disk, not sent anywhere. It is a **move**, not an
upload. Mode `0000` prevents accidental execution.

Two honest caveats:

1. **Backups copy it.** If your backup tool runs as root and includes
   `~/.local/share/myav`, quarantined malware goes into your backups. exclude that path
   if that matters to you.
2. **It is not encrypted.** Anyone with root can read it. Quarantine is containment, not
   a vault.

Purging is permanent and requires `--yes`.

---

## 9. Children, shared machines, and multi-user systems

MYAV stores everything per user, under that user's home directory. It does not create a
system-wide database, a system user, or a shared quarantine.

On a shared machine:

- each user who runs MYAV has their own state and quarantine;
- the ClamAV signature database is system-wide (that is ClamAV's design, not MYAV's);
- `clamd` listens on `127.0.0.1` only — never on a network interface — so other machines
  cannot use your scanner.

There is no cloud account, so there is nothing to share with a family member or
employer. That is the point of local-first.

---

## 10. Compliance statements (careful, non-absolute)

- **GDPR:** MYAV processes no personal data on a remote service. Local reports may
  contain personal data (file paths); you control retention (`report.retention`).
- **HIPAA / PCI:** MYAV is not a compliance control. It is a detector. Do not present it
  as an audit requirement.
- **VirusTotal:** their terms and privacy policy govern the hash lookups. Read them
  before enabling the feature in a regulated environment.

MYAV makes no certification claims.

---

## 11. How to verify all of this yourself

The privacy claims are testable, not just asserted:

```bash
# 1. Watch for network syscalls during a scan (needs strace)
strace -f -e trace=network myav scan ~/Downloads 2>&1 | grep -i "connect"
# Expect: no connect() to a remote address with no VT key configured.

# 2. Inspect the config permissions
ls -l ~/.config/myav/config.toml
# Expect: -rw-------

# 3. Confirm the engine state in a report
myav doctor | grep -i virustotal
# Expect: "not configured (optional)" unless you set a key.

# 4. Read the code
grep -rn "urlopen\|requests\.\|http" src/myav/
# Expect: exactly two places — engines/virustotal.py and rules.py.
```

If you find a network call anywhere else, that is a security bug. Report it via
[SECURITY.md](../SECURITY.md).

---

## Summary

| Question | Answer |
|---|---|
| Does MYAV send my files anywhere? | No. |
| Does it send file names or paths? | No. |
| Does it send hashes? | Only if you enable VirusTotal. |
| Does it phone home to the project? | It has no home to phone. |
| Can I run it completely offline? | Yes, except signature updates. |
| Who can read my quarantine? | You, and root. |
