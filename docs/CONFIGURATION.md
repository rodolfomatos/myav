# Configuring MYAV

Everything MYAV remembers about your preferences lives in **one small text file**:

```text
~/.config/myav/config.toml
```

If that file does not exist, MYAV uses safe defaults. Creating it is optional; the only
setting most people ever change is the optional VirusTotal key, explained step by step below.

---

## 0. Where the file lives on your equipment

The `~` in `~/.config/myav/config.toml` is shorthand for “your home folder”. Each operating
system spells that differently. Use the row that matches your machine:

| Your equipment | The file is here | How to open its folder |
|---|---|---|
| Linux / WSL2 Ubuntu | `~/.config/myav/config.toml` (for example `/home/ana/.config/myav/config.toml`) | `cd ~/.config/myav` |
| macOS | `~/.config/myav/config.toml` (for example `/Users/ana/.config/myav/config.toml`) | `cd ~/.config/myav` |
| Windows, native | `%APPDATA%\myav\config.toml` (for example `C:\Users\ana\AppData\Roaming\myav\config.toml`) | Paste `%APPDATA%\myav` into File Explorer’s address bar |

Two things follow from that table:

- **On Windows, `~` is not the folder you think.** `%APPDATA%` is the per-user roaming folder.
  Use the exact path above; do not create `C:\Users\ana\.config`.
- **The rest of MYAV’s data lives elsewhere.** Section 8 lists every location, including the
  Windows and macOS equivalents of `~/.local/state` and `~/.local/share`.

> **Plain-words recap.** Configuration is one text file. You do not need a database, a registry
> editor, or an installer wizard. If you can edit a note, you can configure MYAV.

---

## 1. The one rule: permissions (Linux and macOS)

The file may contain an API key, so MYAV refuses to read it if other users can read it.

```bash
ls -l ~/.config/myav/config.toml
```

The permissions must be `-rw-------` (`0600`). If they are not:

```bash
chmod 600 ~/.config/myav/config.toml
```

**Why so strict?** An API key is a password. On a shared machine, a world-readable config file
means another user can spend your VirusTotal quota. MYAV checks this before parsing the file
and stops with a clear error instead of silently using an exposed key.

The parent directory `~/.config/myav/` is created as `0700` for the same reason.

### Windows is different — and that is fine

Windows has no `chmod 600`. Access is controlled by **NTFS permissions** (also called ACLs):
the operating system decides which user accounts may read a file. Your `%APPDATA%` folder is
already private to your user account, which is why MYAV does **not** enforce POSIX mode bits
there.

**What you should do on Windows:** nothing special. Do not try to run `chmod`; it will either
fail or do something unrelated. If you want to check, open PowerShell and run:

```powershell
icacls "$env:APPDATA\myav\config.toml"
```

You want to see your own username with `(F)` (full control) and no line granting `Everyone`
or `Users` read access. If you are on a shared Windows account, create a separate Windows user
for each person; that is the real boundary.

> **Why the difference exists.** “Owner-only” is a *concept*; every OS implements it
> differently. Linux and macOS use mode bits. Windows uses ACLs. MYAV asks the operating
> system for the strongest private location it offers instead of pretending one mechanism is
> universal.

---

## 2. Looking at the effective configuration

```bash
myav config show
```

This prints the merged result: defaults plus anything in your file. The VirusTotal key is
redacted by default:

```json
"virustotal": {
  "enabled": true,
  "api_key": "0123…ef",
  "configured": true
}
```

To see the full key (for example, to check that you pasted the right one):

```bash
myav config show --reveal
```

Only do that when nobody is looking over your shoulder. The key never appears in reports,
logs or scan output.

---

## 3. Every setting, explained

The file is [TOML](https://toml.io/en/). A section starts with `[name]`, and each line inside
is `key = value`. Lines starting with `#` are comments.

### `[clamav]` — the signature engine

```toml
[clamav]
prefer_daemon = true
tcp_host = "127.0.0.1"
tcp_port = 3310
local_socket = "/run/clamav/clamd.ctl"
timeout = 60
```

| Key | Default | What it means in plain words |
|---|---|---|
| `prefer_daemon` | `true` | Try `clamd` first (fast, keeps signatures in memory). If it is not running, fall back to `clamscan`, which starts a new process per file and is slower. |
| `tcp_host` | `127.0.0.1` | Where `clamd` listens. Loopback means “this computer only”. Do not change this to a network address; MYAV is not designed to expose a scanner to other machines. |
| `tcp_port` | `3310` | The standard ClamAV daemon port. |
| `local_socket` | `/run/clamav/clamd.ctl` | A Unix socket alternative to TCP. Useful when TCP is restricted. |
| `timeout` | `60` | Seconds to wait for one engine. A timeout becomes `UNKNOWN`, never `CLEAN`. |

### `[yara]` — the pattern engine

```toml
[yara]
timeout = 30
max_scan_bytes = 104857600
malicious_severity = 7
suspicious_severity = 4
```

| Key | Default | What it means |
|---|---|---|
| `timeout` | `30` | Seconds allowed for the YARA scan of one file. |
| `max_scan_bytes` | `104857600` (100 MiB) | Files larger than this are not pattern-scanned. It protects memory and battery. |
| `malicious_severity` | `7` | A rule whose severity metadata is at least this is treated as **MALICIOUS**. Rules from the public pack express severity as 0–10. |
| `suspicious_severity` | `4` | A rule at or above this (but below `malicious_severity`) is treated as **SUSPICIOUS**. |
| constraint | — | `suspicious_severity` must be less than or equal to `malicious_severity`. MYAV rejects the file otherwise. |

**Why two thresholds?** A rule that says “this file contains a PowerShell download cradle” is
strong evidence. A rule that says “this binary imports `VirtualAlloc`” is weak evidence, because
many legitimate programs do. Severity lets MYAV separate the two without pretending both are
certain.

### `[virustotal]` — optional hash reputation

This is the only section that talks to the internet. It is off by default.

```toml
[virustotal]
enabled = true
api_key = "your-64-character-key"
requests_per_minute = 4
requests_per_day = 500
ttl_positive_seconds = 604800
ttl_negative_seconds = 86400
timeout = 15
```

| Key | Default | What it means |
|---|---|---|
| `enabled` | `false` | Master switch. With no key, it stays off even if you write `true`. |
| `api_key` | empty | Your private VirusTotal key. 64 hexadecimal characters. |
| `requests_per_minute` | `4` | The free public API limit. Do not raise it above what your account allows. |
| `requests_per_day` | `500` | Daily limit. MYAV counts its own requests and stops before the limit. |
| `ttl_positive_seconds` | `604800` (7 days) | How long a “known malicious” answer is reused before asking again. |
| `ttl_negative_seconds` | `86400` (24 h) | How long a “not found / clean” answer is reused. |
| `timeout` | `15` | Seconds to wait for the HTTPS request. |

The full walkthrough, including how to get a key, is section 4.

### `[watcher]` — what gets watched

```toml
[watcher]
watch_dirs = ["~/Downloads", "~/Desktop", "~/Documents"]
watch_removable = true
settle_seconds = 2.0
workers = 2
queue_size = 256
```

| Key | Default | What it means |
|---|---|---|
| `watch_dirs` | the three folders | Absolute paths, or paths starting with `~/`. MYAV expands `~` against *its own* home, so a system service and your terminal agree. |
| `watch_removable` | `true` | Also watch USB sticks and removable volumes as they appear. |
| `settle_seconds` | `2.0` | Wait this long after the last write before scanning. Browsers write downloads in chunks; scanning the first chunk would produce a partial, misleading result. |
| `workers` | `2` | How many files are scanned at once. More workers use more CPU and disk. Two is a good laptop default. |
| `queue_size` | `256` | How many pending file events can wait. When the queue is full, events are **dropped and counted**, and the report says so. It never silently ignores files. |

To watch another folder, add it:

```toml
[watcher]
watch_dirs = ["~/Downloads", "~/Desktop", "~/Documents", "~/Projects/incoming"]
```

A relative path is rejected at startup. That is deliberate: a daemon’s working directory is not
your working directory, so a relative path would watch the wrong place.

### `[intel]` — offline threat-intel cache

```toml
[intel]
enabled = false
max_age_hours = 168
timeout = 20
```

| Key | Default | What it means |
|---|---|---|
| `enabled` | `false` | When `true`, and the cache has indicators, the scanner consults the local IOC cache for an **exact SHA-256 match**. A match makes the file MALICIOUS. |
| `max_age_hours` | `168` | Age after which a feed is considered stale in status output. It never deletes indicators automatically. |
| `timeout` | `20` | Network timeout used by `myav intel update` when the source is an HTTP(S) URL. Scans never use the network. |

The cache is populated explicitly:

```text
myav intel update --name urlhaus --source https://urlhaus.abuse.ch/downloads/csv_recent/
myav intel import ~/misp-export.json --name misp --format misp-json
myav intel status
myav intel check <sha256|url|domain|ip>
myav intel clear --yes
```

Only exact SHA-256 hits change a file verdict. URLs, domains and IPs are stored and
reported by `myav intel check`, but they are advisory: matching them inside arbitrary
file contents would be a heuristic with an unmeasured false-positive rate.

### `[scan]` — how a scan behaves

```toml
[scan]
timeout = 60
follow_symlinks = false
skip_hidden = false
```

| Key | Default | What it means |
|---|---|---|
| `timeout` | `60` | Per-file scan budget. |
| `follow_symlinks` | `false` | Do not follow symbolic links. This avoids loops and stops a symlink from pointing the scanner at `/`. |
| `skip_hidden` | `false` | When `true`, names starting with `.` are skipped. Leave it `false` unless you have a reason: malware can hide in a dot-directory. |

### `[report]` — how many reports to keep

```toml
[report]
retention = 90
```

MYAV keeps the newest `retention` report files in `~/.local/state/myav/reports/` and removes
older ones when a new report is written. It only removes its own report files, never anything
else.

---

## 4. Getting and installing a VirusTotal key (complete walkthrough)

This section assumes you have never used VirusTotal.

### 4.1 What VirusTotal is

VirusTotal is a website owned by Google that runs files through dozens of antivirus engines and
shows the results. If someone has already uploaded a file, VirusTotal knows what those engines
said about it.

MYAV uses VirusTotal as a **second opinion**:

- MYAV computes the file’s SHA-256 hash locally.
- MYAV asks VirusTotal: “have you seen this hash before?”
- VirusTotal answers with counts such as “3 of 70 engines call this malicious”.

### 4.2 What MYAV sends — and what it does not

| Sent | Not sent |
|---|---|
| The 64-character SHA-256 hash | The file itself |
| The HTTPS request (standard web metadata) | The file name |
| | The folder path |
| | Your name, email, or machine name |

**Important privacy fact:** a hash is a fingerprint. If VirusTotal did not already have the
file, the lookup tells them that *someone, somewhere* has a file with that fingerprint. That is
a much smaller disclosure than uploading the file, but it is not zero. This is why the feature
is off by default and why the documentation says so plainly. See [PRIVACY.md](PRIVACY.md).

### 4.3 Create an account (free)

1. Open <https://www.virustotal.com/>.
2. Click **Sign up** (top right).
3. Create an account with an email address, or sign in with a Google account.
4. Confirm your email if asked.

You do not need to pay anything for the public API. The free tier is rate-limited, not
feature-locked.

### 4.4 Find your API key

1. Sign in.
2. Click your avatar (top right) → **API key**.
   Direct link: <https://www.virustotal.com/gui/my-apikey>
3. You will see a long string of 64 characters: digits `0-9` and letters `a-f`.
4. Click the copy icon.

**Treat this key like a password.** Anyone who has it can spend your quota. Do not paste it
into a chat, a screenshot, a public issue, or a git commit.

### 4.5 Give the key to MYAV (recommended way)

On Linux, WSL and macOS:

```bash
myav config set-vt-key
```

On native Windows (PowerShell):

```powershell
.venv\Scripts\myav config set-vt-key
```

MYAV will prompt:

```text
Paste your VirusTotal API key (it is not echoed, and it never leaves this
machine except as the x-apikey header on hash lookups).
Get one free at https://www.virustotal.com/gui/my-apikey — docs/CONFIGURATION.md
walks through it.
API key:
```

Paste the key and press Enter. It is **not** echoed to the screen. MYAV validates that it is
exactly 64 hexadecimal characters, writes `~/.config/myav/config.toml` with mode `0600` from
the first byte, and enables the engine.

Expected output:

```text
Wrote /home/you/.config/myav/config.toml (mode 0600).
VirusTotal will now be asked about file *hashes* only — never file contents.
Check with: myav doctor
```

### 4.6 Alternative: non-interactive install

Useful for a script or a password manager:

```bash
MYAV_VT_API_KEY="paste-the-key-here" myav config set-vt-key
```

On native Windows PowerShell the same idea uses PowerShell’s variable syntax:

```powershell
$env:MYAV_VT_API_KEY = "paste-the-key-here"
.venv\Scripts\myav config set-vt-key
Remove-Item Env:\MYAV_VT_API_KEY
```

`$env:NAME = "value"` means “set an environment variable for this PowerShell window only”.
The last line removes it again so it is not inherited by programs you start later.

Or pass it directly (any platform):

```bash
myav config set-vt-key --key "paste-the-key-here"
```

Avoid `--key` on a shared shell if your shell records history; the environment variable or the
prompt is safer. On PowerShell, `Get-History` can show earlier commands, so prefer the prompt
or the environment variable.

### 4.7 Verify it works

```bash
myav doctor
```

Look for:

```text
OK    VirusTotal: hash-only lookups enabled
```

Then scan a harmless file and look at the “What ran” section of the report:

```bash
echo "test" > ~/Downloads/vt-check.txt
myav scan ~/Downloads/vt-check.txt --report
myav report
```

A configured engine shows as enabled. A file that VirusTotal has never seen produces a
`not-found` result in the engine details; that is normal and does **not** mean the file is safe.

### 4.8 Turn it off again

Edit the file:

```toml
[virustotal]
enabled = false
```

or temporarily override with an environment variable for one command (if you prefer not to
edit the file, delete the `[virustotal]` section entirely):

```bash
mv ~/.config/myav/config.toml ~/.config/myav/config.toml.off
myav doctor
```

With no key, the engine reports `not configured (optional)` and verdicts rely on ClamAV and
YARA only. Nothing breaks; the report tells you the truth.

### 4.9 Troubleshooting the key

| What you see | What it means | What to do |
|---|---|---|
| “That does not look like a VirusTotal API key” | Wrong length or non-hex characters (for example, you pasted your *email*) | Copy the key again from the API key page |
| `401 Unauthorized` in engine details | The key is wrong, revoked, or has a typo | Re-run `myav config set-vt-key` |
| `403 Forbidden` | The account is restricted or the key belongs to a different product | Check the key on the VirusTotal site |
| `429 Too Many Requests` | You exceeded 4 requests/minute or your daily quota | MYAV backs off and records `degraded`; wait and retry. Do not raise the limits above your plan |
| `doctor` says “not configured” after you set a key | The file permissions are wrong, so MYAV refused to read it | `chmod 600 ~/.config/myav/config.toml` |
| The key appears in `myav config show` | You passed `--reveal` | That is expected; do not share the output |

---

## 5. Complete example file

This is a realistic configuration for a laptop. Copy it, then change what you need.

```toml
# ~/.config/myav/config.toml
# chmod 600 this file.

[clamav]
prefer_daemon = true
timeout = 60

[yara]
timeout = 30
max_scan_bytes = 104857600
malicious_severity = 7
suspicious_severity = 4

# Optional. Off unless you add a key.
[virustotal]
enabled = true
api_key = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
requests_per_minute = 4
requests_per_day = 500

[watcher]
watch_dirs = ["~/Downloads", "~/Desktop", "~/Documents"]
watch_removable = true
settle_seconds = 2.0
workers = 2
queue_size = 256

# Optional. Off until you import a feed and enable it.
[intel]
enabled = false
max_age_hours = 168
timeout = 20

[scan]
timeout = 60
follow_symlinks = false
skip_hidden = false

[report]
retention = 90
```

---

## 6. What happens when the file is wrong

MYAV refuses to guess. Examples of errors you may see:

| Error | Cause | Fix |
|---|---|---|
| `config.toml is mode 0644; myav requires 0600` | Other users can read it (Linux/macOS) | `chmod 600 ~/.config/myav/config.toml` |
| `invalid TOML` | A missing quote, bracket, or `=` | The message includes the line number; fix that line |
| `yara.suspicious_severity must be <= yara.malicious_severity` | The two thresholds are inverted | Swap them |
| `watcher.watch_dirs must be absolute` | You wrote `Downloads` instead of `~/Downloads` | Add `~/` or the full path |
| `unknown config section [foo] ignored` | A typo or a future setting | It is a warning, not an error; MYAV still runs |

**On Windows you will never see the `0644` error.** That check is disabled there on purpose,
because Windows uses NTFS permissions rather than POSIX mode bits. If you copied a config from
Linux and MYAV cannot find it, you probably put it in `~/.config` out of habit: on Windows it
must be in `%APPDATA%\myav\config.toml`.

To check without running a scan:

```bash
myav config show
```

Exit code `4` means the configuration is invalid or unsafe.

---

## 7. Settings that are not in this file

Some things are intentionally controlled elsewhere:

| Thing | Where | Why |
|---|---|---|
| Scan schedule (02:30 update, Sunday 03:00 full scan) | `myav schedules print` / your system scheduler | The scheduler belongs to the operating system, not to MYAV |
| Quarantine contents | `myav quarantine …` | Files are data, not configuration |
| Allowlisted hashes | `myav allow …` | Stored in the state database with an audit trail |
| Scan scope for a one-off scan | `myav scan PATH` / `myav full-scan PATH` | Command-line intent should not rewrite a file |

---

## 8. Where the rest of MYAV’s data lives

The table below uses Linux notation first, then the equivalent on the other systems. “State”
means “what happened”; “data” means “files MYAV owns, such as quarantined payloads”.

| What | Linux / WSL | macOS | Windows |
|---|---|---|---|
| Settings (may hold the VT key) | `~/.config/myav/config.toml` | `~/.config/myav/config.toml` | `%APPDATA%\myav\config.toml` |
| State database | `~/.local/state/myav/state.db` | `~/Library/Application Support/myav/state.db` | `%LOCALAPPDATA%\myav\state\state.db` |
| Reports | `~/.local/state/myav/reports/` | `~/Library/Application Support/myav/reports/` | `%LOCALAPPDATA%\myav\state\reports\` |
| Scheduler logs | `~/.local/state/myav/logs/` | `~/Library/Application Support/myav/logs/` | `%LOCALAPPDATA%\myav\state\logs\` |
| Quarantined payloads | `~/.local/share/myav/quarantine/` | `~/Library/Application Support/myav/quarantine/` | `%LOCALAPPDATA%\myav\quarantine\` |
| Fetched YARA rules | `~/.local/share/myav/rules/` | `~/Library/Application Support/myav/rules/` | `%LOCALAPPDATA%\myav\rules\` |
| Compiled YARA cache | `~/.cache/myav/` | `~/Library/Caches/myav/` | `%LOCALAPPDATA%\myav\cache\` |

On Linux and macOS, every MYAV-owned directory is `0700` and the config file is `0600`. On
Windows the same protection comes from the per-user `%APPDATA%` / `%LOCALAPPDATA%` folders,
which other Windows accounts cannot read.

MYAV never writes under `/mnt/c` on WSL. If you ask it to, it refuses with an explicit error.
That guard exists because the Windows disk on the reference machine was completely full.

> **Feynman check.** If you remember only one thing: **settings are one file in your home
> folder; everything else is inside folders named `myav`.** Deleting those folders returns the
> machine to the state it was in before MYAV, apart from the ClamAV/YARA packages you installed
> separately.
