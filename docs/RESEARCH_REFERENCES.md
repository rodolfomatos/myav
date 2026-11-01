# Research references

Every source cited here is real and was checked at the time of writing. Nothing in this
file is a placeholder, and no DOI or URL has been invented. Where a claim is **not**
supported by a source, the text says so instead of attaching a citation.

Two purposes:

1. Show what the design decisions rest on.
2. Show what the research track would have to beat to ship.

MYAV Core ships only what is deterministic and explainable. The papers below about machine
learning and behaviour are **research directions**, not features.

---

## 1. Standards and primary documentation

These are the specifications MYAV is actually built against.

| Source | What it is | Used for |
|---|---|---|
| [EICAR test file](https://www.eicar.org/download-anti-malware-testfile/) | The standard harmless antivirus test string | `myav selftest` |
| [ClamAV documentation](https://docs.clamav.net/) | Official ClamAV manual (clamd, clamscan, freshclam, signature format) | Engine integration, `clamd.conf` |
| [YARA documentation](https://yara.readthedocs.io/en/stable/) | Official YARA language and CLI reference | Rule compilation, severity metadata |
| [yara-python](https://yara.readthedocs.io/en/stable/modules/python.html) | Python bindings for YARA | Optional fast path in `engines/yara.py` |
| [Neo23x0/signature-base](https://github.com/Neo23x0/signature-base) | Public YARA rule pack | The optional rule pack, pinned by commit |
| [VirusTotal API v3](https://docs.virustotal.com/reference/overview) | Official API reference | Hash-only lookup, rate limits |
| [MITRE ATT&CK](https://attack.mitre.org/) | Adversary tactics and techniques knowledge base | Threat-model vocabulary (persistence, execution) |
| [NIST SP 800-83 Rev. 1](https://csrc.nist.gov/pubs/sp/800/83/r1/final) | *Guide to Malware Incident Prevention and Handling for Desktops and Laptops* | Detection/response framing; why prevention ≠ detection |
| [TOML v1.0.0](https://toml.io/en/v1.0.0) | Configuration file format | `config.toml` |

### Why these are the *primary* sources

A blog post describing ClamAV is not a specification. Where a behaviour matters (for
example, the exit codes of `clamscan`, or the `x-apikey` header of VirusTotal), the source
of truth is the upstream documentation, and the code is written against that.

---

## 2. Why signature detection has a ceiling

MYAV's honest limitation — "a new sample returns CLEAN" — is not a bug, it is the known
property of signature matching. The literature is unambiguous.

| Reference | Contribution | What MYAV takes from it |
|---|---|---|
| Kolter, J. Z., & Maloof, M. A. (2006). *Learning to Detect and Classify Malicious Executables in the Wild.* Journal of Machine Learning Research, 7, 2721–2744. [jmlr.org](https://www.jmlr.org/papers/v7/kolter06a.html) | Early, careful demonstration that static features can classify malware, and that the problem is adversarial and drifting | Detection is a moving target; a fixed database ages |
| Bayer, U., Comparetti, P. M., Hauswirth, M., & Kruegel, C. (2009). *Scalable, Behavior-Based Malware Clustering.* NDSS 2009. [ndss-symposium.org](https://www.ndss-symposium.org/ndss2009/scalable-behavior-based-malware-clustering/) | Behavioural clustering of malware families at scale | Motivation for the Research track, and why behaviour is a different signal from bytes |
| Rossow, C., Dietrich, C. J., Bos, H., Cavallaro, L., van Steen, M., Freiling, F. C., & Pohlmann, N. (2012). *Prudent Practices for Designing Malware Experiments: Status Quo and Outlook.* IEEE Symposium on Security and Privacy. DOI: [10.1109/SP.2012.20](https://doi.org/10.1109/SP.2012.20) | Methodology for malware experiments: isolation, realism, reproducibility | Why MYAV will not ship an unmeasured ML detector; any Research result must state its methodology |
| Pendlebury, F., Pierazzi, F., Jordaney, R., Kinder, J., & Cavallaro, L. (2019). *TESSERACT: Eliminating Experimental Bias in Malware Classification across Space and Time.* USENIX Security 2019. [usenix.org](https://www.usenix.org/conference/usenixsecurity19/presentation/pendlebury) | Shows that naive random train/test splits overstate malware classifiers; time-aware evaluation changes conclusions | The bar any MYAV Research model must clear: temporal, not random, evaluation |

### The consequence for this project

A "CLEAN" verdict is evidence of absence *from the loaded databases*, not evidence of
safety. [LIMITATIONS.md](LIMITATIONS.md) §2 states this without hedging, and the report
text repeats it on every clean scan. That is the design response to the literature above.

---

## 3. Why machine learning is Research and not Core

The temptation is to bolt a classifier onto the scanner and call it "adaptive". The
literature explains why that usually produces a demo rather than a detector.

| Reference | Contribution | What MYAV takes from it |
|---|---|---|
| Sommer, R., & Paxson, V. (2010). *Outside the Closed World: On Using Machine Learning for Network Intrusion Detection.* IEEE Symposium on Security and Privacy. DOI: [10.1109/SP.2010.25](https://doi.org/10.1109/SP.2010.25) | The canonical argument that ML trained on the "closed world" of a dataset fails under real base rates and adversary adaptation | Why Core stays deterministic; why a Research model must report base rates and false positives, not accuracy |
| Anderson, H. S., & Roth, P. (2018). *EMBER: An Open Dataset for Training Static PE Malware Machine Learning Models.* arXiv:1804.04637. [arxiv.org/abs/1804.04637](https://arxiv.org/abs/1804.04637) | Open, reproducible feature set and dataset for static PE malware ML | A candidate evaluation baseline if the Research track starts; nothing is bundled |
| Küchler, N., Böttinger, K., Martin, A., & Arp, D. (2021). *Does Every Second Count? Time-based Evolution of Malware Behavior in Sandboxes.* NDSS 2021. [ndss-symposium.org](https://www.ndss-symposium.org/ndss-paper/does-every-second-count-time-based-evolution-of-malware-behavior-in-sandboxes/) | Shows sandbox observations depend strongly on observation time; short runs miss behaviour | Why a sandbox integration cannot be advertised as complete detection |

### The policy that follows

A feature enters Core only if it is:

1. deterministic (same input → same verdict);
2. explainable (the report can name the rule or signature);
3. measurable (false-positive rate is stated);
4. offline (no dependency on a remote model service).

Baselines, ML, graph analysis and sandboxing fail at least one of those today. They are
described in [PROJECT_STATUS.md](../PROJECT_STATUS.md) as Research, with no completion
date, and they are not presented as protection.

---

## 4. Why detection is not prevention

MYAV's central limitation — it sees a file after it lands, not before it runs — is a
systems fact, not a shortcut.

| Reference | Contribution | What MYAV takes from it |
|---|---|---|
| Continella, A., Gu, G., Zingaro, D., Kruegel, C., & Vigna, G. (2016). *ShieldFS: A Self-healing, Ransomware-aware Filesystem.* ACSAC 2016. DOI: [10.1145/2991079.2991110](https://doi.org/10.1145/2991079.2991110) | A filesystem-level defence that intercepts writes in the kernel | Illustrates the layer MYAV does not occupy: meaningful blocking requires kernel/filesystem integration |
| NIST SP 800-83 Rev. 1 (above) | Distinguishes prevention, detection, and response controls | MYAV is a detection + response tool; it says so everywhere |

A user-space program using `inotify`/FSEvents/`ReadDirectoryChangesW` receives an event
after the write. There is no portable API that lets an unprivileged process veto an
`execve`. Any product claiming otherwise on desktop is either using a kernel component or
overstating itself.

---

## 5. Antivirus effectiveness, measured honestly

These are useful for setting expectations, and for arguing against "just install AV and
you are done".

| Reference | Contribution | Caution |
|---|---|---|
| MITRE ATT&CK evaluations | Public, scenario-based evaluation of endpoint products | Evaluates commercial products, not MYAV; useful as a vocabulary and as a reality check |
| AV-Comparatives and AV-TEST public reports | Independent malware-protection testing of commercial suites | Methodology and samples differ from MYAV's; not directly comparable |

MYAV does **not** claim an AV-TEST score, a detection percentage, or an ATT&CK coverage
map. It has no such measurement, and inventing one would be the exact dishonesty this
project is organised against.

---

## 6. Supply-chain integrity

MYAV treats its own rule pack and its dependency tree as attack surface (see
[THREAT_MODEL.md](THREAT_MODEL.md) §B1).

| Source | Used for |
|---|---|
| [SLSA](https://slsa.dev/) | Vocabulary for supply-chain levels; informs the "pin the commit, record the hash" design |
| [Sigstore / cosign](https://www.sigstore.dev/) | Direction for future artefact signing; **not yet used** |
| [CycloneDX](https://cyclonedx.org/) | SBOM format used for the dependency inventory in `docs/sbom/` |
| [OpenSSF Scorecard](https://github.com/ossf/scorecard) | Checklist for repository hygiene; aspirational for this project |

At the time of writing, MYAV's concrete supply-chain controls are:

1. YARA rules are fetched at a **pinned commit** and the archive SHA-256 is recorded in
   `PROVENANCE.json`.
2. Rules are **never vendored** into git.
3. Dependencies are few and pinned in `pyproject.toml`.
4. An SBOM is generated and committed; see `docs/sbom/`.

It does not yet sign releases. That is listed as missing in
[PROJECT_STATUS.md](../PROJECT_STATUS.md) rather than implied.

---

## 7. Design references for the non-AV parts

| Topic | Source | Use |
|---|---|---|
| Secure defaults | [NIST SP 800-123](https://csrc.nist.gov/pubs/sp/800/123/final) *Guide to General Server Security* | Loopback-only daemons, least privilege |
| File permission model | POSIX / `open(2)` man pages | `0600` config, `0700` dirs, `O_NOFOLLOW` on quarantine writes |
| Scheduler semantics | [systemd.timer(5)](https://www.freedesktop.org/software/systemd/man/systemd.timer.html), [launchd.plist(5)](https://www.manpagez.com/man/5/launchd.plist/), [schtasks](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/schtasks) | The four recurring jobs |
| WSL filesystem behaviour | [Microsoft WSL documentation](https://learn.microsoft.com/en-us/windows/wsl/) | Why `/mnt/c` is slow and excluded |

---

## 8. What is deliberately *not* cited

To keep this list trustworthy, the following are absent on purpose:

- **Blog posts and vendor marketing** as evidence of effectiveness.
- **Papers I could not verify** — no DOI or URL was guessed. If a claim needed a source I
  could not confirm, the claim was removed or marked as unsupported.
- **Detection-rate numbers** — MYAV has not measured its own detection rate, so quoting
  someone else's would imply a comparison that does not exist.
- **"AI-powered" claims** — the Research track has no results yet, so it has no citations
  claiming results.

If you find a citation here that does not resolve, that is a documentation bug. Open an
issue with the reference and what you expected.

---

## 9. How to verify a citation

Every entry above is a stable identifier or an official domain. To check one:

```bash
# DOI entries resolve through the DOI resolver
curl -sI https://doi.org/10.1109/SP.2010.25 | head -1

# arXiv entries resolve to an abstract page
curl -sI https://arxiv.org/abs/1804.04637 | head -1

# Official docs
curl -sI https://docs.clamav.net/ | head -1
```

Expect `HTTP/2 200` or a redirect to the publisher. A `404` means the reference needs
fixing, not that the paper does not exist.
