# aur-scan Threat Coverage

> **Single source of truth** for what the detection catalog covers, where the gaps
> are, and which work item owns closing each gap. Adversarial by assumption: a
> real attacker reads this file and our ruleset. Keep it current — every vector
> session updates its row when it lands.
>
> Status as of `release/1.1.0-rc1` (the 1.1.0-rc2 code). Catalog: **106 codes**
> across 13 categories. The authoritative, machine-readable list is
> `aur-scan codes`; this doc is the *map*, not the dump.

## How detection works (the model you must hold)

Two engines run over a statically-parsed PKGBUILD (+ `.install`). **Nothing is ever
executed, sourced, or eval'd** — the PKGBUILD is read as text.

1. **Pattern rules** — `crates/aur-scanner-core/src/rules/mod.rs`. Regex
   `Pattern::Rule`s. They get two things for free via `rules::match_content`:
   - **FP suppression** — `informational_lines()` / `is_pure_message_print()` skip
     lines a package merely *prints* (echo/cat/printf message bodies, heredocs).
   - **De-obfuscation** — every rule is also run against the *decoded* variant
     produced by `textutil::deobfuscate` (`normalize_shell_quoting`: ANSI-C
     `$'\x63'`/`$'\NNN'` decode + adjacent-quote-splitting collapse `"b"'u''n'`).
     **This is the multiplier:** hardening normalization hardens the whole catalog
     at once. *Caveat:* the de-obf pass currently only benefits `match_content`,
     and its trigger is too narrow — see [Known defects](#known-defects).

2. **Structural analyzers** — `crates/aur-scanner-core/src/analyzer/*.rs`
   (`source`, `checksum`, `privilege`, `remote_exec`, `deep`, `ioc`, `pattern`).
   Use an **analyzer, not a regex, whenever you need `$pkgdir`-awareness** (the
   `regex` crate has no lookbehind, so it cannot tell a staged
   `install -Dm644 x "$pkgdir/etc/…"` from a live `/etc` write) **or** to read
   parsed metadata fields. Model new analyzers on `privilege.rs`.

The catalog auto-registers rule IDs; **`cli/commands/explain.rs` has a hardcoded
related-codes table that must be extended for every new ID.**

## The non-negotiable bar

**Near-zero false positives.** The clean fixtures
(`tests/fixtures/clean/{example-package,git-package}`) MUST stay clean. Legit
packages install units/hooks/sudoers/etc. *into `$pkgdir`* in `package()`; only
**live-path writes, active verbs, or install-scriptlet** actions are malicious.
Every session adds **both** a positive fixture and a staged-clean fixture that
must NOT fire, keeps the 124-test baseline green, `clippy` clean, and re-runs
`docs/examples/capture.sh` (the audited dataset). A gate that cries wolf is
discarded by users — FP discipline *is* the product.

---

## Coverage status by vector

| Vector | Owning task | State | Build |
|--------|-------------|-------|-------|
| Obfuscation / encoding | **3980** | engine shipped; normalization extensions pending | rules + `textutil` + `deep` |
| RCE / payload delivery (makepkg/VCS/.SRCINFO) | **3981** | core covered; makepkg-specific surfaces open | `remote_exec` + `pattern` + new `.SRCINFO` pass |
| Persistence | **3982** | regex-only today; **needs `$pkgdir`-aware analyzer** | new `analyzer/persistence.rs` |
| Privilege-escalation / tampering | **3983** | base covered; FP fix + new TAMPER codes open | `privilege` + rules |
| Exfiltration / C2 / credential theft | **3984** | reverse-shells + base exfil shipped; deeper channels open | rules + `ioc` |
| Supply-chain / metadata | **3986** | **largely uncovered** — parser extracts fields no analyzer reads | new `analyzer/metadata.rs` |

Cross-cutting bug fixes to *existing* code live in the **rc2-hardening** batch
(see [Known defects](#known-defects)); they are owned there, not by the vector
tasks, so a file has one owner per wave.

---

## 1. Obfuscation / encoding evasion — task 3980

**Pathways:** ANSI-C quoting; adjacent-quote word-splitting; base64/base32/hex/octal
encode→decode→exec; `printf`-assembled commands; `${!var}` indirection,
`${var:off:len}` slicing, `${var//x/}` strip, `IFS=` reassembly; `rev`; `eval`.

**Covered:** the de-obf engine (`normalize_shell_quoting` + `match_content`);
`OBF-001`/`OBF-002` (base64 decode, `eval`); `OBF-003`/`OBF-004`/`OBF-005`;
`OBF-006` (quote-splitting); `OBF-007`/`OBF-008` (printf-assembly, base32/16);
`OBF-011` (interpreter here-string); `DEEP-001`/`DEEP-002` (multi-line
decode-and-exec paired with a sink).

**Gaps:** decode `$(printf …)` / `base64 -d` *literals inline* so every rule sees
the real payload (the highest-value normalization extension); `OBF-009` `${!var}`/
slicing; `OBF-010` `| rev`; `OBF-012` `${//}`/`IFS`; `deep.rs` decode set
(`printf \NNN`, `od`, `hexdump`, `rev`, `tr` redirect forms).

**FP notes:** `printf %s/%d` is ubiquitous → require ≥2 numeric escapes; do **not**
decode base64 that is only assigned or written to a file; `${:off:len}` legit
string-trim → Med, escalate near a sink; `IFS=$'\n'` legit → only flag
printable-non-whitespace IFS.

## 2. RCE / payload delivery (makepkg / VCS / .SRCINFO) — task 3981

**Pathways:** `curl|sh` and every fetch→interpreter variant; process-sub
`sh <(curl)`, `source <(…)`, `eval $(…)`; here-string fetch; top-level
`var=$(curl)` run when makepkg sources the PKGBUILD; network/exec inside
`pkgver()`/`prepare()`/`check()` (run on every build, even `-o`); VCS checkout
running upstream hooks/submodules; PKGBUILD/.SRCINFO divergence (reviewers read
`.SRCINFO`).

**Covered:** `DLE-001`/`DLE-002`/`DLE-003` (download|shell); `EXEC-REMOTE`
(`remote_exec.rs` FETCH_EXEC alternation); `EXEC-002` (`sh -c "$(curl)"`);
`EXEC-005` (detached `setsid`/`nohup`); `FUNC-001` (network in a build function);
`INSTALL-001`/`-003`/`-004`, `ATOMIC-001`/`-002`/`-003` (interpreters /
package-managers in install hooks).

**Gaps:** extend FETCH_EXEC fetchers (`axel`, HTTPie `http`/`https`, `wget2`,
`curlie`) across **all** branches, not just `| sh`; `EXEC-003` here-string fetch;
`EXEC-004` top-level command-substitution; `FUNC-002` network/exec in
`pkgver/prepare/check` (allow read-only git porcelain); `.SRCINFO` mini-parser +
cross-check vs PKGBUILD; `chmod +x`→exec outside `/tmp` (HIDDEN-002 is /tmp-only).

**FP notes:** `build()` runs compilers — never flag; `pkgver` `git describe` is
legit; `-git` branch-tracking is the norm (escalate only when unpinned **and**
non-trusted host).

## 3. Persistence — task 3982 (build the analyzer)

**Pathways:** systemd system/user units, `.socket`/`.path`/`.timer`, drop-in
overrides, `systemctl enable --now`; cron / `| crontab -`; shell rc + `profile.d`;
X11/KDE autostart; `udev RUN+=`; pacman hooks to live dirs; dbus / NM-dispatcher /
polkit; `ld.so.preload`, `modules-load.d`/`modprobe.d`; git hooks; `tmpfiles.d`.

**Covered:** `PERSIST-001..006` (systemd/cron/rc.local/autostart) — **regex-only,
cannot distinguish staged `$pkgdir` installs from live writes.**

**Gaps (high priority):** build `analyzer/persistence.rs` (model on
`privilege.rs`): SUPPRESS when the target is `$pkgdir`/`$DESTDIR`-staged; FLAG on a
live absolute path, an active verb, or an install scriptlet. New codes
`PERSIST-007..016`; `-010` (shell rc/profile.d append) is the trivial, ubiquitous,
totally-uncovered top priority; `-015` (`ld.so.preload`/modprobe) is rootkit-grade.

**FP notes (load-bearing):** legit packages ship units/hooks/udev/dbus/tmpfiles
INTO `$pkgdir`. The staged-clean fixture MUST produce zero findings.

## 4. Privilege-escalation / system tampering — task 3983

**Pathways:** SUID/SGID; sudoers/`doas`/NOPASSWD; privileged account or password
change; auth-db write; PAM; polkit; `nsswitch`; PATH-shadow of a common binary;
`LD_*`; CA trust anchor; pacman `SigLevel=Never` / repo injection; disabling
security controls.

**Covered:** `PRIV-001..006` (sudo/suid/sudoers/setcap/kernel-module/etc.);
`PRIV-007`/`-008` (privileged account, password); `TAMPER-001`/`-002`/`-005`/
`-011`/`-013`/`-017` (auth-db, doas/NOPASSWD, PAM, pacman `SigLevel`, disabling
controls, CA anchor); `TRUST-001`/`-002` (pacman-key/gpg import); `ENV-001..003`.

**Gaps:** `TAMPER-004` polkit, `-006` nsswitch, `-007` PATH-shadow, `-008`
`LD_LIBRARY_PATH`, `-009` `profile.d`, `-010` live pacman hooks (single-owner with
persistence `-013`). Path-write rules want the same `$pkgdir` gate as persistence
(reuse the analyzer or scope to InstallScript).

**FP notes:** `useradd -r` service accounts are legit (PRIV-007 scoped to
uid0/`-o`/wheel/sudo); `setcap` legit; `update-ca-trust` legit (only anchor-add is
signal). **The PRIV `informational_lines` FP is a shipped bug → owned by
rc2-hardening, not this task.**

## 5. Exfiltration / C2 / credential theft — task 3984

**Pathways:** reverse/bind shells (every interpreter); DNS/ICMP/HTTP-upload/email/
cloud-CLI exfil; webhooks; anonymous file-drop; `.onion`/tor; hardcoded C2 token;
cloud/CI creds, keyrings/wallets, env dump, clipboard.

**Covered:** `SHELL-001..011` (bash/nc/python/perl/php/ruby/lua/awk/node/openssl/
mkfifo/busybox/telnet/ncat reverse shells); `EXFIL-001..004`/`006..009` (DNS, curl/
wget upload, Slack/Teams webhooks, file-drop/tunnel hosts); `CRED-001..005`/`008`
(ssh/cloud/CI creds, keyrings/wallets, env dump); `IOC-001` (campaign indicators).

**Gaps:** `EXFIL-005` ICMP, `-010` email, `-011` cloud-CLI; `C2-001` onion/tor,
`C2-002` hardcoded high-entropy token co-located with a network verb; `CRED-009`
clipboard.

**FP notes:** key on method/flag (`-T`/`-d`/`--upload-file`/`--post-data`/`DNS-$()`),
**never bare `curl`**; clipboard + entropy stay Medium and require co-occurrence;
exclude checksum-array lines from the entropy-token rule.

## 6. Supply-chain / metadata — task 3986 (build the analyzer)

**Pathways:** `provides=` shadowing a core package (dependency confusion);
`replaces=`/`conflicts=` displacing a trusted package; stealth `epoch`; `backup=`
of a sensitive file; `install=` outside the package; source-host ≠ `url=`-host;
malformed/wrong-length hash; `::`-rename masquerade; typosquat; unused
`validpgpkeys`.

**Covered:** `SRC-001..007`/`009` (transport integrity, VCS pinning, raw-IP,
obfuscated-IP); `CHK-001..006` (checksum laundering / SKIP across arrays);
`META-001` (`provides=`, informational); `DEP-003`; `PROV-001` (provenance
baseline).

**Gaps (largely uncovered):** build `analyzer/metadata.rs` over already-parsed
fields (the parser extracts `provides`/`conflicts`/`replaces`/`epoch`/`backup`/
`install`/`url`/`validpgpkeys` but **no analyzer reads them**; `validpgpkeys` is
currently dropped into the generic var map): `META-002..007`, `DEP-001`/`-004`,
`SRC-008`/`-010`, `CHK-008`.

**FP notes:** SKIP for VCS, `validpgpkeys`, and `build()`-deps are normal; gate
`META-003`/`DEP-001` on a curated **core/base** name list (not "any repo package");
exclude legit `-git`/`-bin` alternates and self-provides; typosquat must exclude
exact matches + common affixes.

---

## Known defects (rc2-hardening — fix before promoting rc→stable)

Found in the 2026-06-15 four-agent codebase review. These are bugs in **shipped
rc2 code**, owned by the rc2-hardening batch (not the vector tasks). Each file has
a single owner per wave to avoid collisions.

| # | Sev | Where | Defect |
|---|-----|-------|--------|
| 1 | High | `aur.rs:307` `package_exists` | **Fail-open:** swallows a network error as `false`, so `is_aur_package` → "not AUR" on a transient RPC blip and the wrapper installs it **unscanned**. Must fail closed (unknown ⇒ treat as AUR). |
| 2 | High | `wrapper.rs:177,278` | **TOCTOU:** wrapper scans its own fetch, then paru re-fetches & builds a *different* copy. Built ≠ scanned. Hand paru the scanned dir or mark advisory. |
| 3 | High | `static_parser.rs:188,216` | **Parser evasion:** multi-line array terminates on a `)` *inside a quoted value* (`ends_with(')')` is not quote-aware) → a whole malicious `source=`/`sha256sums=` line is hidden from every analyzer. |
| 4 | Med-High | `parser/mod.rs:332` | **Panic/DoS:** CRLF + multibyte `.install` slices mid-codepoint (`map(\|l\| l.len()+1)` under-counts `\r\n`). Don't reconstruct byte offsets from `lines()`. |
| 5 | High (FP) | `privilege.rs:54-189` | Bypasses the informational-line filter → a printed `sudo`/`setcap`/`sudoers` message or heredoc fires **Critical PRIV-001** and can flip the gate. Route through `informational_lines()`. |
| 6 | High (FN) | `textutil.rs`, `remote_exec.rs`, `deep.rs` | **De-obf trigger too narrow** (the marquee feature): 2-char quote-splitting (`"cu""rl"`) and backslash-escapes (`c\url`) bypass it; **`dash` is matched nowhere** (`(…|d|…)?sh` ≠ `dash`); de-obf isn't applied in `remote_exec`/`deep`/`ioc`. Normalize every line; unify shell/interpreter alternations into one shared constant; run de-obf in the analyzers. |
| 10 | Med (FP) | `rules/mod.rs` HIDDEN-002 / INSTALL-002 | Fire on `TMPDIR=/tmp/…`, `mktemp -d /tmp/…`, `./configure`. Require an execution context. |
| 11 | Med | `install.rs:203` | Build prompt has no `is_terminal()` guard → piped `y` accepted as consent. |
| — | FN | `rules/mod.rs` ATOMIC-002 | `npm ci`/`npm exec`/`pnpm dlx`/`yarn dlx` run lifecycle scripts but are unmatched. (Owned by the gate/detection hardening lane; folds toward 3981.) |

**Lower-priority hardening (defense-in-depth):** predictable `0644` provenance temp
(reuse cache's `0600`+random atomic write); install workspace dirs `0755` not
`0700` + no symlink check; depgraph width-cap enforced only after a full BFS level;
unbounded `read_to_string` of operator files; `system.rs` reads PKGBUILDs through
symlinks unlike the hook.

## Verified-solid (do not regress)

`validate.rs` chokepoint (tight allowlist, `.`/`..` rejected, applied at every entry
point); network hardening is *real* (HTTPS-only enforced, redirects `Policy::none()`,
streamed body cap re-checked vs actual bytes, percent-encoded path segments); the
defanged `git clone` (hooks off, `protocol.file/ext=never`, no symlinks/submodules/
tags, `--`); privilege-drop order correct + verified irreversible; CLI `install`/
`check` + hook fail **closed**; cache key-binding + corrupt-as-miss; checksum
SKIP-laundering defense; linear-time `regex` (no ReDoS class).

---

## Adjacent tracks (not vector coverage)

- **Binary-payload analyzer** (salvaged from PR #9): inspect prebuilt `-bin`
  artifacts. Offline tiers (declared-hash IOC, ELF eBPF/import/string, entropy)
  belong in core and are static-only. Open decisions: scanner-side fetch-as-inert-
  data (so the structural tier fires at gate time) vs scope to `system` forensics;
  `BIN-PACKED` entropy must be scoped so benign AppImages don't trip High.
- **Capability-provider plugin framework**: VirusTotal and other *network/capability*
  providers are **plugins**, never core. Tier 1 = declarative (community TOML rules +
  IOC feeds, data-only). Tier 2 = first-party-only, compiled-in, opt-in behind a
  cargo feature + explicit config, capability-declaring. No runtime-loadable
  third-party code — that would invert the tool's trust model. VT is the first Tier-2
  provider; its in-tree-vs-companion-tool placement is an open brand decision.

## Maintenance protocol

When a vector session lands: update its section (move closed pathways from Gaps to
Covered with the new IDs), tick the status table, and note any new FP-scoping
learned. When a hardening item lands: strike it from Known defects. This file is the
coverage contract — if it says "covered," a regression test must prove it.
