# Vordr — Improvement Plans

Rewritten 2026-07-18 against the source tree. The previous version had drifted
(it referenced `tests\redteam.py`, `docs/FORMAT.md`, `inflate.asm`, and CLI verbs
that no longer exist) and was deleted. Every plan below was verified absent or
partial in the code before being listed here.

**Status note (2026-07-18):** `origin/audit-cleanup` was merged into master
(merge commit 8e893a0). Fifteen plans it implemented were removed from this
file: anti-rollback save counter, full-file MAC, save durability + backup
rotation, crash containment, single-instance + external-change detection,
fuzzy sidebar search, trash/undo-delete, drag-and-drop attachments, central
font factory (the S/M/L size setting was added then deliberately dropped in
1b562dc), parser fuzzer, zip-import fuzzer, dead-code detector, reproducible
builds, parallel fail-closed KAT gate (`pkat`, after measurement showed the
KATs cost ~0 ms), and sidebar virtualization (closed with an engineering
verdict: the owner-draw listbox already paints on demand).

**Scope cut (2026-07-18):** E1 (otpauth import), E3 (tags), E4 (templates),
E5 (expiry), E10 (emergency sheet), E12 (clip verb), E13 (breach check),
E14 (auto-type), F3 (DPI), F5 (screen-reader) and F7 (localization) were
removed as out of project scope; recover them from git history if ever wanted.

**Done 2026-07-19:** A1 (cpu_gate now requires SHA-NI; refusal text updated,
refusal path verified with the bit masked) and A2 (framecheck evaluates
symbolic frame sizes — `equ` chains and `sizeof` — and reports unresolvable
frames instead of silently skipping; 11 symbolic-size procs now scanned.
Note: FP findings are warn-by-design, so detection was verified at warn level
with a seeded case, not a strict-build failure). Both removed from this file.

**Done 2026-07-19 (D-group):** D1 (aurora path, `securedesk` spike → dbg-only,
CSV corpse — plus `deadcode.py` no longer counts `public`/`extern` as
references and now scans `macros.inc`; the improved tool found and led to the
removal of `aes_ecb_decrypt`, `theme_backdrop`, `vault_add_entry`,
`ze_export_all`, `va_field`, `SHA1_CTX_SIZE` and six dead CLI field buffers),
D2 (formats.md rewritten, SECRETS.md re-cited by proc, README TPM/density/
BLAKE2b/rollback/MAC claims corrected, stale comments/strings everywhere,
`.gitignore` pruned, committed log/reg artifacts deleted), D3 (`.inc` files
now documented as canonical), D4 (`tools/idcheck.py` gates rc↔asm ID sync in
strict builds), D5 (SDK version resolved at build time). All removed from
this file.

**Done 2026-07-19 (redesign merge, 2c9f744):** the `Vordr_ALT` redesign branch
(36 commits) was merged and the fork deleted. Landed: custom borderless frame
with title-bar search control + command dock, ghost buttons, resizable window
with anchor reflow, read-only-by-default opens + save retry with error dialog,
per-vault availability state machine, `VAULTCTX`/VSLOT multi-vault contexts
with a tab strip and cross-vault search, modular details pane (heading dock,
VF_GROUP/VF_SPACER blocks, entry templates), Ctrl+K/N/G/L shortcuts, and the
mvtest/mvswitch/avtest gate probes. E8 (multi-vault) and F2 (resizable window)
removed from this file as done; the remaining redesign items are group R.
(**The multi-vault contexts / tab strip / cross-vault search / availability
machinery and their probes were later ripped out — 2026-07-23, single-vault only;
see group M.**)
The reverted virtual-scroll commits were secured on branch `recovered-scroll`
before the fork was deleted.

**Done 2026-07-20 (security audit → PR #2, branch `audit-fixes`):** a full-tree
security + stability audit. Landed: the ZIP import parser is fully bounded (the
attacker-controlled overflows in `zj_str`, the field loop, `zi_u2w`/
`zi_stage_title`/`zi_addattach`, and the staged-entry count are all closed);
opaque attachment ZIP member names (entry titles no longer leak in cleartext);
overflow-safe `attach_index_build` bounds + an `attach_open` ctlen/ptlen cross-
check; **the FMAC trailer is now mandatory, with `VAULT_VERSION` bumped to 2**
(see the Format note); a passphrase-length bound in `pwgen_ex`; secret-wipe gaps
closed (`g_hbuf`, `g_rowpw_w`, `g_conv`/`g_convlabel`, `g_urlbuf`, and `g_cfg_pass`
after the startup KAT gate); `argon2id_hash`/`run_selftest` preserve r12/r13/r15;
`gcm_open` scrubs `outp` on tag mismatch; `reg_query_sz` gets a REG_SZ type-check +
NUL-termination; an http/https URL allowlist; `base32_decode` fails instead of
truncating; `write_file`/`log_open` guards; TPM RSA-2048 set explicitly; the
`pkat` CS-teardown race; dead empty `crc32.asm` removed. Follow-ups the audit
surfaced are new below: C7, D6, E16, G8 (the deferred CI SHA-pin is G7.3).

**Done 2026-07-20 (C6, registry location-leak hygiene → PR #2):** the per-vault
HKCU value names — the rollback mirror (`reg_ctr_set`/`reg_ctr_get`) and the TPM
blob (`reg_tpm_set`/`get`/`del`), both previously keyed by the **raw vault path**
— are now SHA-256-hashed to a fixed 32-hex name by `reg_hash_name`, so the vault
location no longer leaks; `reg_prune_all` (called from `vault_unlock`) deletes any
surviving legacy path-named value. Runtime-verified: after a run the Rollback key
holds only hashed names, zero path-leaking. This also closes C4.2 (the TPM value-
name leak), so C4 keeps only the Hello-PIN item. Remaining nicety (not a leak): a
hashed orphan left by a *moved* vault is opaque but not pruned — a touch-timestamp
+ expiry could add that later if wanted.

**Done 2026-07-21 (C8, concurrent shared-drive access → PR #2):** vaults open
read-only with full share (they already did); a save takes a brief advisory
`<vault>.lock` (`CREATE_NEW` + `FILE_FLAG_DELETE_ON_CLOSE`) and, under it, refuses
to overwrite a vault another writer changed since load (`EXIT_CHANGED`) - the GUI
reloads via `vault_reload` (re-decrypt with the existing key, no re-KDF) instead
of clobbering. A held lock -> `EXIT_BUSY` "try again"; the idle poll silently
refreshes a clean vault; a read-only vault file auto-enters E9 read-only mode.
Probes `reload` + `cowrite` gated in RUNALL; `formats.md` updated. The full
"stash + precise re-apply of the pending edit" and an `AVSLOT`-backed retry with
backoff are possible refinements (the current reload-safe flow already prevents
lost updates).

**Done 2026-07-21 (plan-completion sweep → PR #2):** the remaining
headlessly-verifiable backlog was cleared. **C4** (opt-in `TpmRequireHello`:
`tpm_seal` stamps `NCRYPT_UI_POLICY`, `tpm_unseal` drops the SILENT flags when
set; default off = silent unlock behaviorally unchanged; prompting path can't be
verified without a TPM+Hello, so it is gated off). **E15** (DEFLATE-in-zipimport
resolved as a documented STORED-only limitation in README + the GUI no-entries
message; porting inflate deferred rather than add a fuzzed pre-auth path).
**G7.1** (`vfuzz`/`fuzzzip`/`attfuzz` draw a random seed each run, log it, and
accept `--seed N` to reproduce; shared `fuzz_seed` helper). **E6** (vault-health:
`vault_health` computes {weak, reused, old, total}; `healthkat` KAT gates it in
RUNALL; Ctrl+H shows a summary box; sidebar tiles show a weak-password dot — the
richer modeless dialog + reused/stale badges are folded to **R6**). An
adversarial re-audit of the sweep caught and fixed one real bug: `vault_health`
freed its password-digest scratch without a wipe length, which could leak
BLAKE2b fingerprints or drive an OOB `secure_zero`; it now wipes `n*HSTRIDE`
bytes. C4/E6/E15/G7 sections removed from this file; the visual-only remainder
is group R.

**Done 2026-07-21 (R safe-subset → PR #2):** the headlessly-verifiable slices of
group R that carry negligible visual risk. **R6-lite** — the E6 sidebar dot is
now colour-coded red=weak / amber=stale via `vault_entry_stale` (same >365-day
rule as `vault_health`, KAT'd in `healthkat`). **R5-lite** — the last vault the
user opens is persisted (`reg_save_vault`) so startup reopens it. The pure-layout
/ cross-entry-cache remainder (R2 command palette, R3 DPI retrofit, R4 tab
decorations, R5 multi-vault tab-set, R6 reused dot + modeless dialog) stays
deferred — its acceptance tests are visual and need a display. (The R5
multi-vault tab-set item is **cancelled** — single-vault only since 2026-07-23.)

House rules:

- Plan IDs are stable: `C4` stays `C4` when other plans are completed or added.
  Completed plans are removed from this file in the commit that ships them.
  Code comments must cite plan titles, never bare IDs (IDs outlive rewrites).
- Update this file in the same commit as any behavior change.
- Cite proc/file names, not line numbers (line numbers rot).

## Conventions

- **BUILD** = `build.cmd` completes with `BUILD OK: bin\vordr.exe` (kill any
  running `vordr.exe` first; a locked exe fails LNK1104). Run from an "x64
  Native Tools Command Prompt for VS".
- **STRICT** = `build.cmd strict` — `tools/framecheck.py` FATAL findings fail
  the build.
- **RELEASE** = `build.cmd release` — reproducible build (`/Brepro`,
  `/pdbaltpath`); prints the SHA-256 to publish in `docs/RELEASES.md`.
- **SELFTEST** = `bin\vordr.exe selftest` prints `all self-tests passed`.
- **RUNALL** = `tests\run_all.cmd` — the one-command gate and the entire CI
  pipeline: stage 1 redteam (dbg build; 8 fault-injection cases each exit with
  `0xFADE<code>` in the high word, `iat` dies with `0xC0000005`), stage 2
  strict build, stage 3 selftest, stage 4 probes: `seedtest` → `atgen` →
  `zitest` → `phtest` → `secscan` → `lktest` → `tmptest` → `fztest` → `trtest`
  → `vfuzz` → `fuzzzip` → `bktest` → `mactest` → `rbtest` → `xctest` → `reload`
  → `cowrite` → `attfuzz` → `healthkat` → `pkat` → `mvtest` → `mvswitch` →
  `mvname` → `idkat` → `kekkat` → `keyringkat` → `fedkat` → `fedregkat` →
  `fmskat` → `fedapikat` → `fedfanout` → `avtest`. `--quick` skips stage 1.
- **FRAMES** = no >4-arg `WINCALL` directly inside a raw `sub rsp,64` dialog
  proc (`create_proc`, `unlock_proc`, `vault_proc`, `msg_proc`, `about_proc`,
  …); wide calls go in a `FRAME_PROLOG N` helper. This is the BEX64/offset-0
  crash class.
- **PROBE** = the CLI is diagnostics-only by design: no vault path, password,
  or secret on the command line, and no add/get/list verbs. Scripted vault
  scenarios mean `seedtest`, an existing probe verb, or a new dbg-only probe
  verb.

## Sequencing

- **Format note:** the audit-cleanup merge added the FMAC trailer (a trailing
  `[u64 save_counter][keyed BLAKE2b MAC][magic]` block after the VATT trailer)
  plus a reserved `VF_DELETED` tag as **v1** additions that old readers ignored.
  The 2026-07-20 audit made the FMAC trailer **mandatory** and bumped the header
  to **v2**: `vault_unlock` now rejects any image whose version != `VAULT_VERSION`
  and any v2 image lacking a valid FMAC (`EXIT_AUTH`), so the attachment section
  is always authenticated. In-body **field** additions still follow the tolerant
  pattern — a new reserved `VF_*` tag old readers skip (verify the unknown-tag
  skip path first) — but any change to authentication or container layout must
  bump `VAULT_VERSION`, not ride on tag-skipping.

---

## M. Master-vault federation (multi-vault redesign) — WITHDRAWN (2026-07-23)

**Withdrawn / ripped out (2026-07-23).** Per the user, multi-vault support "only
causes problems for us" — Vordr is now **single-vault**: exactly one vault open at a
time. The federation/multi-vault machinery (VSLOT/ctx array, availability retry state
machine, the machine-local keyring + `FEDLINK`/`FEDREC` + `fed_*`/`keyring_*` +
`reg_fed_*`, `vault_id_of`, the M4 management screen, the M3 unified list, and all
their probes) was removed in commit `4bb6210` (~-3.8k lines). M1-M5, M7, and M8
(`federatetest`) are cancelled — do not implement them.

**M6 — vault as export/import format — LANDED (headless core, gate-green).** The one
surviving deliverable, reframed for single-vault: import from / export to a foreign
`.vordr`, nothing federated. Engine in vault.asm:
- **`fed_export(rcx = source body, edx = carry)`** builds a fresh standalone `.vordr`
  from the source body under a NEW salt + the password in `g_cfg_pass`, written to
  `g_cfg_in` (mirrors `do_seed`'s header / `vk_derive` / `vk_kcv` / `vault_seal_write`).
  `carry=1` copies entries verbatim (`entry_copy_full`) and keeps the source's
  attachment context live through the seal so `vault_seal_write` copies every
  referenced blob into the child (ct verbatim, keyed by the AttachRef's own key, so it
  decrypts under the child's new password); `carry=0` is the text-only path.
- **`fed_merge(rcx = source body)`** copies source entries into the live body, deduped
  by the 16-byte **entry** id (`fed_find_by_id`), newer `modified` winning; idempotent.
  Caller reseals.
- **`entry_copy_filtered`/`entry_copy_full`** preserve id16/created/modified (not
  `vault_build_entry`, which would mint new ids and break dedup).
- Probes **`vaultexportkat`** (export under a different password -> ids round-trip ->
  re-merge is a no-op) and **`vaultexpattkat`** (two attachments carried; blobs decrypt
  byte-for-byte in the child) gate it. The search overlay keeps its ranked `g_xr`
  painter, now single-vault.
- **Follow-ups (open, GUI-gated):** selected-subset export (headless API exports all
  entries; the GUI picks the subset); merge-import attachment carry (v1 `fed_merge`
  still filters — export is the primary attachment case).

---

## P. Passkey (WebAuthn) support — new headline effort (2026-07-23)

**Status: PARKED (2026-07-23).** Captured for a future release; no implementation
work is in progress. Left here in full so it can be picked up later — resume at
P1 (the ECDSA P-256 primitive) once the Decision-1 invocation-bridge choice is
made with the user.

Make Vordr a **passkey provider**: generate, store, and use FIDO2/WebAuthn
discoverable credentials (passkeys) so it can stand in for a website's password
with a phishing-resistant public-key login. A passkey is a per-relying-party key
pair — the private key is a first-class secret (vault-resident, `secmem`-wiped on
lock, never on the CLI per PROBE), the public key + a credential id go to the site.

**Why.** Passkeys are the industry's password replacement; a password manager that
cannot hold them is increasingly incomplete. Vordr already has the hard parts of
the *storage* side (AEAD vault, Argon2 gate, attachments, `secmem` hygiene);
what it lacks is (a) an **asymmetric signing
primitive** and (b) a **way for a browser/OS to invoke it**. This effort is
deliberately split so the whole cryptographic core lands **headlessly, KAT-gated**
(the strong part) before the OS/browser integration (the display-gated part).

**The gating fact.** Vordr today has **no software asymmetric crypto** — only the
TPM/NCrypt RSA sealing in `tpm.asm` (platform, not a primitive we control). WebAuthn's
mandatory algorithm is **ES256 = ECDSA over NIST P-256 with SHA-256** (COSE alg
`-7`). So **P1 (a P-256 + ECDSA implementation) is the critical path**; nothing else
in this group can be tested until it exists. It is a large but self-contained,
KAT-friendly primitive — exactly the kind the new differential crypto harness
(`docs/ASSURANCE.md`, `tests/verify_crypto.py`) was built to prove.

**Decisions to make with the user before P4 (flagged, not assumed):**
1. **Invocation bridge.** How a browser reaches Vordr — the real integration lift:
   - **(a) Windows 11 passkey *plugin authenticator* / credential-manager API**
     (23H2+, 2024): third-party providers register so the native OS passkey UI
     offers them. Best UX, no extension, Windows-only, substantial COM surface and
     app-identity/registration requirements. **Recommended strategic target.**
   - **(b) Browser extension + native-messaging host:** an extension shims
     `navigator.credentials.create/get` and talks to a Vordr helper over
     stdin/stdout JSON. Cross-browser, how 1Password/Bitwarden shipped first, more
     moving parts — and it needs a **new non-GUI process mode** (Vordr is a
     GUI-subsystem exe with a diagnostics-only CLI; a native-messaging host breaks
     the PROBE "no real I/O verbs" shape and must be a separate, explicitly-scoped
     entry point).
   - (c) Full CTAP2 authenticator over hybrid/virtual-HID — heaviest; out of scope
     for v1.
2. **Attestation:** `none` (privacy-preserving, no provider fingerprint —
   **recommended for v1**) vs self/`packed`.
3. **Discoverable (resident) vs server-side credentials:** resident (usernameless,
   the modern default) is primary; also support server-side (credential id carries
   the wrapped private key, zero storage) — decide whether v1 does both.
4. **Signature counter policy:** return **0** (sync-friendly across machines and
   exported/imported copies — recommended) vs a monotonic per-credential counter
   (single-device clone-detection, but clobbers when a vault copy is synced).
5. **Algorithms:** ES256 is mandatory and sufficient for v1; EdDSA (`-8`, Ed25519)
   and RS256 (`-257`) are optional later additions (each a new primitive).

**Security posture (state it plainly).** A passkey private key is the crown jewel:
it is generated with `rng_fill`, stored **only** AES-256-GCM at rest inside the
vault body like every other secret, `VirtualLock`'d + `secure_zero`'d on lock, and
**never** printed, exported in the clear, or accepted/emitted on the command line
(PROBE). Every assertion (login) requires the vault unlocked **and** an explicit
per-use consent gesture bound to the shown relying party — Vordr must **never sign
silently**; the anti-phishing guarantee is that the signature is bound to
`rpIdHash = SHA-256(rpId)` and the origin from `clientDataJSON`, so a look-alike
site gets a different (useless) credential. Deterministic ECDSA (RFC 6979) is used
for signing so a bad RNG can never leak the key through nonce reuse — and it makes
signatures exact-match testable.

### P1. ECDSA over P-256 (ES256) — the new asymmetric primitive (critical path)
1. NIST P-256 field + group arithmetic (256-bit modular over the curve prime and
   order), constant-time scalar multiplication, key generation (`rng_fill` scalar →
   public point), and **deterministic ECDSA** signing (RFC 6979 with SHA-256; Vordr
   already has `sha256_hash`/`hmac`). A verify path too, for self-checking. New file
   `p256.asm`; treat it with the same care as `argon2.asm`/`aesgcm.asm` (frames,
   `secmem` for the private scalar, no secret-dependent branches/indexing).
2. *Test:* `p256kat` (headless, gated in RUNALL) — **NIST CAVP P-256** key/sign
   vectors + the **RFC 6979 Appendix A.2.5** deterministic (r,s) vectors (exact
   bytes), plus a sign→verify round-trip and a tampered-message reject. **Extend the
   differential harness:** add a `katreport` line emitting a deterministic signature
   for a fixed key/message and have `verify_crypto.py` check it against the RFC 6979
   vector and validate it with a small self-contained pure-Python P-256 verify (the
   same "self-validating independent reference" pattern already used for AES-GCM).

### P2. COSE / CBOR + the WebAuthn data objects
1. A minimal canonical **CTAP2 CBOR** encoder (and just-enough decoder), a
   **COSE_Key** EC2 encoder for the public key (`{1:2, 3:-7, -1:1, -2:x, -3:y}`),
   and the WebAuthn structures: **authenticatorData** (`rpIdHash(32) ‖ flags(1) ‖
   signCount(4) ‖ attestedCredentialData ‖ extensions`), the registration
   **attestation object** (`CBOR{fmt:"none", authData, attStmt:{}}`), and the
   assertion signature input (`authData ‖ SHA-256(clientDataJSON)`).
2. *Test:* `webauthnkat` (headless) — byte-exact COSE_Key and
   attestation-object encodings for fixed inputs; the assertion signature over a
   known `authData ‖ clientDataHash` **verifies** against the stored public key
   (chains P1). Canonical-CBOR ordering asserted (deterministic encoding).

### P3. Credential store (vault-resident passkeys)
1. A passkey record = `{ credentialId | rpId | rpIdHash | userHandle | userName |
   private_scalar | publicKey | signCount | created }`. Store as a **new hidden
   entry class** — a reserved **`VF_PASSKEY`** marker on an entry the list builder
   excludes from password rows (self-contained within P; the M1 system-item scheme
   it once leaned on is cancelled) — so it rides the existing authenticated+encrypted
   container with no new parser and round-trips forward-compatibly; the list builder
   shows passkeys in a dedicated view. Server-side (non-discoverable) mode:
   `credentialId` = the AES-256-GCM-wrapped private key (self-contained, no stored
   record). **Format discipline:** a new `VF_*` tag old readers skip is the tolerant
   pattern, but passkey *semantics* need the new reader — decide whether this rides a
   `VAULT_VERSION` bump or stays additive (per the Format note, anything touching
   container/auth layout bumps the version; a new tag alone does not).
2. **Export/import (M6) interaction:** passkeys are ordinary vault entries, so they
   carry through `fed_export`/`fed_merge` like any secret — but the **counter policy
   (Decision 4)** must be sync-safe (returning 0 sidesteps clobber across an
   exported copy). *Test:* `passkeykat` (headless) — create a
   credential, seal → wipe → reload, produce an assertion, assert it verifies
   against the stored public key; **per-RP isolation** (an assertion for `rpId` A
   never validates against B's credential); server-side wrap/unwrap round-trips.

### P4. The invocation bridge (Decision 1 — OS/browser integration, not headless)
1. Implement the chosen path from Decision 1 — recommended: the **Win11 passkey
   plugin authenticator** COM server (register the provider; implement create/get so
   the OS passkey UI lists Vordr; route to P1–P3 + the P5 consent). The
   extension+native-messaging fallback needs the new non-GUI helper process mode
   noted above.
2. *Test (needs a display + a real relying party):* register a passkey on a live
   WebAuthn test site (e.g. `webauthn.io`) via Vordr, then sign in with it; the RP
   accepts the assertion. Not gate-automatable — verified interactively, like the R
   group.

### P5. Consent + user-verification UI (not headless)
1. A per-ceremony consent surface: show the **relying party** and the **account**,
   require an explicit approve gesture, and treat the unlocked vault (password /
   TPM / Hello per C4) as user-verification (UV). Never sign without it; offer
   "this site is asking to sign in as <user> — approve?" with the origin shown for
   anti-phishing. Rate-limit / re-auth for high-value credentials.
2. *Test (needs a display):* a create and a get ceremony each show the RP + account
   and block until approved; declining aborts with no signature emitted.

### P6. Test/probe strategy (headless-first, per PROBE)
The entire crypto core is provable headlessly and must land KAT-gated before P4/P5:
`p256kat` (P1, CAVP + RFC 6979), `webauthnkat` (P2, byte-exact COSE/attestation +
assertion verify), `passkeykat` (P3, create→seal→reload→assert→verify + per-RP
isolation + server-side wrap). All hermetic, synthetic keys, **never emit a private
scalar**, wired into `tests\run_all.cmd`, and the P1 signature cross-checked by the
independent `verify_crypto.py` reference. Only P4 (OS/browser) and P5 (consent UI)
need a live environment — mirror the R-group "verified interactively" stance.

**Sequencing.** P1 (P-256/ECDSA — the gating primitive, KAT-gated) → P2 (COSE/CBOR
+ WebAuthn objects) → P3 (`VF_PASSKEY` store, decide the `VAULT_VERSION`
interaction) → **decision point** (P4 invocation bridge — pick (a) or (b) with the
user) → P4 → P5 (consent UI). P6 KATs land alongside P1–P3. Do **not** start P4
before P1–P3 are green — the integration is worthless without a proven, testable
signing core, and P1 is a multi-week primitive on its own. P3's storage is a
self-contained `VF_PASSKEY` hidden-entry class — no dependency on other groups.

---

## R. Redesign remainder — the current active backlog (2026-07-21)

With the C/E/G backlog cleared, group R is what's left. Every R item is
**painter/interaction work whose acceptance test is visual** ("100% vs 200%
screenshots", "scrolls with no paint over the header", "fast-scrolls to the
right letter"), so each needs a real display to verify — they were deliberately
left for an environment where the window can be seen, rather than shipped
build-green-but-unverified. The headlessly-safe slices are already done (R5-lite
last-vault restore, R6-lite weak/stale tile dot — see the Done log). Sequence
suggestion for the visual remainder: R3 (DPI, touches every painter — do it
before adding more) → R6/R4 (tile decorations, shared analysis/enumeration) →
R2 (palette). (R5's multi-vault tab-set restore is cancelled — see below.)

Folded in from `docs/REDESIGN_PLAN.md` (the standalone doc was merged into
this file and deleted). The redesign landed with merge 2c9f744: custom frame +
title-bar search & dock, ghost buttons, resizable reflow, the B1–B3 IO
contract, multi-vault contexts/tabs/cross-vault search (**since removed —
single-vault only, 2026-07-23**), modular details pane (groups/spacers/templates),
and Ctrl+K/N/G/L shortcuts. What remains:

### R2. Command palette (Ctrl+Shift+P)
The landed title-bar overlay in command mode (`>` prefix): Lock, New item,
Export, Import, Settings, theme switching, Trash view. *Test:* every command
fires; fuzzy ranks correctly; Esc closes.

### R3. DPI audit
Revived by the redesign (supersedes the 2026-07-18 scope cut of the old F3).
The layout engine already scales; sweep painters for hardcoded px through a
`dpi_scale` (MulDiv) helper; recreate fonts on WM_DPICHANGED. *Test:* 100% vs
200% screenshots — chips, underlines, icons all scale.

### R4. Sidebar niceties
Tag chips row under search results; alphabet fast-scroll on >200 entries.
*Test:* 5k vault fast-scrolls to the right letter.

### R5. Session restore — DONE (single-vault)
The last successfully-opened vault is persisted via `reg_save_vault`, so startup's
`gui_resolve_vault` (HKLM>HKCU) reopens it. The multi-vault "reopen the whole tab
set as locked placeholders" remainder is **cancelled** with the single-vault
rip-out (2026-07-23) — there is no tab set. Nothing left here.

### R6. Vault-health dashboard, richer (from E6) — partially done
E6 shipped the analysis pass (`vault_health` + `healthkat`), a Ctrl+H summary
box, and a tile dot now colour-coded red=weak / amber=stale (`vault_entry_stale`,
KAT'd). *Remaining (needs a display + a cache):* a modeless health dialog whose
rows jump to the offending entry, a **reused**-password tile indicator, and a
worst-bucket count badge. These need a per-entry classification cached at
`gui_poplist` and invalidated on edit/save (the reused check is O(n²), too heavy
to recompute per paint). *Test:* fix one weak password → badge decrements after
save; clicking a row highlights its tile.

### R7. Title-bar & dialog UI polish (2026-07-21)
Small visual/interaction fixes; all need a display to verify, so they ride with
the R group. Each is independent and can ship together in one session.

**LANDED (2026-07-23) — build-clean + gate-green, AWAITING an on-screen pass.** All
five implemented (strict build 0 fatal / 0 dead; full gate green - the changes are
GUI-only, so no headless probe covers them):
- **R7.1** unlock-dialog theme cogwheel (id 990) removed (`unlock_proc`: the
  `ghost_make`, the dispatch, `up_cyclescheme`, the orphaned `gl_t_theme`).
- **R7.2** ghost-button hover fixed: `TRACKMOUSEEVENT.cbSize` was 16 (x86); on x64
  it must be 24, so `TrackMouseEvent` had failed to arm `WM_MOUSELEAVE` and the halo
  stuck. Root-cause fix.
- **R7.3** unlock "Open read-only" `AUTOCHECKBOX` -> Fluent pill toggle matching the
  TPM pill (`.rc` LTEXT + `BS_OWNERDRAW`; `theme_toggle(g_readonly)`; `up_ronly`
  flips + repaints; `gui_unlock` no longer reads a checkbox).
- **R7.4** standalone (dock-launched) pwgen action button reads **Copy** and copies to
  the clipboard with auto-clear; field-launched keeps **Use**.
- **R7.5** minimize/maximize/`IDC_V_LOCK`/hamburger `IDC_V_MENU` buttons removed; the
  caption keeps only Close (dock reflows left of it); Ctrl+L still locks (id/dispatch
  kept), X/Esc/idle lock to tray, and `IDC_T_SET` opens the settings overlay.

The clauses below are the original spec (kept for the on-screen review checklist).

1. **Remove the misplaced per-dialog theme cogwheel.** The id-990 `GLY_SETTINGS`
   "ghost-button foundation demo" that cycles the colour scheme (`unlock_proc`
   `up_init` → `up_cyclescheme`; check `create_proc`/`about_proc` for siblings) is
   out of place. Drop it — theme switching stays in the settings menu
   (`IDC_V_MTHEME`) and the title-bar dock settings button (`IDC_T_SET`). *Test:* no
   cogwheel on the unlock/create/about dialogs; theme still switchable from settings.
2. **Ghost buttons must dim again on mouse-leave.** They currently keep the hover
   halo after the cursor leaves. Fix in `ghost_subclass` — the hover byte in
   `GWL_USERDATA` set by `gsc_move` should be cleared + repainted by the
   `WM_MOUSELEAVE` (`gsc_leave`) path; verify the `TrackMouseEvent`/`TME_LEAVE`
   arm actually fires and re-arms (check `TRACKMOUSEEVENT.cbSize`/struct and the
   "already hovering → skip" guard so a missed leave can't stick). *Test:* hover
   then leave every ghost button (dock + converted toolbar) → halo fades.
3. **Read-only checkbox → Fluent toggle.** Convert the unlock dialog's `IDC_U_RONLY`
   "Open read-only" checkbox to a Fluent pill toggle matching the existing
   `IDC_V_MTPM` toggle (`vp_tdraw_toggle` painter), for style consistency. *Test:*
   the toggle reads/writes `g_readonly`; looks like the TPM pill.
4. **Standalone pwgen: "Use" → "Copy".** When the generator is opened standalone
   from the title-bar dock (`vp_gen_standalone`, `g_pg_target == -1`) rather than
   from a secret's field (`vpd_gen`), the action button should read **Copy** and put
   the generated password on the clipboard (existing clip path + auto-clear timer)
   instead of writing to `g_pg_target`. *Test:* dock-launched pwgen shows Copy →
   clipboard gets the password; field-launched still shows Use → writes the field.
5. **Remove the minimize / maximize / lock / burger buttons.** Drop:
   - the `IDC_T_MIN` and `IDC_T_MAX` caption buttons (+ `gt_min`/`gt_max` strings,
     anchors, handlers) — no need to minimise/maximise;
   - the `IDC_V_LOCK` button — redundant because `vp_close` (the `IDC_T_CLOSE`
     "X"), `vp_esc` (Escape), and the idle-timeout all already fall through to
     `vp_lock`, which wipes and hides to tray; so the X and Escape lock to tray;
   - the **hamburger menu** `IDC_V_MENU` (`GLY_MORE`, `wb_menu`/`wb_close` toggle)
     — redundant now that the title-bar dock settings glyph `IDC_T_SET` opens the
     same overlay (both route to `vp_menu` → `gui_menu_toggle`). Keep `IDC_T_SET`
     as the toggle; the overlay still closes via re-click / Esc.
   Reflow the caption/toolbar to drop the removed slots. *Test:* only the close
   glyph in the caption and the dock's New/Generate/Settings/search remain; Esc and
   X lock (wipe) + hide to tray; the settings glyph opens/closes the overlay.

### R8. Search overhaul — one title-bar search (2026-07-21, in progress)
Consolidate to a single search driven from the title bar; the sidebar filter box
is gone. Built on the existing `search_overlay_*` (panel/edit/list) infrastructure.
1. **[done, stage 1]** Remove the redundant sidebar box (`IDC_V_SEARCH`); the list
   reflows to fill it. Ctrl+K, list type-to-search (`search_type_subclass`) and
   ghost-button type-to-search (`gsc_char`) now open the overlay and forward the
   keystroke into `IDC_SO_EDIT`. *Verify on screen:* list fills the space; typing
   anywhere with no field focused opens the overlay and starts the query.
2. **Type-anywhere focus:** ensure *every* no-field-focused keypress reaches the
   overlay (extend beyond the list/ghost subclasses if any control swallows it).
3. **Edit painted over the pill:** position `IDC_SO_EDIT` over the `IDC_T_SEARCH`
   rect (not below) so activating looks like the pill becomes the field.
4. **Floating results window:** promote the results panel from a child control to a
   top-level layered popup (`WS_POPUP` + drop-shadow / `WS_EX_NOACTIVATE`) that
   floats over the window with a border + shadow. Subsumes the edit-over-pill
   positioning (3) and dynamic sizing (6).
5. **Linger until selection:** keep the results open until Enter/click/Esc (already
   the behaviour — confirm no close-on-blur once it is a popup).
6. **[done, stage 2]** Scale with hits: `search_overlay_resize` sizes the list +
   backdrop to `clamp(rows × itemHeight, one row, SO_LISTH)` after every populate,
   so the dropdown shrinks live as the query filters. Carries over to the popup.
*Sequence:* stages 1–2 done → 2b (type-anywhere completeness) → 4+3 (the
floating-popup rebuild, reuses the stage-2 sizing) → 5 (confirm). All visual —
each increment verified by screenshot.

---

*Completed plans are removed from this file in the commit that ships them.
Plans verified against master (post-merge 8e893a0) on 2026-07-18; if something
here is already done, delete it — the file was wrong, not the code.*
