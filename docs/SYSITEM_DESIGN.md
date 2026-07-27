# System items — implementation review

**Status: PROPOSAL (2026-07-26). Nothing has been written. Sign off on §7 first.**

Supersedes the system-item half of the deleted `docs/M1_DESIGN.md` (commit `8097fe0`,
2026-07-23), which was never implemented and whose motivation — a pinned vault ID for
the federation keyring — died with the multi-vault rip-out. What survives is the part
that is still wanted: **a place inside the encrypted body for permanent per-vault
metadata**.

---

## 1. Scope

**In:** one hidden entry per vault, holding vault-level settings as ordinary fields.
First customer is the **C9** master-password re-verify stamp (`pwverify`). The
mechanism is the deliverable; the stamp is the proof it works.

> **C9 — periodic master-password reminder (new ID, 2026-07-27).** Under TPM Unlock the
> master password is never typed, so it rots. C9 prompts for it every N days (HKCU
> `PwVerifyDays`, HKLM override, default 30, 0 = off).
>
> **Reminder only — no enforcement.** An earlier draft made it mandatory after a 3-day
> grace and dropped TPM enrolment on refusal. That was wrong: locking someone out of
> their own vault is the worst possible response to the very situation this exists to
> detect. If the password really has been forgotten, the useful move is to let them in
> and suggest exporting to a new vault while they still can. Dropping the enforcement
> also deleted the grace window (nothing left to escalate to), which took `VF_SYS_PWGRACE`,
> the anchor logic and the stateful query with it — `vault_pw_due` is now pure.
> Tag 19 is **retired, not free**: vaults created while that draft was live carry the
> field, and unknown tags are skipped, so it is harmless — but must never be reused.
> **Not C4.** C4 is complete and covers only the opt-in `TpmRequireHello` UI policy
> (`tpm_seal`/`tpm_unseal`). C9 is adjacent — same TPM-unlock area — but a separate
> item; the roadmap's house rule was that plan IDs are stable. C1–C8 are in use.
> Recorded here because `docs/IMPROVEMENT_PLANS.md` was deleted in `820ee24`, so
> there is no longer a roadmap to register an ID in.

**Out** (dead with federation, do not rebuild): pinned vault ID, vault name,
`vault_id_of` rework, export identity minting. If a vault name is ever wanted for
display, it slots in later as one more field — that is the point of the design.

## 2. Encoding

A system item is **an ordinary entry** whose *first field* is the `VF_SYSTEM` marker.
It rides the existing container: same GCM, same authentication, same body walk, and
`vault_body_validate` needs no change because a system item is a legal entry.

| kind | value | meaning |
|---|---|---|
| `VF_SYSTEM`     | 17 | marker. Must be field[0]. Value = 1 byte schema version (=1). |
| `VF_SYS_PWVERIFY` | 18 | u64 FILETIME, last master-password entry (C9). |
| *(reserved)*    | 19+ | future per-vault settings, one field each. |

Written raw (`VFL_RAW`), like `VF_PWHIST`. Unknown `VF_SYS_*` fields must
**round-trip untouched** so an older build never destroys a newer build's settings.

**No `VAULT_VERSION` bump.** Additive `VF_*` tags, and unknown tags are skipped by
readers — [`formats.md:95`](formats.md) records that this is exactly how
FAV/ICON/PWHIST/DELETED landed. A vault without a system item is not upgraded on read;
it gains one on the next save.

## 3. The real work: the exclusion surface

The old design called this "the list builders skip system items". It is bigger than
that. Today there are **25 `vault_count` call sites, 16 `vault_entry_ptr` call sites,
and 4 procs that read `entry_count` straight from `[g_body_ptr]`**. Every one has to
be classified, because the failure mode is silent: a missed site shows a phantom row,
an off-by-one count, or a system item exported in cleartext JSON.

`vault_count` stays the **physical** count. New: `vault_is_system(ecx=idx)`,
`vault_user_count()`, `vault_sys_find() -> idx/-1`.

**Corrected after reading every site (2026-07-27).** The table below originally listed
all 13 as "must exclude". That was derived from the grep, not from the code, and it was
wrong: most of those `vault_count` calls bound a loop that *indexes* entries, or guard a
**physical** index handed back by the listbox. Switching those to `vault_user_count`
would have introduced the exact off-by-one the design exists to prevent. Only 5 sites
actually needed a change.

**Changed:**

| site | proc | fix |
|---|---|---|
| `gui.asm:2047` | `poplist_into` | skip in the fill loop; bound + item data stay physical |
| `gui.asm:5443` | `gui_commit` | `vault_last_user()` instead of `count-1` |
| `gui.asm:11620` | `vault_proc` (post-add) | same |
| `zipexport.asm:587` | `ze_build_json` | skip, **whatever the selection says** |
| `zipexport.asm:883` | `ze_add_attachments` | skip (defensive; none carried today) |
| `vault.asm:4053` | `vault_health` | reported total from `vault_user_count`; loop skips |

**Deliberately unchanged — physical is correct:**

| site | why |
|---|---|
| `gui.asm:4279` `gui_lb_seldata` | guards a **physical** index from `LB_GETITEMDATA` |
| `gui.asm:4341` `gui_copy_topmost` | same; and the list never shows a system row |
| `gui.asm:5500` `gui_check_refresh` | liveness probe: 0 = locked/closed |
| `gui.asm:9764` `gui_purge_trash` | purges only entries carrying `VF_DELETED`, which a system item never has — the "could purge it" claim was wrong |
| `gui.asm:9869` `gui_first_deleted` | same `VF_DELETED` gate; returns a physical index |
| `gui.asm:12968` `gui_export` | sizes the selection array, which is indexed physically |

**~~Known cosmetic gap~~ — closed 2026-07-27, and the note above was stale.** This section
claimed the export checklist would still show a blank row for the system item because
`gui_sel_count` returns the physical count. That caveat was written *before* the row
filter existed and never revised: `gui_sel_exportable` skips system items and trashed
records in the checklist's own loop, and `gui_sel_all` ticks only what the list shows.

`gui_sel_count` returning the PHYSICAL count is correct and must stay that way — it is
the loop bound, and the loop indexes entries. The skip is what hides the row; the count
never needed changing. Making it a user count would have reintroduced the off-by-one this
whole design exists to avoid.

**`vault_last_user()`** exists because `count-1` ("the entry just written") is only safe
while the system item is not last. It is last on any vault that gained one on a later
save, which is every pre-existing vault.

**Must stay physical (do not touch):** `vault_body_validate` (1771),
`vault_entry_ptr` (3791), `attach_build` (5088), `fed_export`/`fed_merge` (3612/3720),
and every probe (`cmd_vfuzz`, `cmd_vaultexportkat`, `cmd_vaultexpattkat`,
`cmd_reload`, `zi_att_verify`).

`gui.asm:11346` (list-size debounce threshold) is cosmetic — N+1 is harmless, leave it.

**Index discipline.** List rows keep carrying the **physical** entry index
(`XR.xr_entry`), so no downstream edit/save/attachment path needs remapping — the
builders only *skip*. This is the single most important invariant; breaking it turns
every `vault_entry_ptr` caller into a bug.

**M6 — done 2026-07-27.** Both directions filter, via the pointer-based
`sys_first_kind` rather than `vault_is_system`: these loops walk a **foreign** body, and
`vault_is_system` indexes the live `g_body_ptr`, so it would test the wrong vault.

- `fed_export` skips the parent's system item. A child is a different vault; inheriting
  the stamp would start its clock pre-verified.
- `fed_merge` skips a foreign one. Dedup is by **entry id**, so a foreign system item
  would not collide with ours — it would land as a *second* system item, and
  `vault_sys_find` returns the first, silently shadowing this vault's own stamp.

Both covered by `sysitemkat` and negative-tested (disable either filter and it exits 1).
The merge case deliberately flips a byte of the snapshot's entry id: merging a body into
itself proves nothing, because dedup would skip the item as "not newer" whether or not
the filter exists.

## 3b. Creation — wired 2026-07-27

Two paths, deliberately different:

- **New vault:** `gui_create_do` adds the item right after the first `vault_unlock`
  and reseals, so it is entry 0 and every later record sits after it. This is the real
  creation path only — `do_init`/`do_seed` stay system-item-free (§4).
- **Existing vault: no migration.** Opening an old vault does **not** rewrite it.
  `vault_pwverify_set` creates the item **on demand**, the first time there is actually
  a setting to store, riding a save the caller was making anyway. Migrating on unlock
  would mean a silent write to every existing vault the first time it is opened, for no
  benefit — and would be impossible on a read-only vault, which can never persist one.

The consequence to remember: on a migrated vault the system item is **last**, not first.
That is exactly what `vault_last_user()` (§3) exists for.

## 4. Probe suite: keep test vaults system-item-free

`do_seed` / `do_init` must **not** create a system item, so every existing probe that
asserts a physical count is untouched. Only the real GUI creation path adds one. The
new KAT builds its own.

## 5. Interaction with the work already in the tree

The uncommitted change puts `pwverify` in a v2.1 file-MAC trailer
(`[u64 counter][u64 pwverify][u32 "VMA2"][32 MAC]`). It is built and gate-green, but it
is a **second mechanism for the same job**.

**Recommendation: revert it** (`git checkout -- src/vault.asm`) and carry the stamp in
the system item. One mechanism for vault-level metadata, not two. The trailer work is
worth ~90 lines and is fully recoverable from this document if we ever want it back.

Honest trade: for *one u64* the trailer is genuinely simpler — no exclusion surface at
all. The system item only wins once there is a second setting. If per-vault settings
are not actually coming, keeping the trailer and dropping this proposal is the smaller,
safer change.

## 6. Test plan (headless, gated)

- **`sysitemkat`** (new): create a vault with a system item; seal; reload →
  `vault_is_system(0)==1`, `vault_user_count()` excludes it, `vault_count()` includes
  it; the `pwverify` field round-trips a known FILETIME; reseal is idempotent; an
  unknown `VF_SYS_*` field planted by hand survives a save/reload untouched.
- **Exclusion assertions:** a vault with 3 user entries + 1 system item must report
  `vault_user_count()==3`, must export exactly 3 records to JSON, and `vault_health`
  totals must read 3.
- **Purge safety:** `gui_purge_trash` over a vault whose system item is present must
  leave it in place.
- **M6:** export a child from a parent that has a system item → child has its own (or
  none), never the parent's.

## 7. Decisions needed

1. **Go / no-go on the mechanism itself** — build system items, or keep the trailer and
   drop this? (§5 is the honest cost comparison.)
2. **Schema-version byte in `VF_SYSTEM`** — include it (recommended: cheap, and the one
   thing that is painful to add later) or omit?
3. **Unknown-field round-trip** — required (recommended) or may a save drop
   `VF_SYS_*` fields it does not recognise?
4. **Creation-path only** — confirm `do_seed`/`do_init` stay system-item-free (§4).
5. **Scope split** — land headless core + `sysitemkat` first, then the GUI exclusion
   sites as a separate on-screen-verified change (recommended), or both together?

## 8. Risk

The mechanism is additive and cheap. **The exclusion surface is the risk** — 13 sites,
each failing silently and differently, and two of them (`gui_purge_trash`,
`ze_build_json`) fail in ways that lose or leak data rather than just looking wrong.
That is what §6's assertions exist to pin down, and why §7.5 proposes landing the
headless core before any of it is wired to a screen.
