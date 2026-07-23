# M1 — System items + pinned vault ID/name — design proposal

**Status: PROPOSAL (2026-07-23). Needs your sign-off on §7 before any code lands.**

M1 is flagged in the plan as "a core on-disk-format change, do with review." This is
that review. It proposes a concrete, low-risk encoding, isolates the one genuinely
hard problem (`vault_count`), and splits the work so the whole cryptographic/format
core lands **headless + KAT-gated** before the small display-gated hookup.

---

## 1. Goal

Give every real vault two pieces of self-knowledge that travel *inside* the encrypted
file:

1. **A pinned 16-byte vault ID** — random at creation, **immutable across password or
   salt rotation**. The machine-local federation keyring (M2) keys foreign vaults by
   it, so it must not change when a user changes their master password.
2. **A vault name** — user-editable, stored in the file, so the vault knows its own
   name on any machine (today the name is only guessed from the file's basename or
   cached in the federation record).

Both live in a new **system item**: a hidden entry the list builder excludes from the
user's list. The same mechanism is the general extension slot for future per-vault
settings (auto-lock, default-read-only, icon…), each a new `VF_SYS_*` field.

## 2. Why the current `vault_id_of` isn't enough

Today `vault_id_of()` = `SHA-256(header salt)[0..15]` (vault.asm). It works and needs
no format change, but it is **derived from the salt** — so if a "change master
password" ever re-salts the file, the vault's identity changes and the federation
keyring loses track of it. A pinned, body-resident ID is stable by construction. The
existing code comment already says the salt form "supersedes … once system items land."

## 3. Encoding (the on-disk part)

The body already stores, per entry:
`id16 | created:u64 | modified:u64 | field_count:u32 | fields{ u16 type, u32 len, bytes }`
(vault.asm header comment). A **system item is just an ordinary entry** whose fields
carry `VF_SYS_*` markers — so it rides the existing container, is authenticated +
encrypted like any entry, and needs **no new parser**.

New field kinds (macros.inc, in the free `VF_KINDMASK` space above the current max of
16; `VF_LABELED`=0x8000 is unaffected):

| kind | value | meaning |
|---|---|---|
| `VF_SYSTEM`   | 17 | **marker**: an entry whose *first* field is `VF_SYSTEM` is a system item. Value = 1 byte schema-version (=1). |
| `VF_SYS_ID`   | 18 | 16 random bytes — the pinned `vault_id`. |
| `VF_SYS_NAME` | 19 | UTF-8 vault name. |
| *(reserved)*  | 20+ | future per-vault settings, each a `VF_SYS_*` field. |

A reader identifies a system item by "field[0].kind == `VF_SYSTEM`". Unknown future
`VF_SYS_*` fields round-trip untouched (forward-compat). The system item is created
first at vault creation, so it is naturally **entry index 0**; the exclusion logic
below does not *depend* on that (it checks the marker), but it keeps things tidy.

**Format-version impact:** this is an **in-body field addition** (new `VF_*` tags),
not a change to the container layout or the authentication trailer. Per the plan's
Format note, that follows the tolerant pattern and **does not require a
`VAULT_VERSION` bump**. (Option to bump to v3 as a clean-break marker is in §7.)

## 4. The one hard problem: `vault_count`

A system item is a real entry, so `vault_count()` (which returns the raw
`entry_count` at `[g_body_ptr]`) would count it — every count-based probe and the GUI
list would see **N+1**. Mitigation, in two parts:

**(a) Test vaults stay minimal.** `do_seed` / `do_init` (the probe seed paths) do
**not** add a system item, so the entire existing probe suite (which asserts exact
physical counts, e.g. `mvrealremove` expects 3) is **untouched**. Only the real
creation path adds one (§5). The M1 KATs build their own system-item vaults.

**(b) A user-count that excludes system items.** Add:
- `vault_is_system(ecx=index) -> eax` — 1 iff that entry's first field is `VF_SYSTEM`.
- `vault_user_count() -> eax` — physical count minus system items.

`vault_count()` stays the **physical** count (used by seal/teardown/format code and by
the probes that assert physical counts). User-facing code switches to
`vault_user_count()`. The list builders (`xfill_into`/`list_fill_all`,
`poplist_into`) skip an entry when `vault_is_system` is true, but still tag each row
with its **physical** entry index (the `XR.xr_entry` the selection chokepoint already
carries) — so downstream edit/save/attachment paths need **no index remapping**, just
the skip. The M4 fedmgr per-vault count switches to `vault_user_count`.

## 5. `vault_id_of` becomes body-based, with a safe fallback

```
vault_id_of(rcx = out16):
    if a system item exists and has a VF_SYS_ID field:  out = that 16-byte id
    else:                                               out = SHA-256(salt)[0..15]   (unchanged)
```

This is **additive and low-risk**: real vaults created after M1 get the pinned id;
test-seed vaults and anything without a system item keep the salt form. It is now
**body-based** (needs the vault unlocked), which every runtime caller already
satisfies (`vault_ctx_is_dup`, `fed_remember_open` both run post-unlock). Blast
radius into the landed M2 keyring is small:
- `fed_store` keys the registry blob by a **fixed** value name (not a vault-id hash),
  so the registry key is unaffected.
- Federation links store `fl_id` computed by `vault_id_of` when the link is added;
  matching stays consistent as long as it's always computed the same way. ✔
- `cmd_idkat` gets a new assertion branch (pinned-id path + salt-fallback path).
- `mvr_rebuild` (test helper) keeps using the salt form for its `do_seed` vaults
  (which have no system item), so it stays consistent. ✔

## 6. Code changes (concrete)

**Headless core (this is the KAT-gated deliverable):**
1. `macros.inc`: `VF_SYSTEM`/`VF_SYS_ID`/`VF_SYS_NAME` kinds (+ reserved room).
2. `vault.asm`:
   - `vault_add_system_item(rcx = name wide)` — build a system-item entry
     (`VF_SYSTEM` marker + `VF_SYS_ID` = `rng_fill(16)` + `VF_SYS_NAME` = name),
     append it (reuses `va_field_labeled`/`va_field_bin_labeled`, like `do_attgen`).
   - `vault_is_system`, `vault_user_count`, `vault_sys_find() -> index/-1`,
     `vault_sys_id(rcx=out16) -> found`, `vault_sys_name(rcx=out, edx=cap) -> len`.
   - `vault_id_of` — the fallback logic in §5.
3. Wire the **real creation path** (`gui_create_do` / `go_create`) to call
   `vault_add_system_item` right after the body is initialised, before the first
   user entry — so it's entry 0.
4. New probe(s) in `vault.asm` + `main.asm` + gate (§8).

**Display-gated follow-up (small, needs a screen — lands after the core):**
5. The list builders skip system items; `vault_user_count` feeds the M4 fedmgr count
   and any "N items" display. Verified on-screen like the R group.

**M6 interaction (one decision, §7.5):** an export child is a *different* vault, so
`fed_export` should **not** copy the parent's system item; it mints a **fresh** one
(new random `vault_id`, and either the parent's name or a caller-supplied name).
`entry_copy_filtered`/`_full` already skip nothing special today — they'd copy the
parent's system item verbatim, which is wrong, so export must (a) filter out
`VF_SYS_*` fields / the system item and (b) add a fresh system item to the child.

## 7. Decisions I need from you

1. **Encoding** — separate `VF_SYS_ID`/`VF_SYS_NAME` fields (recommended: explicit,
   extensible) **vs** a single `VF_SYSTEM` field whose value is a packed blob.
2. **Vault ID source** — a dedicated `VF_SYS_ID` field of 16 random bytes
   (recommended: survives a system-item rebuild) **vs** reuse the system item's own
   16-byte *entry* id (lighter, one less field, but tied to that entry's identity).
3. **Test vaults** — keep `do_seed`/`do_init` system-item-free (recommended: zero
   ripple to the existing probe suite) **vs** add system items everywhere (ripples
   every count-based probe to N+1).
4. **`VAULT_VERSION`** — no bump (recommended: additive `VF_*` tags per the Format
   note) **vs** bump to v3 as a clean-break marker that rejects any pre-M1 vault.
5. **M6 export** — child vault gets a **fresh** system item (new id; recommended)
   **vs** carry the parent's id (would make the child a *duplicate* identity — not
   recommended).
6. **Scope split** — land the **headless core** (items 1–4 + KATs) now, and treat the
   **list-exclusion + M4 rename UI** as a separate display-gated change (recommended)
   **vs** hold M1 until both can ship together.

My recommendation is the first option on every line. With those, M1's core is a clean,
additive, fully-headless-KAT'd change that unblocks **M5** (rollback keyed by the
pinned id) and **`federatetest`** (which needs real system-item vaults).

## 8. Test plan (headless, gated)

- **`sysitemkat`** (new): create a vault with `vault_add_system_item("Acct")`, seal,
  reload → `vault_is_system(0)==1`; `vault_id_of` returns the pinned id;
  `vault_sys_name` == "Acct"; `vault_user_count` excludes it; a **second** vault has a
  **different** id; reseal is idempotent (id + name unchanged, `VF_SYS_*` fields
  round-trip). Fast KDF (m=8 KiB) like the other real-vault KATs.
- **`idkat`** extension: assert the pinned-id path *and* the salt-fallback path.
- **`federatetest`** (the M8 probe that's been waiting on M1): stand up a master +
  N foreign real vaults each with a system item, fan-out unlock, and assert the
  unified enumeration is the union with correct owner attribution **and** that no
  system item appears in the user set.

Everything above is provable headlessly; only §6.5 (the list painter + M4 rename)
needs a display.

## 9. Rollout

Pre-v1.0 clean slate ⇒ **no migration**: no code reads a pre-M1 vault expecting a
system item; `vault_id_of`'s salt fallback covers anything without one. Sequence:
core (§6.1–4) + KATs (§8) land build-green first → then M5 rides on the pinned id →
then the display-gated §6.5 + M4 rename get an on-screen pass.
