# Vordr — Improvement Roadmap

Planning notes written after landing image attachments. Ordered by value/risk.
Each item lists **why**, a concrete **approach**, and the **effort/risk** so work can
be picked up cold. Items marked ★ are the ones I'd do next.

---

## 0. Where the code stands

- Hybrid CLI+GUI, one hand-written MASM64 binary, no CRT, fail-closed, self-test
  every launch. Crypto: AES-256-GCM + Argon2id, KCV key-check, VirtualLock'd body.
- Records are modular TLV fields (labeled/ordered/repeatable): username, secret,
  url, notes, email/text, TOTP, and now **image**.
- **Attachments (new):** large blobs live in a separate section of the vault file,
  each AES-256-GCM'd under its own random key/nonce stored (encrypted) in the body
  as a 68-byte `AttachRef`. A 12-byte `VATT` trailer terminates the file, so an
  attachment-free vault is byte-identical to the old format (backward compatible).
- Images decode/draw via a thin GDI+ wrapper (`img.asm`); import from file or paste
  from the clipboard (DIB→PNG); click-to-enlarge viewer with export.

---

## 1. Attachment system follow-ups (highest leverage)

### 1.1 ★ Stream attachments on demand instead of holding the file resident
**Why:** today `vault_unlock` keeps the *entire* file image (`g_filebuf`) in memory
while unlocked so `attach_open` can read ciphertext by pointer. That defeats the
"unlimited size" goal — a 500 MB attachment means 500 MB resident, and the whole
file is read at unlock.
**Approach:** the pieces already exist. `fileio.asm` has `file_open_read`,
`file_read_at` (positioned exact read), `get_file_size`. Change unlock to:
(a) read only `[header][body_ct][tag]` to decrypt the body; (b) build `g_attidx` by
seeking the attachment section headers (`id16 || u64 ctlen`) via `file_read_at`,
recording each entry's **file offset** instead of a pointer; (c) keep the vault path
only. `attach_open` then opens the file, `file_read_at(offset, buf, ctlen+16)`,
GCM-opens, closes. `attach_build` (emit) streams existing entries old→new via
`file_read_at` + `file_write_all` rather than one giant `g_outbuf`.
This also lets `vault_seal_write` stop allocating a full-file buffer.
**Effort:** M–L. **Risk:** M (touches the crypto file paths — gate behind the KAT +
a headless file round-trip test, see 5.1).

### 1.2 Per-attachment size cap + total-vault budget
**Why:** no bound today; a huge paste/import can wedge the UI or bloat the file.
**Approach:** reject imports over a configurable cap (e.g. 25 MB/attachment,
250 MB/vault) with a Fluent message box; make caps policy-overridable via HKLM like
the password policy.
**Effort:** S. **Risk:** Low.

### 1.3 Optional downscale/recompress on import
**Why:** originals are stored verbatim (user's choice), but an opt-in "shrink large
images" toggle would keep vaults lean for the common ID-card/QR use case.
**Approach:** GDI+ has the pieces — `GdipGetImageThumbnail` or draw-to-bitmap at a
capped longest edge, then `GdipSaveImageToStream` (PNG/JPEG). Reuse the encoder path
already written for clipboard paste. Setting in the burger overlay.
**Effort:** M. **Risk:** Low.

### 1.4 Attachment de-duplication
**Why:** the same image pasted into two records stores two ciphertexts.
**Approach:** hash plaintext (BLAKE2b already in-tree); if an existing `AttachRef`
in the body has a matching content hash, share the id/key. Add a `sha`/`hash` field
to `AttachRef` (bump `ARF_SIZE`; the on-disk format already length-prefixes values).
**Effort:** M. **Risk:** Low–M (ref-counting on delete).

### 1.5 Garbage-collection audit
**Why:** on save, only attachments still referenced by a body `VF_IMAGE` field are
re-emitted, so deletes are GC'd — good. But verify orphaned pending buffers are
always freed on every exit path (`attach_reset` on lock covers it; double-check
error paths in `vault_seal_write`).
**Effort:** S. **Risk:** Low.

---

## 2. Security hardening

### 2.1 ★ Contain the image-parser attack surface
**Why:** GDI+/WIC decoders have a long CVE history; decoding an attacker-supplied
image is the riskiest new capability. The images are the user's own, but defense in
depth matters for a security tool.
**Approach:** (a) decode in a **separate low-integrity/AppContainer process** over a
pipe, returning only a pre-rendered bitmap — the crypto/keys never touch the parser.
(b) At minimum, `GdiplusStartupInput.SuppressExternalCodecs = TRUE` to block
third-party codec DLLs, and validate a magic-byte allowlist (PNG/JPEG/BMP/GIF)
before handing bytes to GDI+.
**Effort:** (a) L, (b) S. **Risk:** (a) higher complexity, (b) trivial — **do (b) now**.

### 2.2 Guarantee the VirtualLock working set
**Why:** `secmem_alloc` notes VirtualLock is best-effort; with the body cap now
16 MiB the lock may silently fail, and decrypted secrets could hit the pagefile.
**Approach:** `SetProcessWorkingSetSize` (raise min) before locking; log/refuse if
the lock still fails and a "strict" policy is set.
**Effort:** S. **Risk:** Low.

### 2.3 Bind attachments to the vault identity
**Why:** an attacker who can write the file could splice an attachment section from
a *different* Vordr vault (they can't decrypt it, but could cause confusion).
**Approach:** extend each attachment's GCM AAD (currently `id || ptlen`) to include
the vault salt or KCV, so cross-vault splices fail authentication.
**Effort:** S. **Risk:** Low (format tweak; do before wide use).

### 2.4 Clipboard hygiene for images
**Why:** the existing auto-clear timer covers text copies; exported/enlarged images
don't touch the clipboard, but a future "copy image" would.
**Approach:** reuse the `g_clip_seq` clear pattern if image-copy is added.
**Effort:** S. **Risk:** Low.

### 2.5 Memory-safety sweep of the new hand-written code
**Why:** the attachment/GDI+ code added many raw pointer + length paths.
**Approach:** re-audit every `att_cpy`/`gui_bcpy` length against buffer bounds; the
software shadow stack + canaries already catch control-flow/overflow at runtime, but
a static pass over `attach_build`, `attach_open`, `img_encode_hbitmap` is warranted.
Consider a fuzz harness feeding malformed attachment sections to `attach_index_build`.
**Effort:** M. **Risk:** — (it *reduces* risk).

---

## 3. Features

- **Drag-and-drop image import** (WM_DROPFILES) — natural complement to the picker.
- **Multiple images per record** already works (modular fields); add a gallery/strip
  layout when a record has several.
- **Generic file attachments** — DONE. `VF_FILE` stores any file as an encrypted
  attachment (own key/nonce, separate file section) + its filename; a row shows a
  shell thumbnail, the filename, and Open / Save (Export) / Choose. Preview uses
  `IShellItemImageFactory::GetImage` (Windows built-in), which renders a **PDF's
  first page** where a thumbnail provider exists, else the file-type icon.
  *Caveat / follow-up:* Open and preview decrypt to a `%TEMP%` file (the shell API
  is path-based). Preview deletes it immediately; **Open leaves plaintext in %TEMP%
  until the OS cleans it** — the app the user opens holds it. Follow-ups: shred the
  temp on lock, or use a per-session RAM disk / restricted-ACL temp dir; render PDF
  in-memory via `Windows.Data.Pdf` (WinRT) to avoid the temp entirely (hard from
  no-CRT MASM); larger enlarge preview (re-request the shell thumbnail at view size).
- **Password history** per secret (keep prior values, timestamped).
- **Vault-wide export/import** (encrypted backup, or plaintext export behind a scary
  confirm) and **merge**.
- **Auto-lock on idle / on screen-lock** (WTS session notifications).
- **Breach check** (k-anonymity HIBP range API) — but only with explicit opt-in and a
  clear network-egress disclosure, since the app is otherwise offline.

---

## 4. UX / GUI polish

- **Scrolling detail pane:** the field form is capped by height (Add-field disables
  when full). A real scroll (host rows in a child panel + WM_VSCROLL) removes the cap
  and helps image rows, which are tall. **★ worth doing** — it's the main layout debt.
- **Thumbnail affordance:** show a subtle "click to enlarge" hint and a hover border.
- **Progress/wait cursor** while decoding large images.
- **Keyboard:** Delete key on a focused row = remove; Ctrl+V on an image row = paste.
- **High-DPI:** verify DLU→pixel mapping and thumbnail crispness at 150/200% scale.
- **Viewer:** zoom/pan for large images; fit-vs-actual toggle.

---

## 5. Testing & tooling

### 5.1 ★ Headless attachment file round-trip KAT
**Why:** the current `attach_selftest` covers the *crypto* (seal→open + AAD binding)
but not the *file* path (`vault_seal_write` with a trailer → `vault_unlock` →
`attach_open`). That path is only exercised through the GUI, which can't be
self-tested.
**Approach:** a CLI-only test that creates a temp vault, injects a `VF_IMAGE` field
with a staged attachment, seals to disk, re-unlocks, and asserts the decrypted bytes
match. Gate CI on it. This de-risks 1.1 and any format change.
**Effort:** M. **Risk:** — (adds safety).

### 5.2 Fuzz `attach_index_build` / trailer detection with malformed files.
### 5.3 Golden-file compatibility test: an old (pre-attachment) vault still unlocks.
### 5.4 Wire a `bench` case for GCM throughput on multi-MB attachments.

---

## 6. Code health

- **Split `gui.asm`** (now ~3.9k lines). Carve out `gui_img.asm` (image row/viewer)
  and `gui_fields.asm` (row model) to keep files reviewable.
- **Frame-size discipline:** the owner-draw frame gotcha (frame ≥ deepest local +
  outgoing-arg area) bit us repeatedly. Add a short assertion macro or a comment
  convention that records each proc's outgoing-arg footprint.
- **Document the file format v2** in `docs/formats.md` (trailer + AttachRef layout).
  ★ do alongside 1.1 so on-disk docs don't drift.
- **Consistent error surfacing:** attachment import/open failures currently no-op
  silently; show a Fluent message so the user knows a paste/import didn't take.

---

## Suggested next sprint

1. `docs/formats.md` update for the attachment format (2.3 AAD tweak folded in).
2. Headless attachment file round-trip KAT (5.1).
3. Stream attachments on demand (1.1) — the flagship follow-up.
4. `SuppressExternalCodecs` + magic-byte allowlist (2.1b), per-attachment size cap (1.2).
5. Scrolling detail pane (4).
