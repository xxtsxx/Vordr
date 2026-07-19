# Vordr 2.0 — GUI + functionality redesign plan

A complete, phased plan for redesigning Vordr's shell (title bar, tabs,
search), its vault-IO model (multi-vault, read-only-by-default, lock/retry
semantics), and its details pane (modular, dynamic, responsive). Written
against the codebase at `audit-cleanup` (e0e6972). Every step names the files
it touches, the procs/data it adds, and a concrete verification test.

Conventions used below:

- **BUILD** = `build.cmd strict` → `BUILD OK` + framecheck 0 fatal + deadcode 0 dead.
- **RUNALL** = `tests\run_all.cmd --quick` → ALL STAGES PASSED.
- **SMOKE** = Start-Process `bin\vordr.exe`, still alive after 3 s.
- **GUI-V** = manual (or computer-use) visual verification against a test vault.
- All new code follows the house rules: FRAME_PROLOG with 32-byte shadow +
  8-byte-per-local slots, WINCALL args 5+ never passed in volatile regs,
  MASM hex with trailing `h`, WSTR strings without commas/apostrophes,
  every dialog proc that is raw (`sub rsp,64`) delegates >4-arg WINCALLs to
  FRAME_PROLOG helpers.

---

## 0. Where we are (survey)

| Area | Today | Redesign target |
|---|---|---|
| Window | `DLG_VAULT` fixed 484×350 DLU, `WS_POPUP\|WS_CAPTION\|WS_SYSMENU`, OS title bar | Borderless custom-frame window: title bar owned by us (search + dock + tabs), resizable, responsive |
| Search | `IDC_V_SEARCH` edit pinned under the sidebar list | VS-Code-style title-bar search control opening a blended overlay ("quick pick") searching **all** open vaults |
| Vault state | ~36 process globals in `vault.asm` (g_vkey, g_filebuf, g_hdr, g_attidx…) — exactly one vault | `VAULTCTX` struct array (up to 8), every vault.asm proc takes rcx=ctx |
| File IO | Open→read→close per load; save = atomic tmp+ReplaceFileW (holds no standing handle today — good baseline) | Formalize read-only-by-default contract; save takes the write lock only for the save; 1 s × 10 retry on sharing violations; per-vault availability state machine |
| Details pane | Fixed header (icon/title/fav/ovfl) + stacked field rows, hard bottom (no scroll), fixed widths | Modular block list (fields + **spacers** + **group headers**), scrollable, reflowing with window width; heading = glyph+title+username + command dock |
| Buttons | Owner-draw framed buttons (`theme_drawitem`) | Glyph-only "ghost" buttons: bare Fluent/Symbol glyph, hover = subtle bg, tooltip |
| Sidebar | LISTBOX owner-draw (virtualized) | Kept, restyled; gains a tab strip above it (per-vault + All-results tab) |

Assets already in the tree that the redesign reuses:

- `theme.asm` scheme engine (`g_col_*`, `scheme_traits`, `theme_dwm_apply`,
  `theme_scrollbars`), owner-draw menu machinery (`gui_menu_*`),
  `g_font_icon` (Segoe Fluent Icons) + `g_font_sym` (Segoe UI Symbol) fonts.
- The **reverted virtual-scroll work is recoverable from the reflog**
  (`18c747e` gui: virtual-scroll the detail field list, `b47fd3b` drop the
  room cap). Phase D resurrects and adapts it rather than rewriting.
- Trash view, password history, TOTP, attachments-as-tags, drag-drop,
  fuzzy search scoring (`fuzzy_score`), settings overlay — all carried over.

---

## 1. Design language (applies to every phase)

### 1.1 Glyph inventory — always from a font, never bitmaps

Primary font: **Segoe Fluent Icons** (`g_font_icon`, Win11; fallback probe
"Segoe MDL2 Assets" on Win10 — same codepoints for everything used here).
Secondary: **Segoe UI Symbol** (`g_font_sym`) only for glyphs Fluent lacks
(e.g. ♻ U+267B already in use for restore).

| Control | Glyph | Codepoint |
|---|---|---|
| Search (title bar) | Search | `E721h` |
| New item (dock) | Add | `E710h` |
| Generate password (dock) | Permissions/key | `E8D7h` |
| Settings (dock) | Settings | `E713h` |
| Edit (header dock) | Edit | `E70Fh` |
| Favorite off/on | FavoriteStar / StarFill | `E734h` / `E735h` |
| More (ellipsis) | More | `E712h` |
| Copy password / username | Copy | `E8C8h` |
| Phonetic reader | Read aloud (speaker) | `E995h` |
| Show history | History | `E81Ch` |
| Delete secret | Delete | `E74Dh` |
| Tab close | ChromeClose | `E8BBh` |
| Vault (tab icon) | Lock | `E72Eh` |
| All-results tab | SearchAndApps | `E773h` |
| Reveal / conceal | View / Hide | `E890h` / `ED1Ah` |
| Spacer / group (palette) | Remove / GroupList | `E738h` / `F168h` |
| Window min/max/restore/close | ChromeMinimize/Maximize/Restore/Close | `E921h/E922h/E923h/E8BBh` |
| Warning (vault unavailable) | Warning | `E7BAh` |

Rule: any new glyph must be added to this table (single source of truth,
mirrored as `equ GLY_*` constants in a new `src/glyphs.inc`).

### 1.2 Ghost buttons (glyph-only, hover halo, tooltip)

New shared control style replacing framed owner-draw buttons everywhere the
redesign touches (title bar dock, header dock, per-row buttons):

- **Data:** per-button state packed in `GWL_USERDATA`: byte0 = style
  (2 = ghost), byte1 = hover flag, word2 = glyph codepoint. Helper
  `ghost_make(rcx=parent, edx=id, r8d=glyph, r9=tooltip wstr)` creates a
  `BS_OWNERDRAW` button, stores state, registers the tooltip.
- **Painter:** extend `theme_drawitem` with a `tdi_ghost` branch:
  - background: parent bg normally; on hover fill a rounded 4-px-radius
    rect with `g_col_hover` (new per-scheme colour = bg ±8% luma, computed
    once per scheme switch next to the existing derived colours);
    on ODS_SELECTED darken a further step.
  - glyph: `g_font_icon` (or `g_font_sym` when codepoint < `E000h`),
    `g_col_text`, `DT_CENTER or DT_VCENTER or DT_SINGLELINE`.
- **Hover tracking:** ghost buttons are plain BUTTONs, so hover comes from
  `WM_MOUSEMOVE` seen by a subclass proc `ghost_subclass` (SetWindowSubclass
  via comctl32, already linked) that calls `TrackMouseEvent(TME_LEAVE)`,
  flips the hover bit, and invalidates. WM_MOUSELEAVE clears it.
- **Tooltips:** one shared `TOOLTIPS_CLASS` window per top-level
  (`g_tooltip`), `InitCommonControlsEx(ICC_BAR_CLASSES)`; `ghost_make`
  adds a TTTOOLINFOW per button (`TTF_IDISHWND or TTF_SUBCLASS`). Tooltip
  colours via `TTM_SETTIPBKCOLOR/TEXTCOLOR` from the scheme; re-issued by
  `gui_apply_scheme`.
- Files: `src/theme.asm` (painter + hover colour), `src/gui.asm`
  (`ghost_make`, `ghost_subclass`, tooltip singleton), `src/glyphs.inc`.
- *Test:* dbg verb `ghostlab` opens a scratch dialog with 6 ghost buttons;
  visual: bare glyphs, hover halo follows mouse, tooltips appear after
  ~400 ms, all 9 schemes readable. BUILD + SMOKE.

### 1.3 Layout engine (kill the fixed DLU tables)

Today every x/y/w/h is a hard-coded DLU. The redesign introduces one
client-rect-driven layout pass:

- `layout_root(rcx=hwnd)` — computes, in **pixels** from `GetClientRect` +
  `GetDpiForWindow`:
  - `LAY_TITLEBAR` (top strip, height 40 px @96dpi, scaled),
  - `LAY_TABS` (28 px, only when >1 vault),
  - `LAY_SIDEBAR` (fixed 260 px, but ≤ 38% of client width; hidden below
    the S breakpoint),
  - `LAY_DETAIL` (remainder).
  Results stored in a `g_lay` RECT table; every child is positioned from
  it (MoveWindow, no MapDialogRect on the redesigned surfaces).
- Breakpoints: **S** < 560 px client width → sidebar becomes an overlay
  (slides over the detail pane, toggled by a hamburger ghost button);
  **M** 560–900 px → sidebar 220 px; **L** > 900 px → sidebar 260 px and
  detail-pane blocks get two-column flow (label left, value right, as now,
  but value width = pane width − 190 px, elastic).
- Called from `WM_SIZE`, `WM_DPICHANGED`, scheme/density switches.
- *Test:* resize 500→2500 px wide: no overlapped/clipped controls at any
  width (scripted `MoveWindow` sweep via a dbg verb + screenshots at
  S/M/L). BUILD + GUI-V.

---

## 2. Phase A — the shell: custom frame, title-bar search, control dock

### A1. Borderless custom frame

Convert the vault window from a captioned dialog to a custom-frame window
(VS Code style — content owns the title bar):

1. Keep it a dialog (message routing unchanged) but style
   `WS_POPUP or WS_THICKFRAME or WS_SYSMENU or WS_MINIMIZEBOX or
   WS_MAXIMIZEBOX` and **no** `WS_CAPTION`.
2. `WM_NCCALCSIZE` (wParam=1): return 0 after shrinking only the top by 0
   — i.e. client area covers the whole window except the OS-drawn resize
   borders; DWM shadow retained via
   `DwmExtendFrameIntoClientArea{0,0,1,0}` + existing `theme_dwm_apply`
   (dark caption attrs become irrelevant but harmless).
3. `WM_NCHITTEST` proc `frame_hittest`:
   - within 6 px of edges → HTLEFT/…/HTBOTTOMRIGHT (resize),
   - inside the title-bar strip and not over an interactive child →
     HTCAPTION (drag),
   - over our min/max/close ghost buttons → HTMINBUTTON/HTMAXBUTTON/
     HTCLOSE (gives the Win11 snap flyout on hover for free),
   - else HTCLIENT.
4. Caption buttons: three ghost buttons (1.1 glyphs) right-aligned in the
   title bar; close hover uses the standard red (`C42B1Ch`) regardless of
   scheme.
5. `WM_GETMINMAXINFO`: min track size 480×360 px scaled by DPI.
6. Persist placement: `WINDOWPLACEMENT` → HKCU `WinPlace` (REG_BINARY) on
   close; restore clamped to the nearest monitor
   (`MonitorFromRect(MONITOR_DEFAULTTONEAREST)`).
- Files: `src/gui.asm` (vault_proc additions live in FRAME_PROLOG helpers
  `frame_hittest`, `frame_nccalc`, `caption_build`), `vordr.rc` (style
  change only — controls are runtime-created from here on).
- *Test:* drag by the empty title area moves; edges resize; double-click
  title maximizes; Win11 snap flyout appears over the max button;
  Alt+F4 / close glyph both exit through the existing WM_CLOSE path
  (wipe + tray rules intact). RUNALL + GUI-V.

### A2. Title-bar search control (VS Code style)

1. **The control:** a ghost *composite* — a rounded rect (panel colour,
   1-px `g_col_border`) centered in the title bar, max 480 px wide,
   containing glyph `E721h` + dim text `Search all vaults (Ctrl+K)`.
   Owner-draw STATIC `IDC_T_SEARCH`; click (or Ctrl+K / Ctrl+F) opens the
   overlay.
2. **The overlay** (`search_overlay_open`): a borderless `WS_POPUP` themed
   window (per-pixel border like the owner-draw menus, `DLGC`-free),
   positioned directly under the search control, same width, containing:
   - a real EDIT (`IDC_SO_EDIT`, themed, no border) with the query,
   - an owner-draw results LISTBOX (`IDC_SO_LIST`,
     LBS_OWNERDRAWFIXED, max 10 rows) painted like sidebar tiles
     plus a right-aligned dim vault name per row.
   Blend rules: same bg as the main window (`g_col_bg`), 8-px corner
   radius via `SetWindowRgn`/DWM round corners, drop shadow via
   `CS_DROPSHADOW`. **It must look like part of the page** — no caption,
   no frame, aligned flush to the search control's rect.
3. **Behaviour:** live re-query on EN_CHANGE (fuzzy_score across vaults —
   Phase C wires the multi-vault part; until then the single open vault);
   ↑/↓ move selection, Enter activates (switch tab + select entry +
   close), Esc / focus-loss (`WM_ACTIVATE` inactive) closes. The overlay
   never takes activation from typing: opened with
   `SetForegroundWindow` + caret in the edit.
4. **Type-to-search:** in vault_proc's message path add
   `WM_CHAR`/`WM_KEYDOWN` fall-through: if the char is printable and
   `GetFocus()` is not an EDIT (walk `GetClassNameW`), open the overlay
   seeded with that character. Implemented as an `IsDialogMessage`
   pre-filter in the main message loop (`gui_msgfilter`) so it works
   regardless of which child has focus.
- Files: `src/gui.asm` (`search_ctl_paint`, `search_overlay_open/close`,
  `search_overlay_proc`, `gui_msgfilter`), `src/glyphs.inc`.
- *Test:* click and Ctrl+K both open the overlay flush under the control;
  typing `gmwk` with the sidebar focused opens it seeded with "g" and the
  Gmail-Work entry ranks first (fuzzy KAT `fztest` already covers the
  scorer); Esc closes and restores focus; overlay matches bg in all 9
  schemes (screenshot diff). BUILD + GUI-V.

### A3. Title-bar control dock

1. Left-to-right layout in the title bar: `[app icon] [tab strip →]
   … [search control centered] … [dock: New • Generate • Settings]
   [min][max][close]`.
2. Dock buttons are ghost buttons (1.2): New item `E710h` → existing
   add-entry flow; Generate `E8D7h` → existing pwgen dialog
   (standalone mode); Settings `E713h` → existing settings overlay.
   Tooltips: "New item (Ctrl+N)", "Password generator (Ctrl+G)",
   "Settings".
3. Retire the old sidebar `+`/`e`/`-` buttons and the bottom `+ Add field`
   relocation is Phase D (stays put until then). Keyboard: Ctrl+N, Ctrl+G
   accelerators via the msgfilter.
- Files: `src/gui.asm` (`caption_build` extends), `vordr.rc` cleanup.
- *Test:* all three fire their flows from every state (view/edit/trash);
  tooltips + hover halos correct; tab order reaches them (WS_TABSTOP);
  GUI-V + RUNALL.

---

## 3. Phase B — vault IO contract: read-only by default, polite writer

Today `vault_load` reads and closes; saves go through tmp+`ReplaceFileW`.
The contract is formalized and hardened:

### B1. Read-only open + snapshot semantics

1. All reads use `CreateFileW(GENERIC_READ, FILE_SHARE_READ or
   FILE_SHARE_WRITE or FILE_SHARE_DELETE, OPEN_EXISTING)` — never blocks
   other writers/synced copies. (Audit `fileio.asm read_file` — set the
   share mask explicitly; add `FILE_ATTRIBUTE_READONLY` tolerance.)
2. No standing handle is ever held between operations (already true —
   assert it: dbg verb `handleaudit` walks `NtQuerySystemInformation`?
   No — simpler: after unlock, `Restart-Computer`-free check that the
   vault file can be renamed by an external script while Vordr shows it).
- *Test:* while a vault is open, an external PowerShell renames the file
  and renames it back → both succeed (no lock held). RUNALL.

### B2. Save = short exclusive lock + retry 1 s × 10

1. `vault_save_locked(rcx=ctx)`: the existing atomic path, but the final
   `ReplaceFileW`/`MoveFileExW` step is wrapped in a retry loop:
   on `ERROR_SHARING_VIOLATION`/`ERROR_ACCESS_DENIED`/
   `ERROR_LOCK_VIOLATION`, `Sleep(1000)` and retry, ≤ 10 attempts. The
   tmp write happens **before** the loop (no lock needed — tmp is ours).
2. UI feedback: after attempt 3, the save button swaps to an hourglass
   glyph + tooltip "Waiting for the vault file…" (timer-driven, main
   thread — no worker threads; the shadow stack is process-global).
   Modal-less: the retry runs off a `WM_TIMER` state machine
   (`g_save_retry` countdown in the ctx), not a Sleep on the UI thread.
3. On exhaustion show the themed msgbox: **"Unable to write to the vault
   file - it is read-only or locked by another program."** with Retry /
   Save As… / Discard options (Save As routes through the existing
   export-path picker to write a copy).
4. `FILE_ATTRIBUTE_READONLY` on the target: detected up front → the same
   dialog immediately (no 10 s wait), message variant "the file is
   read-only."
- Files: `src/vault.asm` (`vault_replace_retry`), `src/gui.asm`
  (retry timer + dialog), `src/fileio.asm` (share-mode audit).
- *Test:* new probe verb `lktest <vault>`: child PowerShell holds the file
  open with no sharing for 4 s → save succeeds on ~5th retry; holds 15 s →
  error dialog path returns the documented code. Set +R attribute → the
  immediate read-only variant. RUNALL green.

### B3. Availability state machine (per vault)

States in ctx: `VA_OK`, `VA_RETRYING(n)`, `VA_GONE`.

1. Triggers: header re-verify fail (existing external-change hash),
   read errors, path unreachable (USB unplugged, share offline).
2. On failure: hide the vault's tab content (tab shows the `E7BAh`
   warning glyph + dim title, sidebar/detail replaced by a friendly
   "Vault unavailable — retrying…" panel), schedule `WM_TIMER` retries
   **3 × 5 s** (`VA_RETRYING 1→3`); each retry = full read-only reload +
   MAC verify with the still-held master key.
3. After the 3rd failure → `VA_GONE`: stop retrying, panel text becomes
   "Vault unavailable. It will be retried at the next unlock."; the tab
   stays (so the user can close it) but is inert. `VA_GONE` clears only
   on the next unlock cycle (lock → unlock), per the requirement.
4. Secrets hygiene: entering `VA_RETRYING` does **not** wipe the in-memory
   entries (the user may be mid-edit); entering `VA_GONE` wipes that ctx's
   decrypted material (`secure_zero`) and keeps only the path + name.
- Files: `src/gui.asm` (panel + timer), `src/vault.asm` (reload probe).
- *Test:* open a vault from a temp dir, rename the dir → warning tab
  within 5 s, three timed retries visible in `--trace` breadcrumbs,
  then GONE + wiped (dbg `secscan` on that ctx); restore the dir → still
  GONE (no retry) until lock/unlock → reloads fine. GUI-V + RUNALL.

---

## 4. Phase C — multi-vault: contexts, tabs, cross-vault search

The largest structural change. Split into strictly separable steps.

### C1. `VAULTCTX` — contextify vault.asm (no behaviour change)

1. Define `VAULTCTX` struct in `macros.inc` gathering the ~36 vault
   globals (from the survey: `g_vkey[32]`, `g_hdr`, `g_filebuf/size`,
   `g_body_ptr/len`, `g_save_counter`, `g_rollback`, `g_fmac_*`,
   `g_ext_*`, `g_attidx*/g_newatt*`, `g_att_*`, `g_tmppath`, `g_bak_*`,
   path, display name, availability state, save-retry counter, dirty
   flag). Size ~64 KiB → allocate via the existing `secmem_alloc`
   (VirtualLock'd) per open vault; `MAX_VAULTS equ 8`;
   `g_vaults dq 8 dup (?)`, `g_vault_cur dd` (active index),
   `g_vault_n dd`.
2. Mechanical refactor: every `vault.asm` proc gains `rcx=ctx` as arg 1
   (existing args shift right); every `[g_x]` becomes `[rcx+VC_X]` (or a
   saved-local ctx). **One commit per proc cluster** (load / save / attach
   / MAC / counter), each ending BUILD+RUNALL — the KATs and roundtrip
   verbs (`seedtest/zitest/vfuzz/bktest/mactest/rbtest/xctest`) are the
   safety net; point them at a stack-less default ctx
   (`g_vaults[0]`) so the CLI keeps working unchanged.
3. `gui.asm` callers pass `ctx = g_vaults[g_vault_cur]` through a tiny
   accessor `cur_ctx()` (rax return, leaf).
4. Registry mirrors become per-vault: the anti-rollback counter subkey is
   keyed by a BLAKE2b(path) hex prefix instead of the single value
   (`Rollback\<hash8>`); migration: read the legacy value into the first
   vault once, then write per-path.
- *Test:* full RUNALL after every cluster commit; final commit adds dbg
  verb `ctxdump` printing per-ctx offsets vs the struct (guards offset
  drift). Behaviour identical for a single vault.

### C2. Multi-unlock flow

1. Unlock dialog gains "Open additional vault…" (post-unlock: dock →
   Settings → Vaults section, plus Ctrl+O): file picker → per-vault
   secure-unlock password entry → `vault_load(ctxN)`.
2. Each vault keeps **its own master key** in its ctx (no cross-vault key
   reuse); locking (manual, idle, Win+L) locks **all** vaults at once —
   one wipe path that iterates `g_vaults[0..n-1]` (preserves today's
   single wipe guarantee; per-vault lock is out of scope v1).
3. MRU: HKCU `Vaults\MRU0..4` (paths only). Startup opens MRU0 as today;
   others reopen on demand (explicitly NOT auto-unlocked — each needs its
   password through secure unlock).
- *Test:* open 2 vaults; entries listed per tab (C3); lock wipes both
  (`secscan` extended to iterate ctxs); reopen both; RUNALL.

### C3. Tab strip

1. Owner-draw tab strip in the title-bar area (below the caption strip on
   S/M widths, inline left of the search control on L): one tab per open
   vault (lock glyph + display name, close ghost ×) + a leading
   **All-results tab** (`E773h`) that exists only while a cross-vault
   search is active.
2. Painter reuses the sidebar tile style (accent underline on the active
   tab, hover halo). Click switches `g_vault_cur` + repopulates
   sidebar/detail (all existing populate procs already read via
   `cur_ctx()` after C1). Middle-click / × closes (= locks + wipes that
   ctx only — the one exception to "lock everything", safe because it is
   an explicit close).
3. Ctrl+Tab / Ctrl+Shift+Tab cycle tabs; Ctrl+W closes the current tab
   (with the dirty-entry prompt).
- Files: `src/gui.asm` (`tabs_build/paint/hittest`), glyphs.
- *Test:* 3 vaults open → 3 tabs; switch preserves per-vault selection +
  scroll; close middle tab → indices stay coherent (ctx array compaction);
  dirty edit + close → Save/Discard/Cancel. GUI-V.

### C4. Cross-vault search + All-results tab

1. The search overlay (A2) queries every `VA_OK` ctx: for each, run the
   existing per-entry fuzzy scorer, tag hits with the ctx index; merge-sort
   by score into one list. Row paint: entry tile + right-aligned dim vault
   name.
2. Enter on a hit: activate that vault's tab, select the entry.
3. "Show all results" footer row in the overlay (or Enter on 0 selection)
   opens the **All-results tab**: sidebar shows the merged list grouped
   under per-vault group headers; the detail pane works read-only across
   vaults (edit jumps to the home tab first — keeps every mutation on its
   own ctx path).
- *Test:* same title in two vaults → both rows show with correct vault
  names; activation lands on the right ctx (planted distinct usernames);
  All-results tab groups correctly; searches with 0 hits show the empty
  state. GUI-V.

---

## 5. Phase D — the modular details pane

### D1. Heading redesign

1. Header block (fixed, above the scrolling field area): 48-px strip =
   entry glyph tile (existing icon system) + **title** (big font) +
   **username** underneath in `g_col_textdim` (first VF_USERNAME value;
   falls back to the first VF_TEXT labelled Email, else blank).
2. Right-aligned **command dock** of ghost buttons: Edit `E70Fh`,
   Favorite `E734h/E735h`, More `E712h`.
3. **Ellipsis menu** (reuses the themed owner-draw popup menu): Copy
   password `E8C8h`, Copy username `E8C8h`, Phonetic reader `E995h`,
   Show history `E81Ch`, separator, Delete secret `E74Dh` (danger row —
   red text). Each routes to the existing flows (`gui_copy_secret`,
   phonetic popup, DLG_PWHIST, delete-to-trash). Items grey out when the
   entry lacks the field.
4. The old IDC_V_HEADER/IDC_V_FAV/IDC_V_OVFL/IDC_V_TIMES controls are
   replaced by this block; the trash-mode recycle behaviour moves onto the
   Favorite slot exactly as today (glyph swap ♻).
- *Test:* every menu item fires its flow; entry without a password greys
  "Copy password"; Narrator reads button names (SetWindowTextW kept in
  sync with tooltips). GUI-V + RUNALL.

### D2. Block model: fields, spacers, groups

The pane becomes a list of **blocks**; a field row is one block kind.

1. **Format (TLV, backward compatible):** two new reserved labeled-field
   kinds inside the existing `VF_LABELED` scheme:
   - `VF_SPACER` — no value; renders as an 18-DLU gap.
   - `VF_GROUP` — value = group title; renders as a section header
     (dim caps text + hairline rule, like "Contact Information" in the
     Enpass reference).
   Old builds that don't know these kinds already skip unknown labeled
   fields gracefully (verify + KAT); no version bump needed, but add a
   `vfuzz` dictionary entry for both.
2. **Editing:** the `+ Add field` palette gains "Group heading" and
   "Spacer" entries; blocks participate in the existing chevron
   reorder + per-row delete exactly like fields (they live in
   `g_fields[]` with their own FD_KIND paint/measure branches — reuse
   the row infrastructure wholesale).
3. **View mode:** spacers/groups render but expose no buttons; group
   titles are skipped by copy/search.
- Files: `src/gui.asm` (row builder + painter branches), `src/vault.asm`
  (kind constants only), `docs/FORMAT.md`.
- *Test:* compose Login-style layout (fields, group "Contact
  Information", spacer, notes) → save → reopen → identical order;
  export/import `.vaultz` roundtrip preserves blocks; old-format vault
  still loads (version-gate test). RUNALL.

### D3. Scroll + responsiveness (resurrect the reverted work)

1. `git cherry-pick 18c747e b47fd3b` (both still in the reflog) onto the
   redesign branch — this restores `gui_row_height`, viewport clamping,
   `IDC_V_ROWSCROLL`, wheel + WM_VSCROLL handling, and the removal of the
   field-count room cap. Re-verify, then adapt:
2. Pixel-based viewport: the DLU constants (`ROW_TOP/ROW_VIEW_BOT`) become
   `g_lay.detail` rect values from the layout engine (1.3) so the visible
   row window grows with the window height — more rows visible on a tall
   monitor, scrollbar only when needed.
3. Elastic widths: value/label x/w computed from the detail rect
   (label column 170 px fixed, value = rest − button cluster) instead of
   DLU 176/196 constants.
4. Wheel scrolling accumulates `WHEEL_DELTA` fractions (precision
   touchpads), and PageUp/PageDown/Home/End work when the pane (not an
   edit) has focus.
- *Test:* 25-field entry on a 350-px-tall window scrolls smoothly and
  never paints over the header/buttons; maximized on 1440p shows ~20 rows
  and no scrollbar for a 15-field entry; RUNALL; the `lktest`-style GUI
  walk from the reverted-commit era repeated. GUI-V.

### D4. Templates hook (small, high leverage)

With blocks in place, the New-item flow becomes template-driven: Login /
Credit card / Identity / Server / Note tables in `.const` (list of
(kind, label) rows incl. groups + spacers, e.g. the Enpass-style Login =
Username, E-mail, Password, group "Contact Information", Website, Phone,
group "Totp", One-time code, Security question/answer, spacer, Notes,
Tags, Attachments). The dock's New button opens a small themed popup menu
of templates.
- *Test:* each template creates its block list; save/reopen preserves.

---

## 6. Phase E — proposed extras (recommended, each independently shippable)

1. **Command palette** (Ctrl+Shift+P): the A2 overlay in command mode
   (`>` prefix, like VS Code): Lock, Switch vault, New item, Export,
   Import, Settings, theme switching, Trash view. ~1 day on top of A2;
   makes every feature keyboard-reachable and doubles as the keyboard-nav
   safety net.
2. **Toasts**: layered themed child, auto-fade; "Copied — clears in 30 s",
   "Saved", "Vault locked". Replaces silent actions; queue ≤3.
3. **DPI audit**: the layout engine (1.3) already scales; sweep painters
   for hard px (underlines, chip radii) through a `dpi_scale` MulDiv
   helper; recreate fonts on `WM_DPICHANGED`.
4. **Keyboard navigation completion**: tab order through ghost docks,
   accelerator table (Ctrl+K/N/G/O/W/Tab, F2 edit, Del → trash), Esc
   closes overlay→edit→clears search in that order.
5. **Sidebar niceties**: per-vault entry counts on tabs; tag chips row
   under the search results (existing tag data); alphabet fast-scroll on
   >200 entries.
6. **Health indicators inline**: reuse strength grades to dot weak/reused
   entries in the sidebar (grey/amber/red 4-px dot on the tile) — cheap
   precursor to a health dashboard.
7. **Session restore**: reopen the same tab set (paths from MRU) at next
   unlock, each tab showing a locked placeholder until its password is
   supplied (click → secure unlock for that vault).
8. **`--ro` mode**: with B1 in place, a read-only launch flag is nearly
   free: hide Save/Edit docks, title suffix "(read-only)"; good for USB
   backups review.

---

## 7. Sequencing, branches, risk

### Order (each phase = its own branch, merged after RUNALL + GUI-V)

```
1.2 ghost buttons + 1.3 layout engine        (foundation, no visible change yet)
A1 custom frame  →  A3 dock  →  A2 search overlay + type-to-search
B1 → B2 → B3     (IO contract; independent of A, can run in parallel)
C1 (contextify — the long, mechanical one) → C2 → C3 → C4
D1 → D2 → D3 (cherry-pick) → D4
E-items opportunistically after their dependencies
```

Rationale: A gives the visible shell early; B is low-risk and de-risks C;
C1 is the schedule risk (touching every vault.asm proc) so it starts as
early as possible and lands in per-cluster commits; D depends only on the
layout engine + (for D3) the reflog commits, so it can interleave with C.

### Risk register (project-specific, from hard-won history)

| Risk | Mitigation |
|---|---|
| WINCALL rax/volatile-reg clobber when adding ctx args (the zipexport pwlen class) | args to locals first, never `eax` as arg 4 with `addr` as arg 5; framecheck on every commit |
| Raw dialog procs (`vault_proc` is `sub rsp,64`) + new >4-arg WINCALLs | all new handlers are FRAME_PROLOG helper procs, raw proc only dispatches |
| Process-global shadow stack = strictly single-threaded UI | every retry/timer design above is WM_TIMER state machines, zero worker threads |
| MASM local overlap (dword under qword footprint) | every new local gets its own 8-byte slot; the frame checker gates |
| Owner-draw dark gotchas (COMPOSITED, SS_WHITERECT, DM_SETDEFID dword LPARAM) | reuse the documented patterns from theme notes; new surfaces (overlay, tabs) reuse the menu/tile painters |
| Tray-launched windows not foreground | overlay + dialogs keep DS_SETFOREGROUND + SetForegroundWindow |
| C1 offset-drift bugs | `ctxdump` dbg verb + one-cluster-per-commit + full probe suite each commit |
| Custom frame breaks snap/accessibility | HTMAXBUTTON hit-test for snap flyout; keep real BUTTON hwnds + window text for MSAA |
| Format additions (VF_SPACER/GROUP) corrupt old readers | they ride the existing skip-unknown-labeled-kind path; version-gate test with a pre-change vault fixture committed to tests/ |

### Test additions to `run_all.cmd`

- `lktest` (B2 lock/retry), `ctxdump` sanity (C1), multi-ctx `secscan`
  (C2), block roundtrip in `seedtest` fixtures (D2), and a `layoutsweep`
  dbg verb driving WM_SIZE across widths asserting no control-rect
  intersections (1.3/D3) — the closest a headless gate can get to
  responsive-layout regression coverage.

### Rough effort (sessions, at this codebase's pace)

| Phase | Estimate |
|---|---|
| 1.2 + 1.3 foundations | 2 |
| A1–A3 shell | 3–4 |
| B1–B3 IO | 2 |
| C1 contextify | 4–6 (mechanical but wide) |
| C2–C4 tabs + search | 3 |
| D1–D4 details pane | 3–4 |
| E extras | 1 each |

---

## 8. Out of scope (explicitly)

- True multi-threading (parallel unlock, background IO) — blocked on the
  per-thread shadow-stack redesign documented in the Plan-34 post-mortem;
  nothing in this redesign requires it.
- Per-vault independent locking (v1 locks all vaults together, except
  explicit tab close).
- Browser extension / auto-type — separate initiative.
- Localization — the string table keeps growing in-place; the catalog
  indirection remains a later data-only change.
