# Settings screen — why it keeps breaking, and how to get out

**Status: ACCEPTED — option C, staged. Stage (i) landed 2026-07-28; (ii) and (iii) open.**
See §7 for what stage (i) actually cost.

## 1. What it is today

The settings screen is not a window. It is a **simulated** one: a full-size owner-draw
backdrop (`IDC_V_MBACK`, `0,0,484,350`) plus ~34 controls that live inside `DLG_VAULT`
alongside the vault's own controls, with visibility flipped by hand.

The machinery that keeps the illusion up:

| piece | what it is | what it costs |
|---|---|---|
| `g_menu_ids` + `MENU_ID_COUNT` (35) | hand-maintained id array | every new setting must be added, and the count bumped |
| `g_vault_ids` + `VAULT_ID_COUNT` (14) | the other half of the partition | a control in neither array is never hidden |
| `g_menu_open` (gui.asm) | "settings showing" | 3 reset sites |
| `g_overlay` (theme.asm) | the same fact, in another module | its own lifetime |
| painter guards | `theme_erase`, `gui_draw_field_cards`, row painter | each painter must **opt out** |
| absolute DLU layout | settings rows sit in `DLG_VAULT`'s coordinate space | a new row means shifting every row below it |

## 2. Every bug we hit this session traces to one of those rows

- **Settings backdrop showed the vault's cards through it** — a painter that did not
  self-suppress. Fixed by adding a guard to `gui_draw_field_cards`.
- **Locking with settings open left the sidebar card unpainted for the whole next
  session** — `g_overlay` is the same state as `g_menu_open` but in another module with a
  different reset point, and only one of the pair was re-zeroed on window creation.
- **The C9 row bled onto the main screen** — proximate cause was an id collision, but the
  reason a collision *could* hide a control is that visibility is a lookup by id in a
  hand-maintained array rather than a property of a window.
- **Adding the C9 row** meant editing the rc, an `equ`, `g_menu_ids`, `MENU_ID_COUNT`, the
  populate path, the save path, the HKLM-lock path, and shifting four rows below it by
  14 DLU.

None of these are hard bugs. They are the *same* bug: **two screens sharing one window,
partitioned by hand.**

## 3. The observation that decides it

Every other screen in Vordr is already a real dialog — `DLG_HOTKEY`, `DLG_PWGEN`,
`DLG_ICON`, `DLG_ABOUT`, `DLG_SELECT`, `DLG_PWHIST`, `DLG_PWREMIND`. None of them needs an
id array, a visibility flag, or a painter guard, because a window occludes what is behind
it for free.

**Settings is the only screen implemented as an overlay, and it is the only screen that
keeps breaking.** The exception is the defect.

## 4. Options

**A — modal popup dialog.** Smallest change, matches every other screen. But settings
becomes a separate window rather than an in-place panel, which is a real UX change.

**B — keep the overlay, make it data-driven.** One table of rows {id, label, kind, global,
reg name, min, max, lock flag} driving layout, populate, save and visibility. Removes the
hand-maintained duplication, and adding a setting becomes one table entry. Does **not**
fix the shared-window painting problem — painter guards and `g_overlay` stay.

**C — child dialog inside the vault window (recommended).** `CreateDialog` a `WS_CHILD`
settings dialog over the client area; show/hide **one hwnd** instead of 35 ids. Keeps the
in-place look exactly as it is today.

What C deletes outright:

- `g_menu_ids`, `MENU_ID_COUNT`, `g_vault_ids`, `VAULT_ID_COUNT` — the child occludes the
  vault, so nothing needs hiding.
- `g_overlay` and its `theme_erase` guard — the child paints its own background.
- `gui_draw_field_cards`'s guard and the row-painter guard — those painters can no longer
  be seen when settings is up.
- `IDC_V_MBACK` — the child *is* the backdrop.
- The layout coupling: settings gets its own coordinate space, so a new row can never
  disturb the vault's.

`g_menu_open` survives as one flag in one module (Esc handling, save-on-lock), instead of
a mirrored pair.

## 5. Decisions needed

1. **A, B or C?** C keeps today's look; A is smaller but changes it to a popup.
2. **Staged or one commit?** Recommended: (i) move the controls into a child dialog with
   the existing populate/save logic retargeted, verify on screen; (ii) delete the arrays,
   flags and guards that are now dead — the strict build's dead-code check will name them;
   (iii) optionally fold in B's table so adding a setting is one entry.
3. **Resize behaviour** — one `MoveWindow` of the child on `WM_SIZE`, or give it the
   existing `ANCH_STRETCHW|ANCH_STRETCHH` anchor that `IDC_V_MBACK` uses today.

## 6. Risk, honestly

This is a visual refactor of the screen that has already misbehaved most, and **none of it
is gate-testable** — every check is on-screen. Against that: stage (ii) is guarded by the
dead-code checker, which will refuse to build while anything it should have deleted still
exists, so the cleanup cannot be half-done silently.

The thing that does *not* work is leaving it as-is and being more careful. Four separate
breakages this session, each fixed correctly, and the fifth is already latent in the next
setting someone adds.

## 7. What stage (i) actually cost (written after the fact)

§6 said the risk was that none of this is gate-testable. That was right, and it was the
expensive part: moving 34 controls into another window created **ten** bugs of one shape —
a call still aimed at the window the control used to be in. Win32 fails these silently
(`SetDlgItemTextW` → FALSE, `GetDlgItemInt` → 0, `GetDlgItem` → NULL), so all ten built
clean and five passed visual inspection.

Three were found on screen, one by reading, and six by a script written afterwards:

- `gui_menu_save` stored its `rcx` **into** `g_settings_hwnd` instead of a local, so
  closing settings hid the vault window and silently discarded every numeric setting.
- the colour-scheme and hotkey captions wrote to the vault and went nowhere; the rc's
  placeholder caption (`"Dark"`) was plausible enough to read as a real scheme name.
- `g_overlay` was set on open and never cleared on close, so `theme_erase` skipped
  `theme_sidecard` for the rest of the session — the same mirrored-pair bug as the
  lock-with-settings-open one, at a different reset point.
- six toggle handlers called `InvalidateRect(GetDlgItem(vault, <settings id>), ...)`.
  `InvalidateRect(NULL)` does **not** no-op: it repaints every window on the desktop, so
  the toggle refreshed as collateral damage and the miss was invisible.

Two lessons worth keeping:

1. **A placeholder that looks like real data hides the bug that would have exposed it.**
   Captions that get written at runtime are now empty in the rc, so a failed write shows
   as a blank control instead of a convincing wrong value.
2. **Prefer removing the way to get it wrong over fixing the instance.**
   `gui_hotkey_label` lost its hwnd parameter and the six toggles were folded into
   `gui_inval_setting`, because those controls exist in exactly one window — passing an
   hwnd only created the opportunity to pass the wrong one.

`tools/dlgtarget.py` now gates this class: it reads the rc for which dialog owns each
control id, reads gui.asm for which window each call targets, and fails a strict build
when they disagree. Its limits are real — it can only attribute hwnd expressions naming
a known global, so calls reaching a control through a local are reported as
unattributable (`--strict-unknown`) rather than proven.
