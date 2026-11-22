# User guide

[Documentation](README.md) · [Install and configure policy](DEPLOYMENT.md)

## Install and create a vault

Vordr runs natively on Windows x64 and Windows on ARM (ARM64). On x64, its CPU
gate requires AES-NI, PCLMULQDQ, SSE4.1, and SHA-NI (AVX2 and RDSEED are optional).
On ARM64, its CPU gate requires ARMv8 Cryptography Extensions (`AESE`/`AESMC`,
`PMULL`, `SHA256*`, `SHA1*`; ARMv8.5 `RNDRRS` is mixed in automatically when
`FEAT_RNG` is available). The default password derivation allocates 512 MiB in
addition to the application's other memory.

Install from the WinGet community source, or choose a download from
[Releases](https://github.com/xxtsxx/Vordr/releases). See
[executable verification](RELEASES.md#verify-a-download) for checking the build.

- **WinGet:** run the command below to download and install the published universal MSI.
- **Portable executable:** run `vordr.exe` (x64) or `vordr-arm64.exe` (ARM64) from a folder you control.
- **MSI:** a single universal installer that carries both x64 and ARM64 binaries, automatically deploys the native executable to `%ProgramFiles%\Vordr\vordr.exe`, and requires elevation. Vordr itself runs with the launching user's privileges.

```powershell
winget install --id ThomasSmistad.Vordr --exact --source winget
```

WinGet uses the MSI's machine-wide installation and may request administrator
approval. It does not create or upload your vault. WinGet needs network access
to retrieve packages; Vordr's offline behavior is unchanged. If WinGet is not
available, use a manual download or follow Microsoft's
[WinGet setup guidance](https://learn.microsoft.com/en-us/windows/package-manager/winget/).

Open Vordr from the notification area. On first use, create the vault and choose
a strong, unique master password. The default policy requires 12 characters
and three character classes; satisfying that policy alone does not make a
predictable password strong. A randomly generated password or passphrase avoids
the patterns people commonly choose.

There is no password reset, escrow, or vendor recovery. Keep a written copy of
the master password in a physically secure place if that fits your needs.

### Where the vault lives

The default is `Vordr\vault.vordr` under a linked OneDrive account's folder,
or under Documents if no linked account is found. The environment variable alone
does not establish that OneDrive is linked. The unlock dialog shows the path.
An administrator can pin it through policy.

The application does not synchronize data itself. A sync client sees the encrypted
file, but can still observe file sizes and update times, lose updates, or restore
an older copy. Keep an independent backup and avoid editing on two devices before
their sync clients have caught up.

## Updates

Vordr does not check for or install updates itself. For an installed copy,
WinGet can check the community listing and install a newer published version:

```powershell
winget show --id ThomasSmistad.Vordr --exact --source winget
winget upgrade --id ThomasSmistad.Vordr --exact --source winget
```

Save your work, back up the encrypted vault, and exit Vordr before upgrading.
An upgrade may request administrator approval. If no newer version is listed,
there is nothing to upgrade through this source. A GitHub release can appear
before its WinGet submission is approved and published.

WinGet does not replace an arbitrary portable `vordr.exe` in a folder you chose.
For portable use, download and verify the new executable, then replace your
old executable after exiting it; keep the vault and backups. Installing the MSI
does not remove a separate portable copy, so avoid accidentally running an old one.

On managed machines, follow your administrator's update process. A plain WinGet
upgrade does not repeat custom MSI policy properties; see
[deployment and upgrades](DEPLOYMENT.md#installation-and-upgrades).

WinGet publication is not Microsoft security certification or code signing,
and does not guarantee the absence of antivirus warnings. Continue to follow
the [verification guidance](ANTIVIRUS.md). For command behavior, see Microsoft's
[install](https://learn.microsoft.com/en-us/windows/package-manager/winget/install)
and [upgrade](https://learn.microsoft.com/en-us/windows/package-manager/winget/upgrade)
references.

## Work with entries

An entry can contain usernames, passwords, dedicated PIN codes, URLs, notes, TOTP
keys, custom-labeled fields, and attachments. PIN fields share the same masking,
reveal, clipboard auto-clear, and change-history protections as password fields,
but use PIN-specific health and policy checks (`PinMinLen = 6` characters by default,
no character-class mix required, and detection of trivial patterns such as repeated
characters, `123456` runs, short cycles, and palindromes, controlled by **Reject
trivial PINs** in Settings). Search and favorites help find entries; custom icons
help distinguish them. TOTP uses a base32 key and depends on the computer's clock.

The generator offers random passwords, passphrases (`6` to `24` words drawn from an
embedded `2,048`-word list, `11` bits per word), pronounceable strings, PINs,
and hexadecimal strings. Its entropy display is an estimate for the selected
generation method, not an assessment of an arbitrary password you typed.

Changing a field can retain its previous value in encrypted history. Use the
History browser to inspect or purge recorded values. “Do not save history” stops
new capture; do not assume it removes records already stored. Likewise, deleting
an entry into Trash is not the same as permanently purging it. When you delete
fields, purge history, or permanently delete an entry so the vault shrinks, Vordr
automatically overwrites and removes local `.bak1`–`.bak3` files from alongside
the active vault; separate external backups and exports can still retain earlier
snapshots.

An entry Vordr cannot show completely - more fields than the detail pane holds, a
value too long to display, or an attachment it cannot list (possible only for
data imported from elsewhere) - opens read-only with an explanation. Every change
is saved by rebuilding the entry from what is on screen, so saving one that is
only partly shown would drop the rest.

Lists, and an entry with more fields than fit on screen, scroll with a bar that
appears when you point at their right edge: drag it, click above or below it to
move a page, or use the mouse wheel. An entry's fields scroll a whole
card at a time, and tabbing to a field that is off screen brings it into view.

Vordr animates a little when Windows' own **Animation effects** setting is on:
the selection slides between entries, an entry cross-fades into the next one,
focus underlines expand from center, toggle pills slide, and rows and buttons
fade their highlight in and out (an administrator can override this with the
`ui_anim` policy value: `0` follow Windows, `1` always, `2` never).
**Settings > Color scheme** cycles sequentially through three light palettes (*Light*,
*Sepia*, *Solarized*) and six dark palettes (*Nord*, *Midnight*, *Sapphire*,
*Gruvbox*, *Catppuccin*, *OLED Black*), plus *Follow Windows*
(`ui_scheme`: `0..8` for the palettes, `6` default, `9` to switch automatically
between your last-chosen light and dark palettes when Windows toggles Light/Dark mode).
**Settings > Backdrop** cycles the main window surface across sixteen static
GPU-computed procedural styles (*Cut planes*, *Low-poly neon*, *Corner mosaic*,
*Crystal rim*, *Guardian sigil*, *Cipher rings*, *Intaglio print*, *Leaf*,
*Shadow*, *Tattoo*, *Nebula*, *Mariusgenser*, *Matrix*, *Tron*, *Event horizon*,
*Spiderweb*) plus *Flat* (enforceable via `ui_backdrop`: `0..15` for the
procedural styles, `16` for flat). Each backdrop is rendered once
into a cached bitmap when the window size, color scheme, or backdrop choice
changes, using zero GPU or CPU during normal interaction. On the Home overview, a
circular health ring summarizes vault password hygiene, clicking the *Weak*,
*Reused*, or *Ageing* stat cards filters the entry list directly (click
*Secrets* or the active card again to show all entries), and a bottom-aligned
frosted glass status pane shows the vault path, health summary, and launch
known-answer test verification. Each entry's tile shows a softened gradient
monogram of its title unless the title names a known service or you pick an
icon in edit mode—choosing from 144 Fluent icons and full-color *Segoe UI Emoji*
across three tabs, with independent **Tile** (background) and **Icon** (accent)
color selection across 24 solid swatches, a custom color picker, Auto mode, and
8 live-animated palettes.

## Locking, screen capture, and the clipboard

By default, Vordr clears a copied secret after 20 seconds, hides its windows from
ordinary screenshots and screen-sharing (`SetWindowDisplayAffinity`), locks after
10 minutes of system inactivity, and locks when Windows locks. Settings can adjust
clipboard and auto-lock timeouts, while `AllowScreenCapture` is an administrator-only
`HKLM` policy. To inspect a separate vault without modifying it, launch
`vordr.exe --ro <path\to\vault.vordr>` when the vault path is not locked by `HKLM`
policy.

Clipboard clearing checks the clipboard sequence number, so it does not erase
something you copied afterward. Both Vordr's Copy buttons and `Ctrl+C`/`Ctrl+X` inside
secret edit fields route through the same auto-clearing clipboard handler and supply
Windows clipboard exclusion formats. These reduce exposure to cooperating Windows
features; they do not prevent another process from reading the current clipboard.

Locking discards unsaved Settings changes rather than auto-committing them, wipes the
loaded vault and display/compositor buffers, clears Vordr's clipboard copy if it still
owns it, and attempts preview-file cleanup. Save changes and close attachment viewers
before exiting. A forced process stop is not equivalent to an orderly lock and cleanup.

A lock - from inactivity, Windows locking, the hotkey or Ctrl+L - first closes any
Vordr dialog or message box that is open, answering it as Cancel, and then locks.
An unanswered question no longer keeps the vault open.

## Unlock options

### Private-desktop password entry

Secure Unlock is enabled by default. It runs the password prompt on an isolated Windows
desktop (`CreateDesktopW` + `SwitchDesktop`), shielding keystrokes and dialog rendering
from ordinary user-mode hooks and screen capture on the main desktop. If Windows refuses
to create the private desktop, Vordr explains why and asks for explicit confirmation
before showing a normal-desktop prompt—unless `SecureUnlock=1` is locked by administrator
policy (`HKLM`), in which case Vordr refuses fallback altogether. It does not protect
against kernel-level or `SYSTEM`/admin attackers.

### TPM convenience unlock

**Settings > TPM Unlock** lets you choose how this PC's TPM 2.0 chip unlocks the vault:

- **Off:** always require your master password.
- **TPM only (default when a TPM is available):** unseals silently on this PC.
- **TPM + PIN:** pairs the TPM with a Vordr PIN (minimum 6 characters by default; digits
  or letters allowed). Failed attempts are recorded under a rotating TPM state key so
  registry backups cannot reset the counter; after **TPM PIN max tries** failed attempts
  (default `3`), Vordr deletes the TPM shortcut and requires your master password.
- **TPM + Hello:** requires both this PC's TPM key and Windows Hello (face, fingerprint,
  or Windows Hello PIN).

Like a password unlock, every TPM mode warns before opening a vault file older than the
last one saved on this PC. TPM unlock is a local convenience path on one device, not a
replacement for backing up your master password.

A cleared TPM, hardware replacement, changed Windows setup, or a different
computer can make this shortcut unavailable. The master password still matters.
The default reminder asks you to type it every 30 days. This is a reminder, not
a lockout deadline: postponing it does not deliberately revoke TPM access.

If Windows or the hardware TPM enters anti-hammering protection (for example,
Windows's default 8-hour standard-user cooldown after 4 failed TPM authorization
attempts on the PC, or a hardware TPM dictionary-attack heal interval of 10-120
minutes of powered-on time per attempt), Vordr displays the active mechanism,
remaining cooldown, and estimated expiry time. Your vault and master password are
unaffected and can be used immediately while the cooldown expires.

## Attachments and plaintext copies

Attachments are encrypted in the vault. Opening one in another application
requires a plaintext temporary file. Vordr creates a separate random temporary
directory, tracks the file, and attempts to overwrite, flush, and delete it on
lock. If a viewer blocks cleanup, it keeps the path for another attempt every
five seconds while locked. Normal Exit asks you to close blocked viewers.

Crashes, forced termination, shutdown, filesystem snapshots, and the viewer's own
copies can leave plaintext behind. Overwriting is not a guarantee of physical
erasure, especially on SSDs or backed-up storage.

Enable **Disable attachment preview** (`NoPreview`) to turn off preview hand-off
completely. Even when preview is enabled, Vordr restricts automatic preview to a strict
**safe-preview allowlist** of eight extensions—`.txt`, `.png`, `.jpg`, `.jpeg`, `.gif`,
`.bmp`, `.webp`, and `.pdf`—written with sanitized filenames inside an owner-only
temporary directory (`DACL`) and stamped fail-closed with Mark of the Web
(`Zone.Identifier`, `ZoneId=3`) so viewers apply untrusted-file protections (such as
Protected View). Every other file type routes exclusively to **Save As** (download-only)
and is never launched via Windows Shell. Each entry supports up to 24 attachments of up
to `256 MiB` each, and Vordr reports explicitly if a dropped or selected file exceeds
that cap.

## Back up and restore

Keep copies of the complete `.vordr` file, not just selected exported entries.
Vordr rotates previous generations into `.bak1` through `.bak3` during saves.
Those nearby copies are useful after a mistake, but can be lost with the same
disk, account, or sync folder as the active vault.

1. Finish saving and lock Vordr before copying the vault.
2. Store an additional encrypted copy independently of the active location.
3. Test recovery using a separate copy; do not overwrite your only good vault.
4. When restoring, retain the current file until you have verified the recovered data.

A rollback warning means the file's save counter is older than the value this
machine last recorded. It can be expected after an intentional restore, but an
unexpected warning warrants investigation. The warning is not available on a
machine with no matching counter history.

## Import and export

Export selected entries to a separate encrypted file with its own password.
Password history and internal system records are excluded, so selective export
is not a full-fidelity backup of the original vault.

| Format | Choose it when | Important limits |
|---|---|---|
| `.vordr` (default) | Another Vordr instance will read the data | Native vault protection; attachments retain their own encryption metadata |
| AES-encrypted `.zip` | Another compatible tool must read the data | Weaker password derivation; archive structure, sizes, and attachment extensions remain visible |

ZIP exports contain `vordr.json` (including per-attachment `SHA-256` plaintext
digests) and attachments in the WinZip AE-2 format. Use a tool that explicitly
supports AES-encrypted ZIP; ordinary ZIP support is not sufficient. Choose a
strong export password and protect the resulting file. Vordr's ZIP importer
supports **STORED (uncompressed)** members, not DEFLATE, and fails closed without
importing partial data if any referenced attachment member is missing, fails AE-2
authentication, or mismatches its `SHA-256` digest (older Vordr `.zip` exports
without `"sha256"` fields remain supported). If assembling a compatible archive
elsewhere, select STORE/no compression.

Export refuses to write over the vault you have open, however its path is
spelled. Import recognizes file contents rather than trusting the extension, and
names an encrypted ZIP it cannot read (AES-128/192, or compressed inside AES) as
such rather than reporting a wrong password. Choose the source, enter its
password, and select entries to append. Double-clicking a
`.vordr` file invokes this import workflow; it does not automatically switch
the registered vault or import anything without the remaining prompts.

## When something goes wrong

| Symptom | What to check |
|---|---|
| No window after launch | Look in the notification area; normal launch starts there |
| CPU-feature error | Check the required instruction set: AES-NI, PCLMULQDQ, SSE4.1, and SHA-NI on x64; ARMv8 Cryptography Extensions on ARM64 |
| Save blocked by another writer or a changed file | Let the other save finish, then reload; do not overwrite either copy blindly |
| Settings control disabled | An HKLM policy value may be enforcing it |
| Secret-memory warning | Windows could not pin a static buffer; review memory pressure and machine policy |
| Exit asks you to close a viewer | A preview file is still open and cleanup could not finish |
| ZIP import fails | Confirm AES-256 ZIP and STORED members; Vordr says when the archive uses something else |
| An entry opens read-only | Part of it cannot be shown in the detail pane; saving it there would drop that part |
| "The vault file was replaced by an OLDER copy" | Another program or a restore put an older vault in place; check it before saving |
| Antivirus warning | Follow [Antivirus warnings](ANTIVIRUS.md) before running the file |

For a bug report, use synthetic data and redact screenshots, paths, and logs.
For a possible vulnerability, follow the [private reporting policy](../SECURITY.md).
