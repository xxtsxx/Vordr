# User guide

[Documentation](README.md) · [Install and configure policy](DEPLOYMENT.md)

## Install and create a vault

Vordr runs on Windows x64. Its CPU gate requires AES-NI, PCLMULQDQ, SSE4.1, and
SHA-NI; AVX2 and RDSEED are optional. The default password derivation allocates
512 MiB in addition to the application's other memory.

Install from the WinGet community source, or choose a download from
[Releases](https://github.com/xxtsxx/Vordr/releases). See
[executable verification](RELEASES.md#verify-a-download) for checking the build.

- **WinGet:** run the command below to download and install the published MSI.
- **Portable executable:** run `vordr.exe` from a folder you control.
- **MSI:** installs for all users in `%ProgramFiles%\Vordr` and requires elevation.
  Vordr itself runs with the launching user's privileges.

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

An entry can contain usernames, secrets, URLs, notes, TOTP keys, custom-labeled
fields, and attachments. Search and favorites help find entries; custom icons
help distinguish them. TOTP uses a base32 key and depends on the computer's clock.

The generator offers random passwords, passphrases, pronounceable strings, PINs,
and hexadecimal strings. Its entropy display is an estimate for the selected
generation method, not an assessment of an arbitrary password you typed.

Changing a field can retain its previous value in encrypted history. Use the
History browser to inspect or purge recorded values. “Do not save history” stops
new capture; do not assume it removes records already stored. Likewise, deleting
an entry into Trash is not the same as permanently purging it. Old backups and
exports can retain data after you purge it from the active vault.

## Locking and the clipboard

By default, Vordr clears a copied secret after 20 seconds, locks after 10 minutes
of system inactivity, and locks when Windows locks. Settings can change these
values unless administrator policy fixes them.

Clipboard clearing checks the clipboard sequence number, so it does not erase
something you copied afterward. Vordr also supplies Windows clipboard exclusion
formats. These reduce exposure to cooperating Windows features; they do not
prevent another process from reading the current clipboard.

Locking wipes the loaded vault and relevant display buffers, clears Vordr's
clipboard copy if it still owns it, and attempts preview-file cleanup. Save
changes and close attachment viewers before exiting. A forced process stop is
not equivalent to an orderly lock and cleanup.

## Unlock options

### Private-desktop password entry

Secure Unlock is enabled by default. It places the password prompt on a separate
Windows desktop, reducing exposure to ordinary input hooks and screen capture
on the main desktop. It is not a guarantee against local malware or privileged
attackers. If the private desktop cannot be created, the application can fall
back to the normal prompt.

### TPM convenience unlock

TPM unlock is enabled by default when a usable TPM is available. It wraps the
vault key using a machine-local TPM key and stores the wrapped blob in HKCU.
It is an alternative to typing the master password, not an additional factor.
The optional `TpmRequireHello` setting requests provider-mediated confirmation.

A cleared TPM, hardware replacement, changed Windows setup, or a different
computer can make this shortcut unavailable. The master password still matters.
The default reminder asks you to type it every 30 days. This is a reminder, not
a lockout deadline: postponing it does not deliberately revoke TPM access.

## Attachments and plaintext copies

Attachments are encrypted in the vault. Opening one in another application
requires a plaintext temporary file. Vordr creates a separate random temporary
directory, tracks the file, and attempts to overwrite, flush, and delete it on
lock. If a viewer blocks cleanup, it keeps the path for another attempt every
five seconds while locked. Normal Exit asks you to close blocked viewers.

Crashes, forced termination, shutdown, filesystem snapshots, and the viewer's own
copies can leave plaintext behind. Overwriting is not a guarantee of physical
erasure, especially on SSDs or backed-up storage.

Enable **Disable attachment preview** to avoid the preview hand-off. Attachments
then become download-only: downloading still creates a plaintext file at the
location you choose, and you are responsible for that copy. Executable
attachments are download-only regardless of this setting.

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

ZIP exports contain `vordr.json` and attachments in the WinZip AE-2 format.
Use a tool that explicitly supports AES-encrypted ZIP; ordinary ZIP support is
not sufficient. Choose a strong export password and protect the resulting file.
Vordr's ZIP importer supports **STORED (uncompressed)** members, not DEFLATE.
If assembling a compatible archive elsewhere, select STORE/no compression.

Import recognizes file contents rather than trusting the extension. Choose the
source, enter its password, and select entries to append. Double-clicking a
`.vordr` file invokes this import workflow; it does not automatically switch
the registered vault or import anything without the remaining prompts.

## When something goes wrong

| Symptom | What to check |
|---|---|
| No window after launch | Look in the notification area; normal launch starts there |
| CPU-feature error | Check the required instruction set, including SHA-NI |
| Save blocked by another writer or a changed file | Let the other save finish, then reload; do not overwrite either copy blindly |
| Settings control disabled | An HKLM policy value may be enforcing it |
| Secret-memory warning | Windows could not pin a static buffer; review memory pressure and machine policy |
| Exit asks you to close a viewer | A preview file is still open and cleanup could not finish |
| ZIP import fails | Confirm AES ZIP compatibility and STORED members |
| Antivirus warning | Follow [Antivirus warnings](ANTIVIRUS.md) before running the file |

For a bug report, use synthetic data and redact screenshots, paths, and logs.
For a possible vulnerability, follow the [private reporting policy](../SECURITY.md).
