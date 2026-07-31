# Deployment and policy

How to install Vordr across a fleet, and how to make settings stick when you get
there. Everything here is machine-wide configuration an administrator applies; a
single user installing Vordr for themselves needs none of it.

Two things to read before the tables, because they are the source of most of the
surprises:

1. **A policy value's *presence* is the lock.** Vordr does not have a separate
   "is this enforced" flag. If a value exists under `HKLM`, it wins over the
   user's preference *and* the matching control in Settings is disabled. So
   writing `SecureUnlock=1` is not the same as leaving it out: the first takes
   the choice away from the user, the second leaves them free to keep it on —
   and both produce the same behaviour today. Set only what you actually mean to
   mandate.
2. **MSI does not remember properties.** They are not stored, so an upgrade that
   does not repeat them installs without those values and the old package's
   values are removed along with it. Policy has to be passed on *every* install,
   upgrades included. Deployment tooling normally does exactly that, but it
   catches people who upgrade by hand.

Installing replaces any existing Vordr from `0.0.0` up to **and including** the
version being installed, so a rebuilt package of the same version takes over from
the one already there rather than registering beside it. If you ever see two
Vordr entries in Add/Remove Programs, that range is what went wrong; `verify_msi.ps1`
checks it and reports what a package would displace on the machine it runs on.

## Installing

The package is per-machine and needs elevation. It installs `vordr.exe` into
`%ProgramFiles%\Vordr`, an all-users Start Menu shortcut, the `.vordr` file
association, and any policy values you name — nothing else.

```
msiexec /i vordr-0.2.2.msi /qn
msiexec /i vordr-0.2.2.msi /qn VORDR_SECUREUNLOCK=1 VORDR_PWMINLEN=16 VORDR_CLIPSECONDS=10
msiexec /x vordr-0.2.2.msi /qn
```

Per-machine is deliberate: it is the only scope in which HKLM policy and file
associations can be registered, and Program Files is read-only to standard users,
so the binary cannot be replaced by anything running without admin. It does not
contradict `vordr.manifest`'s `asInvoker` — that governs how the program *runs*
(never elevated), not how it is installed.

Uninstall removes the exe, the shortcut, the file association and the policy
values it wrote. It does **not** touch vaults or `HKCU`. There is no `RemoveFile`
row anywhere in the package, and there must never be: for a password manager,
"cleaning up on removal" means destroying the user's secrets.

## Properties

All fifteen are public and settable on the command line. Fourteen write one
`HKLM\SOFTWARE\Vordr` value each, as `REG_DWORD`.

| Property | Registry value | Range | Vordr's default | Effect |
|---|---|---|---|---|
| `VORDR_PWMINLEN` | `PwMinLen` | 1–256 | 12 | minimum master-password length |
| `VORDR_PWMINCLASSES` | `PwMinClasses` | 1–4 | 3 | character classes a master password must mix |
| `VORDR_SECUREUNLOCK` | `SecureUnlock` | 0/1 | 1 | type the master password on an isolated desktop |
| `VORDR_TPMUNLOCK` | `TpmUnlock` | 0/1 | 1 | allow TPM convenience unlock |
| `VORDR_TPMREQUIREHELLO` | `TpmRequireHello` | 0/1 | 0 | require Hello/PIN for TPM unlock |
| `VORDR_CLIPSECONDS` | `ClipSeconds` | 0–3600 | 20 | clipboard auto-clear delay, seconds |
| `VORDR_IDLELOCKMIN` | `IdleLockMin` | 0–1440 | 10 | idle minutes before auto-lock, 0 = off |
| `VORDR_LOCKONWINLOCK` | `LockOnWinLock` | 0/1 | 1 | lock the vault when Windows locks |
| `VORDR_PWVERIFYDAYS` | `PwVerifyDays` | 0–3650 | 30 | re-verify the master password every N days under TPM unlock, 0 = off |
| `VORDR_NOHISTORY` | `NoHistory` | 0/1 | 0 | do not keep per-entry history |
| `VORDR_NOPHONETIC` | `NoPhonetic` | 0/1 | 0 | disable the phonetic secret reader |
| `VORDR_NOPREVIEW` | `NoPreview` | 0/1 | 0 | attachments download only, never previewed via another app |
| `VORDR_LOGLEVEL` | `LogLevel` | 0–4 | 0 | audit-log verbosity, 0 = off |
| `VORDR_UISCHEME` | `ui_scheme` | 0–8 | 8 | force a colour scheme (8 is the default) |

The "default" column is what Vordr uses when *nothing* is set anywhere. It is not
written by the installer.

One property is not a policy value and is inverted relative to the rest:

| Property | Effect |
|---|---|
| `VORDR_NOASSOC` | set to anything to skip registering `.vordr`. Unset means the association *is* registered. |

**Values are not validated at install time** — they cannot be, the installer only
sees them then. Vordr clamps every one on read, so a typo lands somewhere defined
rather than somewhere undefined. The clamps are not all "nearest edge", which
matters if you are relying on one:

| Value | Too high | Too low / zero |
|---|---|---|
| `PwMinLen` | 256 | **12** — the default, not 1 |
| `PwMinClasses` | 4 | **3** — the default, not 1 |
| `ClipSeconds` | 3600 | 0 is valid: never auto-clear |
| `IdleLockMin` | 1440 | 0 is valid: no idle lock |
| `PwVerifyDays` | 3650 | 0 is valid: no reminder |
| `LogLevel` | **0** — off, not 4 | 0 is valid: off |
| `ui_scheme` | **8** — the default | — |
| the 0/1 values | any non-zero reads as 1 | — |

So `PwMinLen=0` gives you 12 rather than "no minimum", and `LogLevel=9` switches
logging off rather than turning it up. Both are the safe direction, and neither
is what a typo intends.

### Worked examples

A locked-down build: no clipboard lingering, short idle lock, secure desktop
mandatory, attachments never handed to another program.

```
msiexec /i vordr-0.2.2.msi /qn ^
  VORDR_PWMINLEN=16 VORDR_PWMINCLASSES=4 ^
  VORDR_SECUREUNLOCK=1 VORDR_CLIPSECONDS=10 VORDR_IDLELOCKMIN=5 ^
  VORDR_LOCKONWINLOCK=1 VORDR_NOPREVIEW=1 VORDR_LOGLEVEL=2
```

Mandate one thing and leave everything else to the user — the more common case,
and the one the "presence is the lock" rule rewards:

```
msiexec /i vordr-0.2.2.msi /qn VORDR_NOPREVIEW=1
```

Estate that manages file associations centrally:

```
msiexec /i vordr-0.2.2.msi /qn VORDR_NOASSOC=1
```

## HKLM vs HKCU

Every setting resolves the same way, in `regcfg.asm`:

```
HKLM\SOFTWARE\Vordr  →  HKCU\SOFTWARE\Vordr  →  compiled-in default
```

`HKLM` is **policy**. A value found there wins, and Vordr records that it came
from `HKLM` so the Settings screen can disable the matching control. The Settings
save path then skips every locked row, so a user cannot overwrite policy by
opening Settings and pressing Save — the value is not written back at all.

`HKCU` is the **user's own preference**, written by the Settings screen. It is
what the user gets when policy is silent.

Neither hive is consulted for anything secret. The vault itself, its master
password, and its contents are never in the registry.

### If you are writing the registry directly

Any mechanism that can set a registry value works: Group Policy Preferences, an
Intune configuration profile, a configuration-management tool, `reg.exe`, or a
`.reg` file. There is no ADMX template — the values are plain `REG_DWORD`s under
`SOFTWARE\Vordr`, not under `SOFTWARE\Policies`.

```
reg add "HKLM\SOFTWARE\Vordr" /v NoPreview   /t REG_DWORD /d 1  /f /reg:64
reg add "HKLM\SOFTWARE\Vordr" /v ClipSeconds /t REG_DWORD /d 10 /f /reg:64
```

Two things to get right:

- **64-bit view.** `vordr.exe` is 64-bit and reads the native view. Anything
  running as a 32-bit process — an old script host, a 32-bit agent — is redirected
  into `WOW6432Node`, where Vordr never looks. The install *appears* to succeed
  and the policy silently does nothing. `/reg:64` pins it. (The MSI marks its
  registry components 64-bit for exactly this reason.)
- **`REG_DWORD`, not `REG_SZ`.** A value of the wrong type is rejected, and
  rejection means "fall through to `HKCU`, then to the built-in default" — so a
  mistyped policy leaves the setting where it was rather than enforcing something
  arbitrary. Nothing reports the mistake, though, so if a policy appears to have
  no effect, check its type first. (Until August 2026 the type was not checked at
  all. A value stored as the string `"1"` is exactly four bytes, so `PwMinLen` set
  that way read back as 49 and silently enforced a 49-character minimum.)

To remove policy and hand a setting back to the user, delete the value rather
than setting it to the default:

```
reg delete "HKLM\SOFTWARE\Vordr" /v NoPreview /f /reg:64
```

### Everything Vordr keeps in the registry

| Key | Value | Hive | Written by |
|---|---|---|---|
| `SOFTWARE\Vordr` | the fourteen policy values above | HKLM | administrator / MSI |
| `SOFTWARE\Vordr` | the same names, as preferences | HKCU | the Settings screen |
| `SOFTWARE\Vordr` | `vault` | HKLM pins the path, HKCU remembers the last one used | administrator / Vordr |
| `SOFTWARE\Vordr` | `ui_scheme`, `ui_layout`, `ui_hotkey` | HKCU | the Settings screen |
| `SOFTWARE\Vordr\TPM-Unlock` | per-vault TPM convenience blobs | HKCU | Vordr, when the user enrols |
| `SOFTWARE\Vordr\Rollback` | per-vault rollback counters | HKCU | Vordr |
| `SOFTWARE\Classes\.vordr`, `SOFTWARE\Classes\Vordr.Vault` | the file association | HKLM | MSI |

`ui_hotkey` is read with the same `HKLM > HKCU` precedence as everything else, so
setting it machine-wide does work — but it is not surfaced as a locked control,
so a user who rebinds the hotkey will see their choice saved and then quietly
overridden on the next start. Prefer leaving it alone.

`PwVerifyNow` appears in the source as a way to fire the re-verify prompt on every
unlock. It is compiled into test builds only: a release must not carry a registry
switch that changes when a master password is asked for.

## The .vordr file association

The package registers, under `HKLM\SOFTWARE\Classes`:

```
.vordr                          (default) = Vordr.Vault
Vordr.Vault                     (default) = Vordr vault
Vordr.Vault\DefaultIcon         (default) = <install dir>\vordr.exe,0
Vordr.Vault\shell\open\command  (default) = "<install dir>\vordr.exe" "%1"
```

Double-clicking a `.vordr` opens it as an **import source**. It never becomes the
vault Vordr opens from then on, and nothing is imported by the double-click
alone: the master vault is unlocked first, the source vault's own password is
typed in the GUI, and the entries to copy are ticked by hand. The file is
accepted on its magic bytes, not its extension. That is enforced in the program,
not by the installer — see the file-association section of the README.

Uninstalling deletes the `Vordr.Vault` class, so `.vordr` does not survive as a
file type that exists and cannot be opened. It deliberately does **not** delete
the `.vordr` key itself, which other applications may have added themselves to.

Windows Installer writes the association but nothing tells Explorer to re-read
it; there is no standard action for `SHChangeNotify`, and adding one would mean
shipping a custom-action DLL, which the package avoids. Explorer usually picks it
up within a minute, and always after a sign-out. If you are testing, note that a
per-user association in `HKCU\Software\Classes` shadows the per-machine one.

## Verifying a package before you deploy it

```
powershell -ExecutionPolicy Bypass -File tools\verify_msi.ps1 -Msi bin\vordr-0.2.2.msi
```

This does not install anything and needs no elevation. It reads the tables back
*and* costs the package through Windows Installer with properties set, asking
which components would actually be installed — the only way to test the
conditions rather than just the rows. It fails on the mistakes that are otherwise
silent in the field: a property missing from `SecureCustomProperties` (accepted,
then dropped before the elevated half of the install), a component not marked
64-bit (written into `WOW6432Node`), a value written with no condition (locking a
setting nobody asked to lock), an unquoted `%1` in the open command (a vault path
containing a space arrives split into fragments).

`msiexec /a` proves none of that. An administrative install unpacks the payload
without evaluating component conditions or the Registry table — which is how a
badly sequenced `RemoveExistingProducts` once passed `/a` and then failed a real
install with error 2613.

To check a machine after deployment:

```
reg query "HKLM\SOFTWARE\Vordr" /reg:64
```

Only the values you set should be there. In Vordr's Settings screen, every one of
them appears as a disabled control.

## Deliberately not exposed

The vault **path** (`HKLM\SOFTWARE\Vordr:vault`) is not an MSI property, because
an MSI property is one literal string and no single literal path is right for
every account on a machine.

Set by hand it is better than that, as long as you write it as `REG_EXPAND_SZ`:
environment variables in that type are expanded, so one machine-wide value can
give every user their own vault.

```
reg add "HKLM\SOFTWARE\Vordr" /v vault /t REG_EXPAND_SZ ^
        /d "%%USERPROFILE%%\Documents\vault.vordr" /f /reg:64
```

Note the doubled `%%` — that is `cmd` escaping, so the literal `%USERPROFILE%`
reaches the registry instead of being expanded as you type the command. A plain
`REG_SZ` is taken literally, which is what you want for a UNC path or a genuinely
fixed location.

An expansion that does not fit its buffer is rejected rather than truncated, and
Vordr then behaves as though no path were configured. That is deliberate: a
shortened path does not fail, it names a *different* file, which for a vault is
the difference between "not found" and opening the wrong one. (Expansion arrived
in August 2026; before that `REG_EXPAND_SZ` was accepted and then used verbatim,
so a path containing `%USERPROFILE%` simply failed to open.)
