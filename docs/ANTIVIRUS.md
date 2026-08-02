# Antivirus false positives

Microsoft Defender has flagged Vordr as `Trojan:Win32/Wacatac.B!ml`, and v0.2.3 as
`Trojan:Win32/Wacatac.C!ml`. Both are false positives, and this page explains why
it happens, what you can check for yourself, and what is being done about it. It
also says plainly what will **not** be done.

## What that detection name means

The `!ml` suffix marks a **machine-learning** verdict, not a signature match.
Defender did not recognise Vordr as a known piece of malware; a classifier scored
the file as suspicious. `Wacatac` is a generic bucket that such verdicts land in,
and it is one of the most frequently reported false positives for small, new,
unsigned Windows programs.

## Why Vordr scores badly

Three reasons, and only one of them is about the code.

**1. It is not code-signed.** This is the dominant factor. An Authenticode
signature from a certificate authority is the main input reputation systems have,
and Vordr has none yet. See *Signing* below.

**2. Nobody has run it.** Reputation systems weight prevalence heavily: a file
seen on millions of machines is trusted, a file seen on none is not. A new release
starts at zero by construction, and every new release resets it, because the hash
changes.

**3. A password manager looks like a credential stealer from the outside.**
This one is worth stating honestly, because it is not going away. Consider what
Vordr imports and why:

| what it does | why it needs it | how it looks to a classifier |
|---|---|---|
| registers a system-wide hotkey | summon the window from anywhere | keyboard hooking |
| switches to a private desktop | keep the master password away from input hooks | evading observation |
| reads and writes the clipboard | copy a secret, then clear it | clipboard stealing |
| encrypts and decrypts data | it is a vault | payload encryption |
| reads and writes the registry | settings and policy | persistence |

Every one of those is the product working as designed and as documented. A
program that guards secrets and a program that steals them touch the same APIs.
No amount of restructuring changes that, and a tool that avoided these calls would
be a worse password manager.

## What you can check yourself

This is where Vordr can do better than "trust us", and it is the reason the
reproducible build exists.

**Every release is byte-for-byte reproducible.** Anyone with the toolchain can
rebuild the exact tagged commit and get an identical `vordr.exe`, then compare its
SHA-256 against the hash published in [RELEASES.md](RELEASES.md):

```
git checkout v0.2.1
build.cmd release
certutil -hashfile bin\vordr.exe SHA256
```

If it matches, the binary provably corresponds to the source you can read. That is
a stronger statement than any antivirus verdict in either direction: a clean scan
tells you a scanner did not object, while a matching hash tells you exactly what
the program is.

Structurally, the released binary is also unremarkable, which you can verify with
any PE tool:

- **not packed or obfuscated** — overall entropy 6.33, `.text` 6.32; packers push
  this above 7.2
- six normal sections, no writable-executable section
- full version metadata, icon and manifest, declaring `asInvoker` (Vordr never
  asks for elevation)
- NX, ASLR, high-entropy VA and CET all enabled
- imports only documented Microsoft DLLs
- no network imports at all — there is no socket anywhere in the binary

## Reporting it

If your scanner flags Vordr, please report it as a false positive. That is what
actually gets the verdict corrected, for everyone.

- **Microsoft**: <https://www.microsoft.com/en-us/wdsi/filesubmission> — choose
  "Software developer" if you are submitting on behalf of the project. Turnaround
  is usually one to three days.
- Other vendors have equivalent forms.

Because the hash changes with every release, a submission covers **that build
only**. Re-submitting is part of the release process (see RELEASES.md).

### A VirusTotal score of 0 does not mean Defender is happy

For v0.2.3, VirusTotal reported **0 detections across every engine** on the same
day WDSI reported a live `Trojan:Win32/Wacatac.C!ml` verdict on the same file.
That is not a contradiction, and it is worth understanding before reading too much
into a clean VirusTotal page.

The `!ml` suffix means the verdict comes from a **cloud-delivered** classifier that
scores a file in context - its prevalence, its age, where it came from, what it
does when it starts. VirusTotal runs a locally-installed engine against a static
sample: no cloud lookup, no reputation history, no runtime behaviour. The two are
answering different questions, so a clean VirusTotal row for Microsoft says
nothing about what Defender will do on a user's machine.

The practical consequence: judge clearance by WDSI's response, not by VirusTotal.
VirusTotal is still worth submitting to - it seeds the other engines and gives a
public record for the published hash - but it is not the thing that decides whether
your users see a warning.

### Submission log

| version | submitted | Microsoft verdict at submission | outcome |
|---------|-----------|----------------------------------|---------|
| v0.2.3 | 2026-08-02 | `Trojan:Win32/Wacatac.C!ml` (WDSI); VirusTotal 0 detections | awaiting response |

## Signing

Code signing is the real fix and it is not free: an OV certificate is a few
hundred currency units a year, an EV certificate more, and since 2023 both require
the private key to live on a hardware token or in a cloud HSM. EV additionally
grants SmartScreen reputation immediately rather than earning it over time.

Until Vordr is signed, expect new releases to be flagged occasionally, and expect
SmartScreen to warn on first run. That is an honest cost of an unsigned binary and
not something to work around.

## What will not be done

Some "fixes" for antivirus detections make the software worse or less trustworthy,
and Vordr will not use them:

- **No packing, obfuscation or import hiding.** These are the techniques malware
  uses to evade exactly this analysis. They would raise the score, not lower it,
  and they would defeat the point of shipping a program you can read.
- **No dropping of features to look harmless.** The private desktop, the global
  hotkey and the clipboard integration are what the program is for.
- **No asking users to add a blanket antivirus exclusion.** Telling people to
  disable protection for a password manager is bad advice on its face, and it is
  precisely what a malicious program would ask for. Verify the hash instead.
