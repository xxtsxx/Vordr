# Documentation

[Project overview](../README.md)

Start with the guide for your task. User instructions describe the current
source tree; an older release may behave differently. Release hashes are
historical records and must be matched to the exact tag.

## Use and deployment

- [User guide](USER_GUIDE.md): create a vault, manage secrets, back up, and move data.
- [Deployment and policy](DEPLOYMENT.md): MSI installation, registry settings,
  policy precedence, upgrades, and uninstall behavior.
- [Antivirus warnings](ANTIVIRUS.md): verify a download and report a suspected false positive.
- [Release hashes](RELEASES.md): identify and reproduce a published executable.

## Development and review

- [Development](DEVELOPMENT.md): toolchain, build variants, tests, and contribution workflow.
- [Architecture](ARCHITECTURE.md): modules, trust boundaries, unlock, and save flows.
- [File format](formats.md): header offsets, fields, attachments, and authentication.
- [Assurance](ASSURANCE.md): what the automated checks cover and what they do not.
- [Visual assurance guide](assurance.html): an offline browser companion, not a live test dashboard.
- [Secret memory](SECRETS.md): buffer inventory, locking, wiping, and exposure limits.

## Design decisions

These describe implemented designs, not a backlog of proposed features.

- [Settings screen](SETTINGS_DESIGN.md): child-dialog ownership and table-driven settings.
- [System items](SYSITEM_DESIGN.md): encrypted per-vault metadata and index discipline.

## Maintenance

- [Release checklist](RELEASE_CHECKLIST.md): verification, packaging, publication,
  WinGet submission, and security notifications.
- [Security policy](../SECURITY.md): private reporting, scope, support, and disclosure.

When updating a feature, update its guide and reference in the same change.
Keep defaults in the deployment table, format details in the format reference,
and test results in dated logs rather than undated “PASS” badges. Preserve the
existing document paths where possible so external links keep working.
