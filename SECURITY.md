# Security policy

VaultType handles master passwords and vault data, so security reports are taken seriously.

## Reporting a vulnerability

Please **do not** open a public issue for security problems. Report them privately through GitHub's
[private vulnerability reporting](https://github.com/friedPotat0/VaultType/security/advisories/new).

Include as much detail as you can - affected version, steps to reproduce, and impact. Please do not
include your own master password or vault contents.

## Scope

VaultType is a hardened front-end to the official Bitwarden CLI; all cryptography is performed by
Bitwarden's own code. Reports about the CLI or the Bitwarden / Vaultwarden server itself belong to
those projects. In scope here is VaultType's own handling of secrets: memory (locked buffers,
encryption at rest in RAM), auto-typing, the clipboard, process launching, and screen-capture
protection.

## Supported versions

Only the latest release is supported. Please reproduce on the newest version before reporting.
