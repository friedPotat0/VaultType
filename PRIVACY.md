# VaultType privacy policy

*Last updated: 2026-07-28*

VaultType is a Windows client for Bitwarden and Vaultwarden vaults. This policy describes what
data the application handles and where it goes. The short version: **VaultType collects nothing.**

## What the developer receives

**Nothing.** VaultType contains no telemetry, no analytics, no crash reporting, no advertising and
no account system of its own. The developer receives no data of any kind from the application.

## What the application stores locally

All application data lives on your device under `%LOCALAPPDATA%\VaultType`, in a folder whose
access rights are restricted to your Windows user account:

- **Settings** (`config.json`) - hotkey, language, behaviour toggles and the list of configured
  accounts (display name, server URL, email address). No secrets are stored here.
- **Per-account session data** - the cryptographic key envelopes needed to unlock your vault
  (protected by your master password or PIN) and a refresh token sealed with Windows DPAPI.
  Your decrypted vault contents are **never written to disk**; they are re-fetched from your
  vault server on every unlock and held only in protected memory.
- **Favicon cache** - icons downloaded from your own vault server, if the icon feature is
  enabled.
- **Public metadata caches** - non-secret SSH public keys and passkey metadata, so those
  features can list entries while the vault is locked.

VaultType writes no log files. Uninstalling VaultType and deleting this folder removes all of it.

## What network connections the application makes

VaultType connects only to:

1. **The vault server you configure** (your self-hosted Vaultwarden/Bitwarden server, or the
   Bitwarden cloud) - to sign in, sync your vault, and optionally fetch website icons. What that
   server does with your data is governed by its operator's privacy policy (for the Bitwarden
   cloud, see [Bitwarden's privacy policy](https://bitwarden.com/privacy/)).
2. **GitHub** (`api.github.com`) - for the update check, which requests the latest release
   version. It runs when you trigger it manually (tray menu or Settings), and additionally in the
   background - at most once a day - if you switch *Check for updates automatically* on under
   Settings > General. That setting is **off by default**, so unless you turn it on the
   application never contacts GitHub on its own. No personal data is sent; GitHub sees an
   ordinary HTTPS request from your IP address.

There are no other connections. No third-party icon services, no content delivery networks, no
tracking endpoints.

## Vault data, passkeys and SSH keys

Your master password, PIN, vault entries, TOTP seeds, passkey credentials and SSH private keys
are processed exclusively on your device, in hardened memory (see the
[security model](README.md#security-model)). They are transmitted only between VaultType and your
own vault server, end-to-end encrypted according to the Bitwarden protocol. They are never sent
to the developer or to any third party.

## What the application reads from other windows

To decide which entries to suggest, VaultType reads the title and process name of the window that
was active when you pressed the hotkey, and - for recognised browsers - the address currently shown
in the address bar. This happens on your device only and is used solely to match entries against the
current site or application.

When a sequence fills a card or an identity, VaultType additionally reads the **structure** of the
target window's input fields - their labels and internal identifiers - through the Windows
accessibility interface, in order to place each value in the correct field. Only that structure is
read; the content of those fields is not read, and this lookup only runs when a sequence actually
requires it.

None of this information is stored, written to disk, or transmitted anywhere. It exists in memory
for the duration of the auto-type run and is discarded afterwards. VaultType writes no log files.

## Children's privacy

VaultType is a general-purpose utility and does not knowingly collect data from anyone,
including children.

## Changes to this policy

Changes are published in this file within the project repository; material changes are noted in
the release notes.

## Contact

Questions about this policy can be raised on the project's
[GitHub issue tracker](https://github.com/friedPotat0/VaultType/issues).
