# Changelog

All notable changes to this project are documented here.
## [1.3.1] - 2026-11-19

### Bug Fixes

- *(msix)* Start the Store edition with Windows through a startup task
- *(deps)* Update System.Formats.Cbor to 10.0.15

### Documentation

- Update changelog for v1.3.0 [skip ci]

## [1.3.0] - 2026-11-19

### Features

- *(ssh)* Approve a key for one application or all until the vault is locked
- *(offline)* Queue remembered websites and keep an encrypted read-only offline copy
- *(web-vault)* Open the web vault and approve its log in with device requests
- *(offline)* Switch the offline copy per vault and add a read-only vault view
- *(passkey)* Refuse a new passkey right away while its vault is offline

### Bug Fixes

- *(i18n)* Translate German terms left in the other languages
- *(unlock)* Open fresh connections after a network or VPN switch
- *(vault)* Send encryptedFor and keep URI checksums on cipher writes (#6)
- *(passkey)* Accept requests from any version of the VaultType package
- *(settings)* Fall back to a known tray click action

### Refactor

- Trim redundant comments and tidy local names
- *(notifications)* Show errors in a window and drop confirmation notifications

### Documentation

- Update changelog for v1.2.3 [skip ci]
- Document the web vault, the per-vault offline copy and the vault view

## [1.2.3] - 2026-10-09

### Features

- Fill checkout and registration forms from card and identity entries
- *(updates)* Indicate available updates outside of notifications (#4)
- *(autotype)* Pick the card expiry from drop-down lists
- *(installer)* Install into Program Files by default and migrate per-user installs

### Bug Fixes

- Suggest the full host for remembering when host matching is the default
- Always remember the full host regardless of the default match rule
- Ask for the account e-mail when signing in with an API key
- Keep trashed vault entries out of the picker and entry counts
- Send the clear-field Ctrl+A as separate key events
- Raise the default typing delay to 25 ms
- *(signin)* Keep the sign-in window inside the screen and scroll when it does not fit
- *(msix)* Lower the minimum Windows version so the package is not gated on 24H2
- *(signin)* Trim whitespace from a pasted API client secret
- *(autotype)* Find card fields in browsers before the page is accessible and below the fold
- *(unlock)* Report an unreachable server instead of a JSON parse error

### Performance

- *(picker)* Virtualize the grouped entry list and share pending icon lookups

### Refactor

- Remove all runtime logging and dev-only diagnostics

### Documentation

- Update changelog for v1.2.0 [skip ci]
- *(legal)* Complete third-party notices and fix policy statements
- Add Bitwarden cloud regions to the bug report form (#1)
- Document window title matching for desktop apps (#3)
- Document the raised typing delay and the API-key e-mail field
- Use English mock data and refresh the outdated screenshots
- Recapture the sign-in screenshot that predates the account e-mail field
- *(store)* Refresh the listing screenshots

### Miscellaneous

- *(release)* Ship the portable build as a zip with license texts
- Drop an unused using left over from the removed debug output

## [1.2.0] - 2026-07-21

### Features

- Add a default URL match setting (base domain or host)
- Add Bitwarden cloud region selection (US / EU)
- Add a built-in Bitwarden vault client
- Serve vault SSH keys over a built-in SSH agent
- Register as a Windows passkey provider
- Replace the Bitwarden CLI with the built-in vault client
- *(store)* Add store edition support and remove auto-update setting

### Documentation

- Update changelog for v1.1.0 [skip ci]
- Note the Bitwarden CLI signature check in the security model
- Document the URL match setting and refresh the settings screenshot
- Document the Bitwarden cloud regions and refresh the sign-in screenshot
- Add a privacy policy and third-party notices
- Rewrite the README for the built-in vault client and refresh the screenshots
- *(store)* Add store installation guide and listing assets

### Miscellaneous

- Target .NET 10
- Add an MSIX package build
- Pin the release actions and stop inlining workflow inputs
- Redraw the logo with a check mark
- *(store)* Add store job to release workflow
- *(msix)* Add -Store mode for partner center signing
- *(store)* Allow skipping the submission via [skip store] in the tagged commit

## [1.1.0] - 2026-07-12

### Features

- Guided first-run CLI setup with download progress
- Verify the Bitwarden CLI's signature before running it

### Bug Fixes

- Harden TOTP seed handling, CLI arg quoting and regex matching
- Run vault sync off the UI thread and wait for a complete bw.exe

### Refactor

- Remove unused members and constants

### Documentation

- Update changelog for v1.0.1 [skip ci]
- Add setup/download screenshots and refine README

## [1.0.1] - 2026-07-11

### Features

- Rework sign-in and account settings

### Documentation

- Update changelog for v1.0.0 [skip ci]
- Expand the screenshots gallery and installation guide
- Clarify the connection note for bitwarden.com

### Miscellaneous

- Build a per-user installer alongside the portable exe

## [1.0.0] - 2026-07-11

### Features

- Initial public release

### Refactor

- Remove redundant null check that triggered a nullable warning


