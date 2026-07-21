# Changelog

All notable changes to this project are documented here.
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


