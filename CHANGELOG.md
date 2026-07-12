# Changelog

All notable changes to this project are documented here.
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


