# Agent Instructions

## Project overview

`gpg-wrapper` is a Rust 2024 desktop GUI built with `eframe`/egui around the system `gpg` executable. It manages keys, imports and exports ASCII-armored key material, and encrypts/decrypts text.

## Repository layout

- `src/main.rs` — application UI, GPG command execution, key parsing, import/export, encryption/decryption, and tests.
- `Cargo.toml` / `Cargo.lock` — Rust package and locked dependencies.
- `assets/gpg-wrapper-padlock.svg` — shared application/desktop icon source.
- `gpg-wrapper.desktop` — Linux desktop-entry metadata.
- `.github/workflows/release.yml` — tagged Linux and macOS release packaging.
- `Makefile` — local build, run, install, and clean shortcuts.
- `README.md` — user-facing requirements, installation, build, and platform notes.

## Development commands

Run these from the repository root:

```bash
cargo fmt
cargo check
cargo test
```

Use `cargo fmt -- --check` when only checking formatting. Tests invoke GPG and create isolated temporary GPG homes; do not replace them with tests that use a user's real keyring.

For local development:

```bash
cargo run
```

For a release-style Linux build:

```bash
make build
```

## GPG behavior and safety

- Use the system `gpg` executable; do not implement cryptography in Rust.
- Keep `LC_ALL=C` and `LANG=C` for predictable machine-readable GPG output.
- Preserve raw GPG export stdout whenever possible. ASCII armor must retain real newline bytes and both armor delimiters.
- Do not log, persist, or expose passphrases or secret key material.
- Secret-key export is sensitive and should remain explicitly selected by the user.
- Encryption runs GPG in batch mode and uses the configured recipient fingerprint. Do not weaken key handling or add trust bypasses without understanding the security impact.
- Import/export round-trip tests should use an isolated `GNUPGHOME`.

## UI conventions

- Keep public/private export selection separate from import controls; GPG identifies imported key material automatically.
- Disable private-key export when the selected key has no matching secret key.
- Keep export buttons compact and grouped together.
- Keep the window content-driven; avoid reintroducing fixed initial dimensions unless there is a demonstrated layout problem.
- Display key metadata consistently, including algorithm and size where available.

## Platform and packaging

- Runtime users need GnuPG (`gpg`) in `PATH`; Rust is only required to build from source.
- Linux uses the Wayland-enabled `arboard` dependency; non-Linux platforms use the default backend.
- Tagged releases matching `v*.*.*` trigger `.github/workflows/release.yml`.
- Linux releases include an x86_64 tarball and AppImage.
- macOS releases build both `aarch64-apple-darwin` and `x86_64-apple-darwin`, merge them with `lipo`, and package a universal `.dmg`.
- macOS packaging creates an `.app` bundle with `Info.plist`, native `.icns` metadata generated from the SVG through `rsvg-convert`, and an ad-hoc signature. It is not Developer ID signed or notarized unless the workflow is explicitly extended with Apple credentials.
- Do not put secrets or signing credentials in the repository. Use GitHub Actions secrets for future Apple signing/notarization.
- Release workflow changes should be validated with `git diff --check`, Rust checks/tests, and careful review of shell quoting. The actual AppImage/macOS packaging requires the corresponding GitHub-hosted runner.

## Change and release expectations

- Keep changes focused and avoid unrelated refactors.
- Track all changes in the local Git repository with commits; do not leave completed work uncommitted.
- Create annotated semantic-version tags for releases and push commits/tags only when the user explicitly requests pushing.
- Before committing, run `cargo fmt -- --check`, `cargo check`, and `cargo test` when available.
- Release tags are annotated semantic-version tags. Update the GitHub release workflow/body when release changelogs need to be visible.
