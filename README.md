# GPG Wrapper for Linux

A small Rust + egui desktop GUI around the system `gpg` binary.

## Features

- List public keys and detect whether a matching secret key exists.
- Generate keys with GnuPG's `--quick-generate-key`.
- Delete selected public/secret keys.
- Export public or secret keys to clipboard or file.
- Import ASCII-armored/key files from clipboard or file.
- Encrypt text for a selected recipient.
- Decrypt armored ciphertext using the secret keys available to GnuPG.
- Load encryption/decryption input from text, clipboard, or file.
- Copy/save resulting plaintext or ciphertext.

The application does **not** store GPG passphrases. GnuPG and the configured pinentry program handle passphrase prompts.

## Requirements

- Linux
- GnuPG (`gpg`) installed and available in `PATH`
- Rust toolchain (Rust 2024 edition)
- A working desktop session/clipboard

For Debian/Ubuntu, install GPG and the common native build dependencies used by eframe/rfd as appropriate for your distribution, for example:

```bash
sudo apt update
sudo apt install gnupg pkg-config libxcb-render0-dev libxcb-shape0-dev libxcb-xfixes0-dev libxkbcommon-dev libssl-dev
```

## Build

```bash
cargo build --release
```

Run it with:

```bash
cargo run --release
```

The release binary will be at:

```text
target/release/gpg-wrapper
```

## Notes

### Clipboard

Clipboard operations use `arboard`. The Cargo manifest enables its Wayland data-control backend, while keeping its Linux X11/XWayland support available.

### GPG trust

The application intentionally does not add `--trust-model always`. GnuPG therefore keeps its normal trust model and local configuration.

### Secret-key export

Exporting secret keys should be treated as a sensitive operation. Do not copy secret key material into an untrusted clipboard manager or save it to an insecure filesystem.

### Decryption

Decryption may open your normal GPG pinentry dialog if the secret key is passphrase protected.
