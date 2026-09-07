# GPG Wrapper

A small Rust + egui desktop GUI around the system `gpg` binary, available for Linux and macOS.

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

## Availability and requirements

GPG Wrapper is available for:

- Linux
- macOS 12 or later

The only runtime requirement is **GnuPG**, with the `gpg` command available in `PATH`.

### Install GnuPG on Linux

Debian/Ubuntu:

```bash
sudo apt update
sudo apt install gnupg
```

Fedora:

```bash
sudo dnf install gnupg2
```

Arch Linux:

```bash
sudo pacman -S gnupg
```

### Install GnuPG on macOS

Using Homebrew:

```bash
brew install gnupg
```

The macOS release is an unsigned universal `.dmg` containing a binary for both Intel and Apple Silicon Macs. macOS may require opening it through **System Settings → Privacy & Security → Open Anyway**. Code signing and notarization are not included yet.

## Build from source

Building from source additionally requires the Rust toolchain and platform-specific native build dependencies.

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

Clipboard operations use `arboard`. Linux enables its Wayland data-control backend; macOS uses the native macOS clipboard APIs.

### GPG trust

The application intentionally does not add `--trust-model always`. GnuPG therefore keeps its normal trust model and local configuration.

### Secret-key export

Exporting secret keys should be treated as a sensitive operation. Do not copy secret key material into an untrusted clipboard manager or save it to an insecure filesystem.

### Decryption

Decryption may open your normal GPG pinentry dialog if the secret key is passphrase protected.
