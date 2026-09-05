use anyhow::{Context, Result, anyhow};
use arboard::Clipboard;
use eframe::egui;
use rfd::{FileDialog, MessageButtons, MessageDialog, MessageLevel};
use std::fs;
use std::process::{Command, Output};

#[derive(Clone, Debug)]
struct Key {
    fingerprint: String,
    uid: String,
    created: String,
    expires: String,
    key_type: String,
    capabilities: String,
    secret: bool,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum KeyMaterial {
    Public,
    Secret,
}

impl KeyMaterial {
    fn label(self) -> &'static str {
        match self {
            Self::Public => "Public",
            Self::Secret => "Private / Secret",
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum InputSource {
    Text,
    Clipboard,
    File,
}

impl InputSource {
    fn label(self) -> &'static str {
        match self {
            Self::Text => "Text field",
            Self::Clipboard => "Clipboard",
            Self::File => "File",
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum CryptoAction {
    Encrypt,
    Decrypt,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum KeyAlgorithm {
    Rsa2048,
    Rsa3072,
    Rsa4096,
    Ed25519,
    Default,
}

impl KeyAlgorithm {
    fn label(self) -> &'static str {
        match self {
            Self::Rsa2048 => "RSA 2048-bit",
            Self::Rsa3072 => "RSA 3072-bit",
            Self::Rsa4096 => "RSA 4096-bit",
            Self::Ed25519 => "Ed25519 + Curve25519",
            Self::Default => "GnuPG default",
        }
    }

    // --quick-generate-key only creates a primary key when an explicit
    // algorithm is supplied. To keep encryption working, we instead set
    // --default-new-key-algo for this one invocation and ask quick-gen-key
    // for the default key layout (primary + encryption subkey).
    fn default_new_key_algo(self) -> &'static str {
        match self {
            Self::Rsa2048 => "rsa2048/cert,sign+rsa2048/encr",
            Self::Rsa3072 => "rsa3072/cert,sign+rsa3072/encr",
            Self::Rsa4096 => "rsa4096/cert,sign+rsa4096/encr",
            Self::Ed25519 => "ed25519/cert,sign+cv25519/encr",
            // Explicitly request GnuPG's normal cert/sign primary and
            // encryption-capable subkey layout instead of relying on the
            // user's configured default-new-key-algo.
            Self::Default => "default",
        }
    }
}

struct GpgApp {
    keys: Vec<Key>,
    selected_fpr: Option<String>,
    pending_delete_fpr: Option<String>,
    key_material: KeyMaterial,

    crypto_action: CryptoAction,
    crypto_source: InputSource,
    crypto_text: String,

    name: String,
    email: String,
    algorithm: KeyAlgorithm,
    expiration: String,

    status: String,
    error: Option<String>,
}

impl Default for GpgApp {
    fn default() -> Self {
        let mut app = Self {
            keys: Vec::new(),
            selected_fpr: None,
            pending_delete_fpr: None,
            key_material: KeyMaterial::Public,
            crypto_action: CryptoAction::Encrypt,
            crypto_source: InputSource::Text,
            crypto_text: String::new(),
            name: String::new(),
            email: String::new(),
            algorithm: KeyAlgorithm::Rsa3072,
            expiration: "2y".to_owned(),

            status: "Ready".to_owned(),
            error: None,
        };
        app.refresh_keys();
        app
    }
}

impl GpgApp {
    fn refresh_keys(&mut self) {
        match list_keys() {
            Ok(keys) => {
                let keep = self.selected_fpr.clone();
                self.keys = keys;
                self.selected_fpr = keep.filter(|f| self.keys.iter().any(|k| &k.fingerprint == f));
                if self.selected_fpr.is_none() {
                    self.selected_fpr = self.keys.first().map(|k| k.fingerprint.clone());
                }
                self.status = format!("Loaded {} key(s)", self.keys.len());
                self.error = None;
            }
            Err(e) => self.set_error(e),
        }
    }

    fn set_error(&mut self, e: impl std::fmt::Display) {
        self.error = Some(e.to_string());
        self.status = "Operation failed".to_owned();
    }

    fn selected_key(&self) -> Result<&Key> {
        let fpr = self
            .selected_fpr
            .as_deref()
            .ok_or_else(|| anyhow!("Select a key first"))?;
        self.keys
            .iter()
            .find(|k| k.fingerprint == fpr)
            .ok_or_else(|| anyhow!("Selected key no longer exists; refresh the key list"))
    }

    fn generate_key(&mut self) {
        let uid = build_uid(&self.name, &self.email);
        if uid.is_empty() {
            self.set_error(anyhow!("Enter at least a name or an email address"));
            return;
        }
        let expiration = if self.expiration.trim().is_empty() {
            "none"
        } else {
            self.expiration.trim()
        };

        let result = if self.algorithm == KeyAlgorithm::Default {
            gpg_run(&[
                "--default-new-key-algo",
                "default/cert,sign+default/encr",
                "--quick-generate-key",
                &uid,
                "default",
                "default",
                expiration,
            ])
        } else {
            gpg_run(&[
                "--default-new-key-algo",
                self.algorithm.default_new_key_algo(),
                "--quick-generate-key",
                &uid,
                "default",
                "default",
                expiration,
            ])
        };

        match result {
            Ok(_) => {
                self.status = format!("Key generation started/completed for {uid}");
                self.error = None;
                self.refresh_keys();
            }
            Err(e) => self.set_error(e),
        }
    }

    fn request_delete_selected(&mut self) {
        let (fingerprint, uid) = match self.selected_key() {
            Ok(key) => (key.fingerprint.clone(), key.uid.clone()),
            Err(e) => {
                self.set_error(e);
                return;
            }
        };

        self.pending_delete_fpr = Some(fingerprint);
        self.error = None;
        self.status = format!("Confirm deletion of {uid}");
    }

    fn confirm_delete(&mut self) {
        let fpr = match self.pending_delete_fpr.clone() {
            Some(fpr) => fpr,
            None => return,
        };

        let key = match self.keys.iter().find(|k| k.fingerprint == fpr) {
            Some(k) => k.clone(),
            None => {
                self.pending_delete_fpr = None;
                self.set_error(anyhow!(
                    "Selected key no longer exists; refresh the key list"
                ));
                return;
            }
        };

        let result = if key.secret {
            gpg_run(&[
                "--batch",
                "--yes",
                "--delete-secret-and-public-key",
                &key.fingerprint,
            ])
        } else {
            gpg_run(&["--batch", "--yes", "--delete-key", &key.fingerprint])
        };

        match result {
            Ok(_) => {
                self.pending_delete_fpr = None;
                self.status = format!("Deleted {}", key.uid);
                self.error = None;
                self.refresh_keys();
            }
            Err(e) => {
                self.pending_delete_fpr = None;
                self.set_error(e);
            }
        }
    }

    fn export_selected(&mut self) {
        let key = match self.selected_key() {
            Ok(k) => k.clone(),
            Err(e) => {
                self.set_error(e);
                return;
            }
        };

        let data = match self.key_material {
            KeyMaterial::Public => export_public(&key.fingerprint),
            KeyMaterial::Secret => export_secret(&key.fingerprint),
        };

        match data {
            Ok(bytes) => {
                match std::str::from_utf8(&bytes)
                    .context("Exported key is not valid UTF-8 text")
                    .and_then(clipboard_set)
                {
                    Ok(()) => {
                        self.status = format!(
                            "Exported {} key to clipboard for {}",
                            self.key_material.label(),
                            key.uid
                        );
                        self.error = None;
                    }
                    Err(e) => self.set_error(e),
                }
            }
            Err(e) => self.set_error(e),
        }
    }

    fn export_selected_to_file(&mut self) {
        let key = match self.selected_key() {
            Ok(k) => k.clone(),
            Err(e) => {
                self.set_error(e);
                return;
            }
        };
        let data = match self.key_material {
            KeyMaterial::Public => export_public(&key.fingerprint),
            KeyMaterial::Secret => export_secret(&key.fingerprint),
        };
        match data.and_then(|bytes| {
            let Some(path) = FileDialog::new()
                .set_file_name("key.asc")
                .add_filter("ASCII armored key", &["asc"])
                .save_file()
            else {
                return Ok(());
            };
            fs::write(&path, bytes).with_context(|| format!("Could not write {}", path.display()))
        }) {
            Ok(()) => {
                self.status = format!("Exported {} key to file", self.key_material.label());
                self.error = None;
            }
            Err(e) => self.set_error(e),
        }
    }

    fn import_from_clipboard(&mut self) {
        match clipboard_get().and_then(|text| {
            // Preserve the armored key exactly as read from the clipboard.
            // Clipboard providers may omit only the final line ending.
            let text = format!("{}\n", text.trim_end());
            let temp = std::env::temp_dir().join("gpg-wrapper-import.asc");
            fs::write(&temp, text.as_bytes())
                .with_context(|| format!("Could not write {}", temp.display()))?;
            let result = gpg_run(&["--import", temp.to_str().unwrap_or_default()]);
            let _ = fs::remove_file(&temp);
            match result {
                Ok(output) => Ok(output),
                Err(error)
                    if error.to_string().contains("public key")
                        && error.to_string().contains("imported") =>
                {
                    Ok(CommandOutput {
                        stdout_text: String::new(),
                        stderr_text: String::new(),
                    })
                }
                Err(error) => Err(error),
            }
        }) {
            Ok(_) => {
                self.status = "Imported key from clipboard".to_owned();
                self.error = None;
                self.refresh_keys();
            }
            Err(e) => self.set_error(e),
        }
    }

    fn import_from_file(&mut self) {
        let Some(path) = FileDialog::new()
            .add_filter("GPG / ASCII armored", &["asc", "gpg", "pgp"])
            .pick_file()
        else {
            return;
        };

        match fs::read(&path)
            .with_context(|| format!("Could not read {}", path.display()))
            .and_then(|data| gpg_run_with_stdin(&["--import"], &data))
        {
            Ok(_) => {
                self.status = format!("Imported key from {}", path.display());
                self.error = None;
                self.refresh_keys();
            }
            Err(e) => self.set_error(e),
        }
    }

    fn load_crypto_input(&mut self) {
        match self.crypto_source {
            InputSource::Text => {}
            InputSource::Clipboard => match clipboard_get() {
                Ok(text) => self.crypto_text = text,
                Err(e) => self.set_error(e),
            },
            InputSource::File => {
                let Some(path) = FileDialog::new().pick_file() else {
                    return;
                };
                match fs::read_to_string(&path) {
                    Ok(text) => self.crypto_text = text,
                    Err(e) => self.set_error(anyhow!("Read {}: {e}", path.display())),
                }
            }
        }
    }

    fn run_crypto(&mut self) {
        match self.crypto_action {
            CryptoAction::Encrypt => self.encrypt(),
            CryptoAction::Decrypt => self.decrypt(),
        }
    }

    fn encrypt(&mut self) {
        let input = self.crypto_text.clone();
        if input.is_empty() {
            self.set_error(anyhow!(
                "Enter a message or load one from the clipboard/file"
            ));
            return;
        }
        let key = match self.selected_key() {
            Ok(k) => k.clone(),
            Err(e) => {
                self.set_error(e);
                return;
            }
        };

        let result = gpg_run_with_stdin(
            &["--armor", "--encrypt", "--recipient", &key.fingerprint],
            input.as_bytes(),
        );

        match result {
            Ok(out) => {
                self.crypto_text = out.stdout_text;
                self.status = format!("Encrypted for {}", key.uid);
                self.error = None;
                if matches!(self.crypto_source, InputSource::Clipboard) {
                    if let Err(e) = clipboard_set(&self.crypto_text) {
                        self.set_error(e);
                    } else {
                        self.status.push_str(" and copied to clipboard");
                    }
                }
            }
            Err(e) => self.set_error(e),
        }
    }

    fn decrypt(&mut self) {
        let input = self.crypto_text.clone();
        if input.is_empty() {
            self.set_error(anyhow!(
                "Enter armored ciphertext or load it from the clipboard/file"
            ));
            return;
        }

        match gpg_run_with_stdin(&["--decrypt"], input.as_bytes()) {
            Ok(out) => {
                self.crypto_text = out.stdout_text;
                self.status = "Decrypted message".to_owned();
                self.error = None;
                if matches!(self.crypto_source, InputSource::Clipboard) {
                    if let Err(e) = clipboard_set(&self.crypto_text) {
                        self.set_error(e);
                    } else {
                        self.status.push_str(" and copied to clipboard");
                    }
                }
            }
            Err(e) => self.set_error(e),
        }
    }

    fn copy_crypto_output(&mut self) {
        match clipboard_set(&self.crypto_text) {
            Ok(()) => {
                self.status = "Copied text to clipboard".to_owned();
                self.error = None;
            }
            Err(e) => self.set_error(e),
        }
    }

    fn save_crypto_output(&mut self) {
        let Some(path) = FileDialog::new()
            .set_file_name(match self.crypto_action {
                CryptoAction::Encrypt => "encrypted.asc",
                CryptoAction::Decrypt => "decrypted.txt",
            })
            .save_file()
        else {
            return;
        };

        match fs::write(&path, self.crypto_text.as_bytes()) {
            Ok(()) => {
                self.status = format!("Saved {}", path.display());
                self.error = None;
            }
            Err(e) => self.set_error(anyhow!("Write {}: {e}", path.display())),
        }
    }
}

impl eframe::App for GpgApp {
    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        // eframe/egui 0.36 uses App::ui(&mut Ui, ...) rather than the older
        // App::update(&Context, ...) API. Panels are also no longer shown from
        // a Context here, so we build the full application inside this Ui.
        ui.horizontal(|ui| {
            ui.heading("GPG Wrapper");
            ui.separator();
            ui.label("Linux desktop frontend for GnuPG");
        });
        ui.separator();

        egui::ScrollArea::vertical().show(ui, |ui| {
            ui.columns(2, |cols| {
                // Left: key management
                cols[0].heading("Keys");
                cols[0].horizontal(|ui| {
                    if ui.button("↻ Refresh").clicked() {
                        self.refresh_keys();
                    }
                    if self.pending_delete_fpr.is_some() {
                        if ui.button("Confirm delete").clicked() {
                            self.confirm_delete();
                        }
                        if ui.button("Cancel").clicked() {
                            self.pending_delete_fpr = None;
                            self.status = "Deletion cancelled".to_owned();
                        }
                    } else if ui.button("Delete selected").clicked() {
                        self.request_delete_selected();
                    }
                });

                if let Some(fpr) = &self.pending_delete_fpr {
                    if let Some(key) = self.keys.iter().find(|k| &k.fingerprint == fpr) {
                        cols[0].colored_label(
                            egui::Color32::from_rgb(180, 40, 40),
                            format!("Warning: deleting \"{}\" cannot be undone.", key.uid),
                        );
                    }
                }
                cols[0].add_space(6.0);
                let keys = self.keys.clone();
                egui::ScrollArea::vertical()
                    .id_salt("key_list")
                    .max_height(280.0)
                    .show(&mut cols[0], |ui| {
                        if keys.is_empty() {
                            ui.label("No GPG keys found.");
                        }

                        for key in &keys {
                            let selected = self.selected_fpr.as_deref() == Some(key.fingerprint.as_str());
                            let expires = if key.expires.is_empty() {
                                String::new()
                            } else {
                                format!("  •  Exp: {}", key.expires)
                            };
                            let label = format!(
                                "{}\n{}\n{}{}",
                                key.uid,
                                short_fingerprint(&key.fingerprint),
                                if key.secret { "Secret: yes" } else { "Secret: no" },
                                expires,
                            );
                            let response = ui.selectable_label(selected, label);
                            if response.clicked() {
                                self.selected_fpr = Some(key.fingerprint.clone());
                            }
                            ui.separator();
                        }
                    });

                cols[0].separator();
                cols[0].heading("Generate key");
                cols[0].label("Name or UID");
                cols[0].text_edit_singleline(&mut self.name);
                cols[0].label("Email (optional)");
                cols[0].text_edit_singleline(&mut self.email);
                cols[0].horizontal(|ui| {
                    ui.label("Algorithm");
                    egui::ComboBox::from_id_salt("key_algorithm")
                        .selected_text(self.algorithm.label())
                        .show_ui(ui, |ui| {
                            ui.selectable_value(&mut self.algorithm, KeyAlgorithm::Rsa2048, "RSA 2048-bit");
                            ui.selectable_value(&mut self.algorithm, KeyAlgorithm::Rsa3072, "RSA 3072-bit");
                            ui.selectable_value(&mut self.algorithm, KeyAlgorithm::Rsa4096, "RSA 4096-bit");
                            ui.selectable_value(&mut self.algorithm, KeyAlgorithm::Ed25519, "Ed25519 + Curve25519");
                            ui.selectable_value(&mut self.algorithm, KeyAlgorithm::Default, "GnuPG default");
                        });
                });
                cols[0].horizontal(|ui| {
                    ui.label("Expiration");
                    ui.text_edit_singleline(&mut self.expiration);
                });
                cols[0].small("RSA choices create a matching encryption subkey; Ed25519 uses Curve25519 for encryption.");
                cols[0].small("Examples: 1y, 2y, 90d, never");
                if cols[0].button("Generate key").clicked() {
                    self.generate_key();
                }

                cols[0].separator();
                cols[0].heading("Import / export");
                cols[0].label("Import");
                cols[0].horizontal(|ui| {
                    if ui.button("Import from clipboard").clicked() {
                        self.import_from_clipboard();
                    }
                    if ui.button("Import from file").clicked() {
                        self.import_from_file();
                    }
                });
                cols[0].separator();
                cols[0].label("Export selected key");
                let has_secret_key = self.selected_fpr.as_deref().and_then(|fpr| {
                    self.keys.iter().find(|key| key.fingerprint == fpr)
                }).is_some_and(|key| key.secret);
                cols[0].horizontal(|ui| {
                    ui.radio_value(&mut self.key_material, KeyMaterial::Public, "Public");
                    ui.add_enabled_ui(has_secret_key, |ui| {
                        ui.radio_value(&mut self.key_material, KeyMaterial::Secret, "Private / Secret");
                    });
                });
                if !has_secret_key && self.key_material == KeyMaterial::Secret {
                    self.key_material = KeyMaterial::Public;
                }
                cols[0].horizontal(|ui| {
                    if ui.button("Export to clipboard").clicked() {
                        self.export_selected();
                    }
                    if ui.button("Export to file").clicked() {
                        self.export_selected_to_file();
                    }
                });

                // Right: crypto
                cols[1].heading("Encrypt / decrypt");
                cols[1].horizontal(|ui| {
                    ui.radio_value(&mut self.crypto_action, CryptoAction::Encrypt, "Encrypt");
                    ui.radio_value(&mut self.crypto_action, CryptoAction::Decrypt, "Decrypt");
                });
                cols[1].horizontal(|ui| {
                    ui.label("Input");
                    egui::ComboBox::from_id_salt("source")
                        .selected_text(self.crypto_source.label())
                        .show_ui(ui, |ui| {
                            ui.selectable_value(&mut self.crypto_source, InputSource::Text, "Text field");
                            ui.selectable_value(&mut self.crypto_source, InputSource::Clipboard, "Clipboard");
                            ui.selectable_value(&mut self.crypto_source, InputSource::File, "File");
                        });
                    if !matches!(self.crypto_source, InputSource::Text) && ui.button("Load input").clicked() {
                        self.load_crypto_input();
                    }
                });

                if self.crypto_action == CryptoAction::Encrypt {
                    if let Ok(key) = self.selected_key() {
                        cols[1].label(format!(
                            "Recipient: {} ({})",
                            key.uid,
                            short_fingerprint(&key.fingerprint)
                        ));
                    } else {
                        cols[1].label("Recipient: select a key in the key list");
                    }
                } else {
                    cols[1].label("Decrypt uses available secret keys via GnuPG/pinentry");
                }

                cols[1].add_sized(
                    [cols[1].available_width(), 340.0],
                    egui::TextEdit::multiline(&mut self.crypto_text)
                        .hint_text("Paste or type plaintext/ciphertext here…")
                        .code_editor(),
                );

                cols[1].horizontal(|ui| {
                    if ui
                        .button(match self.crypto_action {
                            CryptoAction::Encrypt => "Encrypt",
                            CryptoAction::Decrypt => "Decrypt",
                        })
                        .clicked()
                    {
                        self.run_crypto();
                    }
                    if ui.button("Copy output").clicked() {
                        self.copy_crypto_output();
                    }
                    if ui.button("Save output").clicked() {
                        self.save_crypto_output();
                    }
                });

                cols[1].separator();
                cols[1].small("The app never asks for or stores your GPG passphrase. GnuPG invokes the configured pinentry program when needed.");
                cols[1].small("Exporting secret keys is sensitive: store them only where you trust the destination.");
            });
        });

        ui.separator();
        if let Some(err) = &self.error {
            ui.colored_label(egui::Color32::from_rgb(180, 40, 40), err);
        } else {
            ui.label(&self.status);
        }
    }
}

fn build_uid(name: &str, email: &str) -> String {
    let name = name.trim();
    let email = email.trim();
    match (name.is_empty(), email.is_empty()) {
        (false, false) => format!("{name} <{email}>"),
        (false, true) => name.to_owned(),
        (true, false) => email.to_owned(),
        (true, true) => String::new(),
    }
}

fn short_fingerprint(fpr: &str) -> String {
    if fpr.len() <= 20 {
        return fpr.to_owned();
    }
    format!("{}…{}", &fpr[..10], &fpr[fpr.len() - 10..])
}

fn gpg_command() -> Command {
    let mut cmd = Command::new("gpg");
    cmd.env("LC_ALL", "C");
    cmd.env("LANG", "C");
    cmd
}

fn gpg_run(args: &[&str]) -> Result<CommandOutput> {
    let output = gpg_command()
        .args(args)
        .output()
        .with_context(|| "Could not start 'gpg'. Is GnuPG installed and in PATH?")?;
    parse_output(output)
}

fn gpg_run_with_stdin(args: &[&str], stdin_data: &[u8]) -> Result<CommandOutput> {
    use std::io::Write;
    let mut child = gpg_command()
        .args(args)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .with_context(|| "Could not start 'gpg'. Is GnuPG installed and in PATH?")?;

    if let Some(mut stdin) = child.stdin.take() {
        stdin.write_all(stdin_data)?;
    }
    let output = child.wait_with_output()?;
    parse_output(output)
}

struct CommandOutput {
    stdout_text: String,
    stderr_text: String,
}

fn parse_output(output: Output) -> Result<CommandOutput> {
    let stdout_text = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr_text = String::from_utf8_lossy(&output.stderr).to_string();
    if !output.status.success() {
        let detail = if stderr_text.trim().is_empty() {
            stdout_text.trim().to_owned()
        } else {
            stderr_text.trim().to_owned()
        };
        return Err(anyhow!("GPG failed ({}): {}", output.status, detail));
    }
    Ok(CommandOutput {
        stdout_text,
        stderr_text,
    })
}

fn list_keys() -> Result<Vec<Key>> {
    // --with-colons is the script-friendly machine-readable format documented by GnuPG.
    // We list public keys and separately collect secret-key fingerprints.
    let public = gpg_run(&["--with-colons", "--fixed-list-mode", "--list-keys"])?;
    let secret = gpg_run(&["--with-colons", "--fixed-list-mode", "--list-secret-keys"])?;

    let secret_fprs = parse_secret_fprs(&secret.stdout_text);
    Ok(parse_public_keys(&public.stdout_text, &secret_fprs))
}

fn parse_secret_fprs(s: &str) -> std::collections::HashSet<String> {
    s.lines()
        .filter_map(|line| {
            let fields: Vec<&str> = line.split(':').collect();
            (fields.first().copied() == Some("fpr"))
                .then(|| fields.get(9).copied().unwrap_or_default().to_owned())
        })
        .filter(|f| !f.is_empty())
        .collect()
}

fn parse_public_keys(s: &str, secret_fprs: &std::collections::HashSet<String>) -> Vec<Key> {
    let mut keys = Vec::new();
    let mut current: Option<Key> = None;

    for line in s.lines() {
        let fields: Vec<&str> = line.split(':').collect();
        match fields.first().copied().unwrap_or_default() {
            "pub" => {
                if let Some(key) = current.take() {
                    keys.push(key);
                }
                let key_length = fields.get(2).copied().unwrap_or_default();
                let key_type = fields.get(3).copied().unwrap_or_default();
                let created = fields.get(5).copied().unwrap_or_default().to_owned();
                let expires = fields.get(6).copied().unwrap_or_default().to_owned();
                let capabilities = fields.get(11).copied().unwrap_or_default().to_owned();
                current = Some(Key {
                    fingerprint: String::new(),
                    uid: format!("{}-bit key", key_length),
                    created,
                    expires,
                    key_type: key_type.to_owned(),
                    capabilities,
                    secret: false,
                });
            }
            "fpr" => {
                if let Some(key) = current.as_mut() {
                    if key.fingerprint.is_empty() {
                        key.fingerprint = fields.get(9).copied().unwrap_or_default().to_owned();
                        key.secret = secret_fprs.contains(&key.fingerprint);
                    }
                }
            }
            "uid" => {
                if let Some(key) = current.as_mut() {
                    let uid = fields.get(9).copied().unwrap_or_default();
                    if !uid.is_empty() {
                        key.uid = decode_gpg_colon_field(uid);
                    }
                }
            }
            _ => {}
        }
    }
    if let Some(key) = current.take() {
        keys.push(key);
    }

    // Only show entries that have a fingerprint. This avoids presenting malformed records.
    keys.into_iter()
        .filter(|k| !k.fingerprint.is_empty())
        .collect()
}

fn decode_gpg_colon_field(s: &str) -> String {
    // GnuPG colon output uses backslash-escaped hexadecimal bytes for special characters.
    // Decode those bytes first, then interpret the result as UTF-8.
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'\\' && i + 2 < bytes.len() {
            if let Ok(v) = u8::from_str_radix(&s[i + 1..i + 3], 16) {
                out.push(v);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn export_public(fpr: &str) -> Result<Vec<u8>> {
    let out = gpg_command()
        .args(["--armor", "--no-options", "--export", fpr])
        .output()
        .with_context(|| format!("Could not run `gpg --armor --export {fpr}`"))?;
    if !out.status.success() {
        return Err(anyhow!(
            "GPG export failed: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        ));
    }

    // Return GnuPG's stdout unchanged. It already contains the complete
    // ASCII-armored block and must retain its real newline bytes.
    Ok(out.stdout)
}

fn normalize_armored_key(text: &str) -> Result<String> {
    let normalized = text
        .replace("\\r\\n", "\n")
        .replace("\\\\n", "\n")
        .replace("\\n", "\n")
        .replace("\r\n", "\n")
        .replace('\r', "\n");
    let normalized = normalized.replace('\\', "");
    let begin = normalized
        .find("-----BEGIN PGP PUBLIC KEY BLOCK-----")
        .ok_or_else(|| anyhow!("Clipboard does not contain a public PGP key"))?;
    let content_start = begin + "-----BEGIN PGP PUBLIC KEY BLOCK-----".len();
    let end_marker = "-----END PGP PUBLIC KEY BLOCK-----";
    let end = normalized[content_start..]
        .find(end_marker)
        .map(|offset| content_start + offset + end_marker.len())
        .ok_or_else(|| anyhow!("Clipboard contains an incomplete public PGP key"))?;
    let body = normalized[content_start..end - end_marker.len()]
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .map(|line| line.strip_suffix('\\').unwrap_or(line))
        .collect::<Vec<_>>()
        .join("\n");
    Ok(format!(
        "-----BEGIN PGP PUBLIC KEY BLOCK-----\n{body}\n{end_marker}\n"
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[allow(dead_code)]
    fn normalizes_literal_newlines_and_imports_test_key() {
        let input = "-----BEGIN PGP PUBLIC KEY BLOCK-----\\nmDMEapqvlhYJKwYBBAHaRw8BAQdAj7MK7Tsu+psAzW41qpXfK6bDtFY/uw7ms4VW\\nFu4siwi0BHRlc3SIkAQTFgoAOBYhBOZR33x70HvYIh6sOSBGsrBsAfikBQJqmq+W\\nAhsDBQsJCAcCBhUKCQgLAgQWAgMBAh4BAheAAAoJECBGsrBsAfik2pYBAIf4EQd7\\nozreP8t7MMnlCmNCpuUDI8j1/I2W85f56FZ2AP4l1R+UJg8W/bgRzpCcepvMRPsT\\nN3ylZiNCUl9q/VMbCLg4BGqar5YSCisGAQQBl1UBBQEBB0AYB3GfmAjnQLe3Ub+w\\ntSjFKF0hrKYS5qmDs8XBQhSIEwMBCAeIeAQYFgoAIBYhBOZR33x70HvYIh6sOSBG\\nsrBsAfikBQJqmq+WAhsMAAoJECBGsrBsAfikFD0A/i7zqg1K2HiJ+tSe1sD3Hcoh\\nvHoJ7jcU5kH9jiZm4IayAP41V/gb3FPiT6ewS1uErJmRIQCNiyKeK6Ra3pqxh8DY\\nCA==\\n=DsIk\\n-----END PGP PUBLIC KEY BLOCK-----";
        let normalized = normalize_armored_key(input).unwrap();
        assert!(normalized.starts_with("-----BEGIN PGP PUBLIC KEY BLOCK-----\n"));
        assert!(normalized.ends_with("-----END PGP PUBLIC KEY BLOCK-----\n"));
        assert!(!normalized.contains("\\\\n"));
    }

    #[test]
    fn exported_test_key_imports_back_into_gpg() {
        let home = std::env::temp_dir().join(format!("gpg-wrapper-test-{}", std::process::id()));
        let _ = fs::remove_dir_all(&home);
        fs::create_dir_all(&home).unwrap();
        let old_home = std::env::var_os("GNUPGHOME");
        unsafe {
            std::env::set_var("GNUPGHOME", &home);
        }
        let result = (|| -> Result<()> {
            gpg_run(&[
                "--batch",
                "--pinentry-mode",
                "loopback",
                "--passphrase",
                "",
                "--quick-generate-key",
                "test",
                "ed25519",
                "cert,sign",
                "1d",
            ])?;
            let fpr = gpg_run(&["--with-colons", "--list-keys", "test"])?
                .stdout_text
                .lines()
                .find_map(|line| {
                    let fields: Vec<_> = line.split(':').collect();
                    (fields.first() == Some(&"fpr"))
                        .then(|| fields.get(9).unwrap_or(&"").to_string())
                })
                .ok_or_else(|| anyhow!("test key fingerprint not found"))?;
            let exported = export_public(&fpr)?;
            let imported_home = home.with_extension("import");
            fs::create_dir_all(&imported_home)?;
            unsafe {
                std::env::set_var("GNUPGHOME", &imported_home);
            }
            gpg_run_with_stdin(&["--import"], &exported)?;
            Ok(())
        })();
        if let Some(value) = old_home {
            unsafe {
                std::env::set_var("GNUPGHOME", value);
            }
        } else {
            unsafe {
                std::env::remove_var("GNUPGHOME");
            }
        }
        let _ = fs::remove_dir_all(&home);
        let _ = fs::remove_dir_all(home.with_extension("import"));
        result.unwrap();
    }
}

fn export_secret(fpr: &str) -> Result<Vec<u8>> {
    let out = gpg_command()
        .args(["--armor", "--export-secret-keys", fpr])
        .output()
        .context("Could not start gpg")?;
    if !out.status.success() {
        return Err(anyhow!(
            "GPG secret-key export failed: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        ));
    }
    Ok(out.stdout)
}

fn clipboard_get() -> Result<String> {
    let mut clipboard = Clipboard::new().context("Could not access the system clipboard")?;
    clipboard
        .get_text()
        .context("Clipboard does not contain UTF-8 text")
}

fn clipboard_set(text: &str) -> Result<()> {
    let mut clipboard = Clipboard::new().context("Could not access the system clipboard")?;
    clipboard
        .set_text(text.to_owned())
        .context("Could not write to clipboard")?;
    Ok(())
}

#[allow(dead_code)]
fn write_or_clipboard(data: &[u8], title: &str) -> Result<()> {
    let text = std::str::from_utf8(data)
        .context("Exported key is not UTF-8 text")?
        .to_owned();
    let answer = MessageDialog::new()
        .set_level(MessageLevel::Info)
        .set_title(title)
        .set_description(
            "The exported key will be copied to the clipboard. Yes = save a file, No = cancel",
        )
        .set_buttons(MessageButtons::YesNo)
        .show();

    match answer {
        rfd::MessageDialogResult::Yes => {
            let Some(path) = FileDialog::new()
                .set_file_name("key.asc")
                .add_filter("ASCII armored key", &["asc"])
                .save_file()
            else {
                return Ok(());
            };
            fs::write(&path, text.as_bytes())
                .with_context(|| format!("Could not write {}", path.display()))
        }
        rfd::MessageDialogResult::No => {
            clipboard_set(&text)?;
            Ok(())
        }
        rfd::MessageDialogResult::Cancel => Ok(()),
        _ => Ok(()),
    }
}

fn main() -> eframe::Result {
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_title("GPG Wrapper")
            .with_min_inner_size([900.0, 650.0]),
        ..Default::default()
    };

    eframe::run_native(
        "gpg-wrapper",
        options,
        Box::new(|_cc| Ok(Box::new(GpgApp::default()))),
    )
}
