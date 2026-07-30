//! `loom-bundle-tool` — create, sign, and verify offline update bundles.
//!
//! The private signing key is never embedded: `sign --key <path>` reads it from a file, which the
//! release pipeline populates from a secret. `keygen` is for development and for the operator who
//! generates the production keypair **offline** and then only ever hands the pipeline the secret path.
//!
//! ```text
//! loom-bundle-tool keygen --out-secret dev.key --out-public dev.pub
//! loom-bundle-tool sign   --key dev.key --kind policy --id policy-2026-07 --version 3 \
//!                         --in policy.bin --out policy.bundle
//! loom-bundle-tool verify --public dev.pub --in policy.bundle \
//!                         --require-kind policy --require-id policy-2026-07 --require-version 3
//! loom-bundle-tool inspect --in policy.bundle
//! ```

use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, Subcommand};
use loom_bundle::{hex_encode, signing_key_from_hex, verifying_key_from_hex, Bundle, BundleError};

#[derive(Parser)]
#[command(
    name = "loom-bundle-tool",
    about = "Create, sign, and verify offline update bundles"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Generate an Ed25519 keypair (hex). For development, or for generating the production keypair
    /// offline — the secret half is then handed to the pipeline via a path, never committed.
    Keygen {
        /// Where to write the hex signing (private) key. Keep this secret.
        #[arg(long)]
        out_secret: PathBuf,
        /// Where to write the hex verifying (public) key. Safe to distribute.
        #[arg(long)]
        out_public: PathBuf,
    },
    /// Sign a payload into a bundle. The key is read from `--key`, a path the pipeline fills from a secret.
    Sign {
        /// Path to the hex signing key.
        #[arg(long)]
        key: PathBuf,
        /// Stable bundle id (e.g. `policy-2026-07`).
        #[arg(long)]
        id: String,
        /// Kind: license | policy | model-artifact | software | ...
        #[arg(long)]
        kind: String,
        /// The payload's own version string.
        #[arg(long)]
        version: String,
        /// Signing timestamp (ms since epoch). Defaults to now.
        #[arg(long)]
        created_ms: Option<u64>,
        /// Payload file to wrap.
        #[arg(long = "in")]
        input: PathBuf,
        /// Where to write the signed bundle.
        #[arg(long)]
        out: PathBuf,
    },
    /// Verify a bundle and require the exact signed claims approved for this operation.
    Verify {
        /// Path to the hex verifying (public) key.
        #[arg(long)]
        public: PathBuf,
        /// The bundle file.
        #[arg(long = "in")]
        input: PathBuf,
        /// Exact signed bundle id from the approved change record.
        #[arg(long)]
        require_id: String,
        /// Exact signed artifact kind expected at this update door.
        #[arg(long)]
        require_kind: String,
        /// Exact signed version approved for installation.
        #[arg(long)]
        require_version: String,
    },
    /// Print a bundle's manifest without verifying it.
    Inspect {
        /// The bundle file.
        #[arg(long = "in")]
        input: PathBuf,
    },
}

fn main() -> ExitCode {
    match run(Cli::parse()) {
        Ok(()) => ExitCode::SUCCESS,
        Err(msg) => {
            eprintln!("error: {msg}");
            ExitCode::FAILURE
        }
    }
}

fn run(cli: Cli) -> std::result::Result<(), String> {
    match cli.command {
        Command::Keygen {
            out_secret,
            out_public,
        } => {
            let mut seed = [0u8; 32];
            getrandom::getrandom(&mut seed).map_err(|e| format!("generating key material: {e}"))?;
            let signing = ed25519_dalek::SigningKey::from_bytes(&seed);
            let verifying = signing.verifying_key();
            write_file(
                &out_secret,
                &format!("{}\n", hex_encode(signing.to_bytes().as_slice())),
            )?;
            write_file(
                &out_public,
                &format!("{}\n", hex_encode(verifying.as_bytes())),
            )?;
            eprintln!(
                "wrote signing key to {} and public key to {}",
                out_secret.display(),
                out_public.display()
            );
            eprintln!("public key: {}", hex_encode(verifying.as_bytes()));
            Ok(())
        }

        Command::Sign {
            key,
            id,
            kind,
            version,
            created_ms,
            input,
            out,
        } => {
            let key_hex = read_to_string(&key)?;
            let signing = signing_key_from_hex(&key_hex).map_err(describe)?;
            let payload = read_bytes(&input)?;
            let created = match created_ms {
                Some(ms) => ms,
                None => now_ms()?,
            };
            let bundle =
                Bundle::create(id, kind, version, created, payload, &signing).map_err(describe)?;
            let bytes = bundle.to_bytes().map_err(describe)?;
            write_bytes(&out, &bytes)?;
            eprintln!(
                "signed bundle {:?} ({}, version={}) → {} ({} payload bytes, hash {})",
                bundle.manifest.id,
                bundle.manifest.kind,
                bundle.manifest.version,
                out.display(),
                bundle.manifest.payload_len,
                bundle.manifest.payload_blake3,
            );
            Ok(())
        }

        Command::Verify {
            public,
            input,
            require_id,
            require_kind,
            require_version,
        } => {
            let pub_hex = read_to_string(&public)?;
            let verifying = verifying_key_from_hex(&pub_hex).map_err(describe)?;
            let bundle = Bundle::from_bytes(&read_bytes(&input)?).map_err(describe)?;
            bundle
                .verify_for(&verifying, &require_id, &require_kind, &require_version)
                .map_err(describe)?;
            println!(
                "VERIFIED: bundle {:?} kind={} version={} ({} bytes) — safe to apply.",
                bundle.manifest.id,
                bundle.manifest.kind,
                bundle.manifest.version,
                bundle.manifest.payload_len,
            );
            Ok(())
        }

        Command::Inspect { input } => {
            let bundle = Bundle::from_bytes(&read_bytes(&input)?).map_err(describe)?;
            let m = &bundle.manifest;
            println!("format_version : {}", m.format_version);
            println!("id             : {}", m.id);
            println!("kind           : {}", m.kind);
            println!("version        : {}", m.version);
            println!("created_ms     : {}", m.created_ms);
            println!("payload_len    : {}", m.payload_len);
            println!("payload_blake3 : {}", m.payload_blake3);
            println!("(not verified — run `verify --public <key>` to check the signature)");
            Ok(())
        }
    }
}

fn describe(e: BundleError) -> String {
    e.to_string()
}

fn now_ms() -> std::result::Result<u64, String> {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .map_err(|e| format!("reading the clock: {e}"))
}

fn read_to_string(path: &std::path::Path) -> std::result::Result<String, String> {
    std::fs::read_to_string(path).map_err(|e| format!("reading {}: {e}", path.display()))
}

fn read_bytes(path: &std::path::Path) -> std::result::Result<Vec<u8>, String> {
    std::fs::read(path).map_err(|e| format!("reading {}: {e}", path.display()))
}

fn write_file(path: &std::path::Path, contents: &str) -> std::result::Result<(), String> {
    std::fs::write(path, contents).map_err(|e| format!("writing {}: {e}", path.display()))
}

fn write_bytes(path: &std::path::Path, contents: &[u8]) -> std::result::Result<(), String> {
    std::fs::write(path, contents).map_err(|e| format!("writing {}: {e}", path.display()))
}
