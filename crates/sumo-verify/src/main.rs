//! `sumo-verify` — bank IVD signature validator for external secure boot.
//!
//! After every OTA install the staged bank carries
//! `ivd-manifest.cbor` + `ivd-signature.bin` — produced by the HSM's
//! `ivd-signing` key when content lands in the bank dir. Before any
//! component launches, the secure-boot stage runs this CLI:
//!
//! ```text
//! sumo-verify --bank /persist/banks/vm2/bank_a \
//!             --keystore /var/lib/hsm/keystore \
//!             --expect-bank-id vm2/bank_a
//! ```
//!
//! Exit codes:
//!   0  — manifest signature verifies AND every claimed file hashes
//!         match. Safe to launch.
//!   1  — verification failed (bad sig, tampered file, missing file,
//!         unexpected file, bank_id mismatch, ...). DO NOT launch.
//!   2  — usage / setup error (missing args, missing keystore, ...).
//!         The verifier couldn't run; treat as launch-blocking.
//!
//! On managed-cvc (no real secure boot), `start-managed.sh` runs this
//! after `supernova` comes up, once per VM bank; only the banks that
//! exit 0 get a corresponding `POST /vm/<id>/start`. See
//! `tasks/qnx-sumo-ctl-resmgr-backend.md` follow-up for the integration.

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use hsm::ivd;
use hsm::sim::SimHsm;

const EXIT_OK: u8 = 0;
const EXIT_VERIFY_FAIL: u8 = 1;
const EXIT_USAGE: u8 = 2;

fn usage() {
    eprintln!(
        "\
sumo-verify — validate a staged bank's IVD signature

Usage:
  sumo-verify --bank <dir> --keystore <dir> [--expect-bank-id <id>] [--quiet]

Arguments:
  --bank <dir>            Bank directory to verify (contains
                          ivd-manifest.cbor + ivd-signature.bin and
                          the payload files they cover).
  --keystore <dir>        HSM keystore root — same path supernova
                          uses. SimHsm reads the ivd-signing public
                          half from <keystore>/keys/ivd-signing.pub.
  --expect-bank-id <id>   Pin the manifest's `bank_id` field. Set
                          this when the caller knows which bank is
                          being verified (e.g. \"vm2/bank_a\") so a
                          valid sig from a different bank can't be
                          replayed against this slot.
  --quiet                 Suppress the success line on stdout. The
                          exit code still tells the caller what
                          happened.

Exit codes:
  0  verification passed (safe to launch)
  1  verification failed (DO NOT launch)
  2  usage / setup error",
    );
}

struct Args {
    bank: PathBuf,
    keystore: PathBuf,
    expect_bank_id: Option<String>,
    quiet: bool,
}

fn parse_args(argv: Vec<String>) -> Result<Args, ExitCode> {
    let mut bank: Option<PathBuf> = None;
    let mut keystore: Option<PathBuf> = None;
    let mut expect_bank_id: Option<String> = None;
    let mut quiet = false;

    let mut i = 1;
    while i < argv.len() {
        match argv[i].as_str() {
            "--bank" => {
                i += 1;
                bank = argv.get(i).map(PathBuf::from);
                if bank.is_none() {
                    usage();
                    eprintln!("\nerror: --bank requires a path");
                    return Err(ExitCode::from(EXIT_USAGE));
                }
            }
            "--keystore" => {
                i += 1;
                keystore = argv.get(i).map(PathBuf::from);
                if keystore.is_none() {
                    usage();
                    eprintln!("\nerror: --keystore requires a path");
                    return Err(ExitCode::from(EXIT_USAGE));
                }
            }
            "--expect-bank-id" => {
                i += 1;
                expect_bank_id = argv.get(i).cloned();
                if expect_bank_id.is_none() {
                    usage();
                    eprintln!("\nerror: --expect-bank-id requires a value");
                    return Err(ExitCode::from(EXIT_USAGE));
                }
            }
            "--quiet" => quiet = true,
            "--help" | "-h" => {
                usage();
                return Err(ExitCode::SUCCESS);
            }
            other => {
                usage();
                eprintln!("\nerror: unknown argument '{other}'");
                return Err(ExitCode::from(EXIT_USAGE));
            }
        }
        i += 1;
    }

    let Some(bank) = bank else {
        usage();
        eprintln!("\nerror: --bank is required");
        return Err(ExitCode::from(EXIT_USAGE));
    };
    let Some(keystore) = keystore else {
        usage();
        eprintln!("\nerror: --keystore is required");
        return Err(ExitCode::from(EXIT_USAGE));
    };

    Ok(Args {
        bank,
        keystore,
        expect_bank_id,
        quiet,
    })
}

/// Construct a SimHsm pointing at `keystore` without spawning any
/// child process. We only need the synchronous `sign`/`verify`/`get_*`
/// methods of `HsmProvider`, which read directly from the on-disk
/// keystore — no daemon required.
fn open_keystore(keystore: &Path) -> Result<SimHsm, String> {
    if !keystore.exists() {
        return Err(format!(
            "keystore directory missing: {}",
            keystore.display(),
        ));
    }
    // The `service_bin` path argument is only used to launch
    // vhsm-test-ssd when `start_service` is called. sumo-verify never
    // calls start_service, so a placeholder path is fine.
    Ok(SimHsm::new(
        PathBuf::from("/dev/null"),
        keystore.to_path_buf(),
        0,
    ))
}

fn run() -> ExitCode {
    let args = match parse_args(std::env::args().collect()) {
        Ok(a) => a,
        Err(code) => return code,
    };

    // Surface hsm::ivd's structured timing events on stderr. Default
    // filter is "info" so the per-call "ivd verify OK / FAIL" line
    // shows up automatically without callers needing to set RUST_LOG.
    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| {
                    if args.quiet { "warn" } else { "info" }.parse().unwrap()
                }),
        )
        .with_writer(std::io::stderr)
        .try_init();

    if !args.bank.exists() {
        eprintln!(
            "sumo-verify: bank dir missing: {}",
            args.bank.display(),
        );
        return ExitCode::from(EXIT_USAGE);
    }

    let hsm = match open_keystore(&args.keystore) {
        Ok(h) => h,
        Err(e) => {
            eprintln!("sumo-verify: {e}");
            return ExitCode::from(EXIT_USAGE);
        }
    };

    let result = ivd::verify_bank(
        &hsm,
        &args.bank,
        args.expect_bank_id.as_deref(),
    );

    match result {
        Ok(manifest) => {
            if !args.quiet {
                println!(
                    "ok bank_id={} files={} signed_at_unix={}",
                    manifest.bank_id,
                    manifest.files.len(),
                    manifest.signed_at_unix,
                );
            }
            ExitCode::from(EXIT_OK)
        }
        Err(e) => {
            // Stderr mention what went wrong; stdout stays empty so
            // callers can pipe with confidence.
            eprintln!("sumo-verify: {e}");
            ExitCode::from(EXIT_VERIFY_FAIL)
        }
    }
}

fn main() -> ExitCode {
    run()
}
