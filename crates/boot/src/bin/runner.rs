/// vm-runner — boot loop orchestrator.
///
/// Runs process_boot → start QEMU → wait for exit → repeat.
/// Ctrl+C triggers clean shutdown.

use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use nv_store::block::FileBlockDevice;
use nv_store::store::MIN_NV_DEVICE_SIZE;
use nv_store::types::BankSet;
use vm_boot::backend::BootBackend;
use vm_boot::config::VmProfile;
use vm_boot::qemu::QemuBackend;
use vm_boot::{BootAction, BootManager};

fn usage() -> ! {
    eprintln!("Usage: vm-runner --profile <path.toml> --nv <nv-store-path> --images <dir> [--sim-dir <dir>] [--init]");
    std::process::exit(1);
}

fn parse_args() -> (PathBuf, PathBuf, PathBuf, Option<PathBuf>, bool) {
    let args: Vec<String> = std::env::args().collect();
    let mut profile = None;
    let mut nv = None;
    let mut images = None;
    let mut sim_dir = None;
    let mut init = false;

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--profile" => { i += 1; profile = args.get(i).map(PathBuf::from); }
            "--nv" => { i += 1; nv = args.get(i).map(PathBuf::from); }
            "--images" => { i += 1; images = args.get(i).map(PathBuf::from); }
            "--sim-dir" => { i += 1; sim_dir = args.get(i).map(PathBuf::from); }
            "--init" => { init = true; }
            _ => {
                eprintln!("Unknown argument: {}", args[i]);
                usage();
            }
        }
        i += 1;
    }

    let profile = profile.unwrap_or_else(|| { eprintln!("Missing --profile"); usage() });
    let nv = nv.unwrap_or_else(|| { eprintln!("Missing --nv"); usage() });
    let images = images.unwrap_or_else(|| { eprintln!("Missing --images"); usage() });

    (profile, nv, images, sim_dir, init)
}

fn main() {
    let (profile_path, nv_path, images_dir, sim_dir, init) = parse_args();

    let profile = match VmProfile::from_file(&profile_path) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("[runner] failed to load profile: {e}");
            std::process::exit(1);
        }
    };

    let bank_set = match BankSet::from_str(&profile.vm.bank_set) {
        Some(bs) => bs,
        None => {
            eprintln!("[runner] unknown bank_set in profile: {:?}", profile.vm.bank_set);
            std::process::exit(1);
        }
    };

    let set_idx = bank_set as usize;

    // Ctrl+C handler
    let shutdown = Arc::new(AtomicBool::new(false));
    let shutdown_flag = shutdown.clone();
    ctrlc::set_handler(move || {
        eprintln!("\n[runner] Ctrl+C received, shutting down after current VM exits...");
        shutdown_flag.store(true, Ordering::SeqCst);
    })
    .expect("failed to set Ctrl+C handler");

    // Build backend
    let mut backend = QemuBackend::new();
    if let Some(ref dir) = sim_dir {
        backend = backend.sim_dir(dir);
    }

    let mut boot_count: u32 = 0;

    eprintln!("[runner] starting boot loop for {:?}", bank_set);

    loop {
        if shutdown.load(Ordering::SeqCst) {
            eprintln!("[runner] shutdown requested, exiting boot loop");
            break;
        }

        // Re-open NV store each iteration (diagserver may have written to it)
        let dev = if init && !nv_path.exists() {
            eprintln!("[runner] creating NV store: {}", nv_path.display());
            FileBlockDevice::create(&nv_path, MIN_NV_DEVICE_SIZE)
        } else {
            FileBlockDevice::open(&nv_path)
        };

        let dev = match dev {
            Ok(d) => d,
            Err(e) => {
                eprintln!("[runner] failed to open NV store: {e}");
                std::process::exit(1);
            }
        };

        let mut mgr = BootManager::new(dev);

        let actions = match mgr.process_boot() {
            Ok(a) => a,
            Err(e) => {
                eprintln!("[runner] failed to process boot: {e}");
                std::process::exit(1);
            }
        };

        let action = &actions[set_idx];
        boot_count += 1;

        let bank = match action {
            BootAction::Boot { bank } => {
                eprintln!("[runner] boot #{boot_count}: bank {bank:?} (committed)");
                *bank
            }
            BootAction::TrialBoot { bank, boot_count: trial } => {
                eprintln!(
                    "[runner] boot #{boot_count}: trial bank {bank:?} ({trial}/{})",
                    nv_store::types::MAX_TRIAL_BOOTS
                );
                *bank
            }
            BootAction::AutoRollback { from, to } => {
                eprintln!(
                    "[runner] boot #{boot_count}: AUTO-ROLLBACK {from:?} -> {to:?}"
                );
                *to
            }
            BootAction::HashRollback { from, to } => {
                eprintln!(
                    "[runner] boot #{boot_count}: HASH ROLLBACK {from:?} -> {to:?}"
                );
                *to
            }
            BootAction::HashFatal { bank } => {
                eprintln!(
                    "[runner] boot #{boot_count}: FATAL — committed bank {bank:?} hash failed!"
                );
                break;
            }
            BootAction::FirstBoot => {
                eprintln!("[runner] boot #{boot_count}: first boot, initialized to bank A");
                nv_store::types::Bank::A
            }
        };

        eprintln!("[runner] starting VM...");
        let handle = match backend.start_vm(&profile, bank_set, bank, &images_dir) {
            Ok(h) => h,
            Err(e) => {
                eprintln!("[runner] failed to start VM: {e}");
                backend.cleanup();
                break;
            }
        };

        // Block until QEMU exits
        match backend.wait_vm(&handle) {
            Ok(code) => {
                eprintln!("[runner] VM exited (code: {code:?})");
            }
            Err(e) => {
                eprintln!("[runner] wait_vm error: {e}");
            }
        }

        backend.cleanup();

        if shutdown.load(Ordering::SeqCst) {
            eprintln!("[runner] shutdown requested, exiting boot loop");
            break;
        }

        eprintln!("[runner] re-entering boot loop...");
    }

    eprintln!("[runner] done ({boot_count} boots)");
}
