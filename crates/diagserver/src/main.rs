use nv_store::block::FileBlockDevice;
use nv_store::store::{NvStore, MIN_NV_DEVICE_SIZE};
use nv_store::types::*;

use vm_diagserver::did;
use vm_diagserver::ota;

use std::path::PathBuf;

fn usage() -> ! {
    eprintln!("Usage: vm-diagserver <nv-store-path> <command> [args...]");
    eprintln!();
    eprintln!("Commands:");
    eprintln!("  status <set>                     Show bank status (hyp|os1|os2)");
    eprintln!("  install <set> <image-path> <ver> <secver>  Install OTA image");
    eprintln!("  commit <set>                     Commit trial bank");
    eprintln!("  rollback <set>                   Rollback to previous bank");
    eprintln!("  read-did <set> <did-hex>         Read a DID (e.g. F189)");
    eprintln!("  write-did <set> <did-hex> <val>  Write a runtime DID");
    eprintln!("  provision <serial> <vin>         Write factory data (once)");
    std::process::exit(1);
}

fn parse_set(s: &str) -> BankSet {
    match s {
        "hyp" => BankSet::Hypervisor,
        "os1" => BankSet::Os1,
        "os2" => BankSet::Os2,
        _ => {
            eprintln!("Invalid bank set '{s}'. Use: hyp, os1, os2");
            std::process::exit(1);
        }
    }
}

fn parse_did(s: &str) -> u16 {
    u16::from_str_radix(s.trim_start_matches("0x").trim_start_matches("0X"), 16)
        .unwrap_or_else(|_| {
            eprintln!("Invalid DID '{s}'. Use hex, e.g. F189 or 0xFD10");
            std::process::exit(1);
        })
}

fn bank_letter(b: Bank) -> &'static str {
    match b {
        Bank::A => "A",
        Bank::B => "B",
    }
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 3 {
        usage();
    }

    let nv_path = PathBuf::from(&args[1]);
    let cmd = &args[2];

    let dev = if nv_path.exists() {
        FileBlockDevice::open(&nv_path)
    } else {
        eprintln!("[diag] creating NV store: {}", nv_path.display());
        FileBlockDevice::create(&nv_path, MIN_NV_DEVICE_SIZE)
    };

    let dev = match dev {
        Ok(d) => d,
        Err(e) => {
            eprintln!("[diag] failed to open NV store: {e}");
            std::process::exit(1);
        }
    };

    let mut nv = NvStore::new(dev);

    // Ensure boot state exists
    if nv.read_boot_state().is_none() {
        let mut state = NvBootState::default();
        nv.write_boot_state(&mut state).unwrap();
    }

    match cmd.as_str() {
        "status" => {
            let set = parse_set(args.get(3).map(|s| s.as_str()).unwrap_or_else(|| usage()));
            match ota::status(&nv, set) {
                Some(s) => {
                    println!("Bank set: {:?}", set);
                    println!("Active bank: {}", bank_letter(s.active_bank));
                    println!("Committed: {}", s.committed);
                    println!("Boot count: {}", s.boot_count);
                    if let Some(v) = s.fw_version {
                        let end = v.iter().position(|&c| c == 0).unwrap_or(v.len());
                        println!("FW version: {}", std::str::from_utf8(&v[..end]).unwrap_or("?"));
                    }
                    if let Some(v) = s.fw_secver {
                        println!("Security version: {v}");
                    }
                    if let Some(v) = s.min_security_ver {
                        println!("Min security version: {v}");
                    }
                }
                None => eprintln!("[diag] no boot state"),
            }
        }

        "install" => {
            if args.len() < 7 {
                eprintln!("Usage: install <set> <image-path> <version> <secver>");
                std::process::exit(1);
            }
            let set = parse_set(&args[3]);
            let image_path = PathBuf::from(&args[4]);
            let version = &args[5];
            let secver: u32 = args[6].parse().unwrap_or_else(|_| {
                eprintln!("Invalid security version");
                std::process::exit(1);
            });

            let image_data = std::fs::read(&image_path).unwrap_or_else(|e| {
                eprintln!("[diag] failed to read image: {e}");
                std::process::exit(1);
            });

            let mut meta = ota::ImageMeta::default();
            let vlen = version.len().min(32);
            meta.fw_version[..vlen].copy_from_slice(&version.as_bytes()[..vlen]);
            meta.fw_secver = secver;
            meta.fw_seq = secver;

            match ota::install(&mut nv, set, &image_data, &meta) {
                Ok(result) => {
                    println!("[diag] installed to bank {}", bank_letter(result.target_bank));
                    println!("[diag] SHA-256: {}", hex(&result.image_sha256));
                    println!("[diag] reboot to activate (trial mode)");
                }
                Err(e) => {
                    eprintln!("[diag] install failed: {e}");
                    std::process::exit(1);
                }
            }
        }

        "commit" => {
            let set = parse_set(args.get(3).map(|s| s.as_str()).unwrap_or_else(|| usage()));
            match ota::commit(&mut nv, set) {
                Ok(()) => println!("[diag] committed {:?}", set),
                Err(e) => {
                    eprintln!("[diag] commit failed: {e}");
                    std::process::exit(1);
                }
            }
        }

        "rollback" => {
            let set = parse_set(args.get(3).map(|s| s.as_str()).unwrap_or_else(|| usage()));
            match ota::rollback(&mut nv, set) {
                Ok(bank) => println!("[diag] rolled back to bank {}", bank_letter(bank)),
                Err(e) => {
                    eprintln!("[diag] rollback failed: {e}");
                    std::process::exit(1);
                }
            }
        }

        "read-did" => {
            if args.len() < 5 {
                eprintln!("Usage: read-did <set> <did-hex>");
                std::process::exit(1);
            }
            let set = parse_set(&args[3]);
            let did_num = parse_did(&args[4]);
            let val = did::read_did(&nv, set, did_num);
            match val {
                did::DidValue::Bytes(b) => {
                    // Try as string first
                    let end = b.iter().position(|&c| c == 0).unwrap_or(b.len());
                    if let Ok(s) = std::str::from_utf8(&b[..end]) {
                        if s.chars().all(|c| c.is_ascii_graphic() || c == ' ') && !s.is_empty() {
                            println!("{s}");
                        } else {
                            println!("{}", hex(&b));
                        }
                    } else {
                        println!("{}", hex(&b));
                    }
                }
                did::DidValue::NotFound => {
                    eprintln!("DID 0x{did_num:04X} not found");
                    std::process::exit(1);
                }
            }
        }

        "write-did" => {
            if args.len() < 6 {
                eprintln!("Usage: write-did <set> <did-hex> <value>");
                std::process::exit(1);
            }
            let set = parse_set(&args[3]);
            let did_num = parse_did(&args[4]);
            let value = args[5].as_bytes();
            match did::write_did(&mut nv, set, did_num, value) {
                Ok(true) => println!("[diag] wrote DID 0x{did_num:04X}"),
                Ok(false) => {
                    eprintln!("[diag] runtime DID store full");
                    std::process::exit(1);
                }
                Err(e) => {
                    eprintln!("[diag] write failed: {e}");
                    std::process::exit(1);
                }
            }
        }

        "provision" => {
            if args.len() < 5 {
                eprintln!("Usage: provision <serial> <vin>");
                std::process::exit(1);
            }
            if nv.read_factory().is_some() {
                eprintln!("[diag] factory data already provisioned");
                std::process::exit(1);
            }
            let serial = &args[3];
            let vin = &args[4];

            let mut factory = NvFactory::default();
            let slen = serial.len().min(32);
            factory.serial_number[..slen].copy_from_slice(&serial.as_bytes()[..slen]);
            let vlen = vin.len().min(17);
            factory.vin[..vlen].copy_from_slice(&vin.as_bytes()[..vlen]);

            nv.write_factory(&mut factory).unwrap();
            println!("[diag] factory provisioned: serial={serial} vin={vin}");
        }

        _ => {
            eprintln!("Unknown command: {cmd}");
            usage();
        }
    }
}

fn hex(data: &[u8]) -> String {
    data.iter().map(|b| format!("{b:02x}")).collect()
}
