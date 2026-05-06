use std::process::ExitCode;
use std::thread;
use std::time::Duration;

use vm_devices::regs::health as r;
use vm_devices::transport::posix::PosixSharedMemory;
use vm_devices::transport::SharedMemory;

const SHM_SIZE: usize = 4096;

fn guest_state_str(state: u32) -> &'static str {
    match state {
        r::GUEST_BOOTING => "BOOTING",
        r::GUEST_RUNNING => "RUNNING",
        r::GUEST_DEGRADED => "DEGRADED",
        r::GUEST_SHUTTING_DOWN => "SHUTTING_DOWN",
        _ => "UNKNOWN",
    }
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().collect();

    let (vm_name, wait) = match args.len() {
        2 => (args[1].as_str(), false),
        3 if args[1] == "--wait" => (args[2].as_str(), true),
        _ => {
            eprintln!("usage: vm-health-check [--wait] <vm-name>");
            eprintln!("  exit 0: guest RUNNING with active heartbeat");
            eprintln!("  exit 1: guest not RUNNING or heartbeat stale");
            eprintln!("  exit 2: shared memory not found");
            return ExitCode::from(2);
        }
    };

    let shm_name = format!("/vm-{vm_name}-health");
    let shm = match PosixSharedMemory::open(&shm_name, SHM_SIZE) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("error: cannot open {shm_name}: {e}");
            return ExitCode::from(2);
        }
    };

    let magic = shm.read_u32(r::OFF_MAGIC);
    if magic != r::MAGIC {
        eprintln!("error: bad magic in {shm_name}: 0x{magic:08X} (expected 0x{:08X})", r::MAGIC);
        return ExitCode::from(2);
    }

    if wait {
        // Poll up to 30s for guest to reach RUNNING with incrementing heartbeat
        let deadline = std::time::Instant::now() + Duration::from_secs(30);
        loop {
            let hb_magic = shm.read_u32(r::HB_OFF_MAGIC);
            let guest_state = shm.read_u32(r::HB_OFF_GUEST_STATE);
            if hb_magic == r::HB_MAGIC && guest_state == r::GUEST_RUNNING {
                let seq1 = shm.read_u32(r::HB_OFF_SEQ);
                thread::sleep(Duration::from_millis(1100));
                let seq2 = shm.read_u32(r::HB_OFF_SEQ);
                if seq2 > seq1 {
                    print_status(&shm);
                    return ExitCode::SUCCESS;
                }
            }
            if std::time::Instant::now() >= deadline {
                eprintln!("timeout: guest did not reach RUNNING within 30s");
                print_status(&shm);
                return ExitCode::from(1);
            }
            thread::sleep(Duration::from_secs(1));
        }
    }

    // Single-shot check
    let hb_magic = shm.read_u32(r::HB_OFF_MAGIC);
    if hb_magic != r::HB_MAGIC {
        eprintln!("guest_state: no heartbeat (guest has not written HB magic)");
        return ExitCode::from(1);
    }

    let seq1 = shm.read_u32(r::HB_OFF_SEQ);
    thread::sleep(Duration::from_millis(1100));
    let seq2 = shm.read_u32(r::HB_OFF_SEQ);

    print_status(&shm);

    let guest_state = shm.read_u32(r::HB_OFF_GUEST_STATE);
    if guest_state == r::GUEST_RUNNING && seq2 > seq1 {
        ExitCode::SUCCESS
    } else {
        ExitCode::from(1)
    }
}

fn print_status(shm: &PosixSharedMemory) {
    let guest_state = shm.read_u32(r::HB_OFF_GUEST_STATE);
    let seq = shm.read_u32(r::HB_OFF_SEQ);
    let boot_id = shm.read_u32(r::HB_OFF_BOOT_ID);
    let mono_ns = shm.read_u64(r::HB_OFF_MONO_NS);
    let num_sensors = shm.read_u32(r::OFF_NUM_SENSORS);

    println!("guest_state: {}", guest_state_str(guest_state));
    println!("heartbeat_seq: {seq}");
    println!("boot_id: 0x{boot_id:08x}");
    println!("uptime_ns: {mono_ns}");
    println!("sensors: {num_sensors}");
}
