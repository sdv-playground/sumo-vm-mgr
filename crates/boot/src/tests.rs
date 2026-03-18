use nv_store::block::MemBlockDevice;
use nv_store::store::MIN_NV_DEVICE_SIZE;
use nv_store::types::*;
use sha2::{Sha256, Digest};

use crate::*;
use crate::config::*;
use crate::backend::BootBackend;

fn make_bootmgr() -> BootManager<MemBlockDevice> {
    BootManager::new(MemBlockDevice::new(MIN_NV_DEVICE_SIZE as usize))
}

// --- First boot ---

#[test]
fn first_boot_initializes_state() {
    let mut mgr = make_bootmgr();
    let actions = mgr.process_boot().unwrap();

    assert_eq!(actions[0], BootAction::FirstBoot);
    assert_eq!(actions[1], BootAction::FirstBoot);
    assert_eq!(actions[2], BootAction::FirstBoot);

    // NV state should now be initialized
    let state = mgr.nv().read_boot_state().unwrap();
    for bs in &state.banks {
        assert_eq!(bs.active_bank, Bank::A);
        assert!(bs.committed);
        assert_eq!(bs.boot_count, 0);
    }
}

#[test]
fn second_boot_after_first_is_committed() {
    let mut mgr = make_bootmgr();
    mgr.process_boot().unwrap(); // first boot

    let actions = mgr.process_boot().unwrap();
    for action in &actions {
        assert_eq!(*action, BootAction::Boot { bank: Bank::A });
    }
}

// --- Committed boot ---

#[test]
fn committed_boot_does_not_increment_count() {
    let mut mgr = make_bootmgr();
    mgr.process_boot().unwrap(); // init

    // Boot 5 times in committed mode
    for _ in 0..5 {
        let actions = mgr.process_boot().unwrap();
        assert_eq!(actions[0], BootAction::Boot { bank: Bank::A });
    }

    let state = mgr.nv().read_boot_state().unwrap();
    assert_eq!(state.banks[0].boot_count, 0); // unchanged
}

// --- Trial boot ---

#[test]
fn trial_boot_increments_count() {
    let mut mgr = make_bootmgr();
    mgr.process_boot().unwrap(); // init

    // Put OS1 into trial mode on Bank B
    let mut state = mgr.nv().read_boot_state().unwrap();
    state.banks[1].active_bank = Bank::B;
    state.banks[1].committed = false;
    state.banks[1].boot_count = 0;
    mgr.nv_mut().write_boot_state(&mut state).unwrap();

    let actions = mgr.process_boot().unwrap();
    assert_eq!(actions[1], BootAction::TrialBoot { bank: Bank::B, boot_count: 1 });

    let actions = mgr.process_boot().unwrap();
    assert_eq!(actions[1], BootAction::TrialBoot { bank: Bank::B, boot_count: 2 });

    // Hyp and OS2 should still be committed
    assert_eq!(actions[0], BootAction::Boot { bank: Bank::A });
    assert_eq!(actions[2], BootAction::Boot { bank: Bank::A });
}

#[test]
fn trial_boot_at_max_still_boots() {
    let mut mgr = make_bootmgr();
    mgr.process_boot().unwrap();

    let mut state = mgr.nv().read_boot_state().unwrap();
    state.banks[0].active_bank = Bank::B;
    state.banks[0].committed = false;
    state.banks[0].boot_count = MAX_TRIAL_BOOTS - 1; // one boot left
    mgr.nv_mut().write_boot_state(&mut state).unwrap();

    let actions = mgr.process_boot().unwrap();
    assert_eq!(
        actions[0],
        BootAction::TrialBoot { bank: Bank::B, boot_count: MAX_TRIAL_BOOTS }
    );
}

// --- Auto-rollback ---

#[test]
fn auto_rollback_after_max_trial_boots() {
    let mut mgr = make_bootmgr();
    mgr.process_boot().unwrap();

    // Set OS1 to trial with count at MAX (next boot triggers rollback)
    let mut state = mgr.nv().read_boot_state().unwrap();
    state.banks[1].active_bank = Bank::B;
    state.banks[1].committed = false;
    state.banks[1].boot_count = MAX_TRIAL_BOOTS;
    mgr.nv_mut().write_boot_state(&mut state).unwrap();

    let actions = mgr.process_boot().unwrap();
    assert_eq!(
        actions[1],
        BootAction::AutoRollback { from: Bank::B, to: Bank::A }
    );

    // Verify NV state: rolled back to A, committed
    let state = mgr.nv().read_boot_state().unwrap();
    assert_eq!(state.banks[1].active_bank, Bank::A);
    assert!(state.banks[1].committed);
    assert_eq!(state.banks[1].boot_count, 0);
}

#[test]
fn auto_rollback_from_a_to_b() {
    let mut mgr = make_bootmgr();
    mgr.process_boot().unwrap();

    let mut state = mgr.nv().read_boot_state().unwrap();
    state.banks[0].active_bank = Bank::A;
    state.banks[0].committed = false;
    state.banks[0].boot_count = MAX_TRIAL_BOOTS;
    mgr.nv_mut().write_boot_state(&mut state).unwrap();

    let actions = mgr.process_boot().unwrap();
    assert_eq!(
        actions[0],
        BootAction::AutoRollback { from: Bank::A, to: Bank::B }
    );
}

#[test]
fn full_trial_cycle_10_boots_then_rollback() {
    let mut mgr = make_bootmgr();
    mgr.process_boot().unwrap();

    // Start trial on Bank B
    let mut state = mgr.nv().read_boot_state().unwrap();
    state.banks[0].active_bank = Bank::B;
    state.banks[0].committed = false;
    state.banks[0].boot_count = 0;
    mgr.nv_mut().write_boot_state(&mut state).unwrap();

    // 10 trial boots
    for i in 1..=MAX_TRIAL_BOOTS {
        let actions = mgr.process_boot().unwrap();
        assert_eq!(
            actions[0],
            BootAction::TrialBoot { bank: Bank::B, boot_count: i }
        );
    }

    // 11th boot triggers auto-rollback
    let actions = mgr.process_boot().unwrap();
    assert_eq!(
        actions[0],
        BootAction::AutoRollback { from: Bank::B, to: Bank::A }
    );

    // Subsequent boots are committed on A
    let actions = mgr.process_boot().unwrap();
    assert_eq!(actions[0], BootAction::Boot { bank: Bank::A });
}

// --- Bank set independence ---

#[test]
fn bank_sets_independent_trial() {
    let mut mgr = make_bootmgr();
    mgr.process_boot().unwrap();

    // OS1 in trial, Hyp and OS2 committed
    let mut state = mgr.nv().read_boot_state().unwrap();
    state.banks[1].active_bank = Bank::B;
    state.banks[1].committed = false;
    state.banks[1].boot_count = 0;
    mgr.nv_mut().write_boot_state(&mut state).unwrap();

    let actions = mgr.process_boot().unwrap();
    assert_eq!(actions[0], BootAction::Boot { bank: Bank::A }); // hyp committed
    assert_eq!(actions[1], BootAction::TrialBoot { bank: Bank::B, boot_count: 1 }); // os1 trial
    assert_eq!(actions[2], BootAction::Boot { bank: Bank::A }); // os2 committed
}

#[test]
fn multiple_bank_sets_in_trial() {
    let mut mgr = make_bootmgr();
    mgr.process_boot().unwrap();

    let mut state = mgr.nv().read_boot_state().unwrap();
    // Hyp on trial (bank B), OS2 on trial (bank B)
    state.banks[0].active_bank = Bank::B;
    state.banks[0].committed = false;
    state.banks[0].boot_count = 0;
    state.banks[2].active_bank = Bank::B;
    state.banks[2].committed = false;
    state.banks[2].boot_count = 5;
    mgr.nv_mut().write_boot_state(&mut state).unwrap();

    let actions = mgr.process_boot().unwrap();
    assert_eq!(actions[0], BootAction::TrialBoot { bank: Bank::B, boot_count: 1 });
    assert_eq!(actions[1], BootAction::Boot { bank: Bank::A }); // OS1 committed
    assert_eq!(actions[2], BootAction::TrialBoot { bank: Bank::B, boot_count: 6 });
}

// --- Hash verification ---

#[test]
fn verify_image_correct_hash() {
    let mut mgr = make_bootmgr();
    mgr.process_boot().unwrap();

    let image_data = b"this is a test firmware image";
    let expected_hash: [u8; 32] = Sha256::digest(image_data).into();

    let mut meta = NvFwMeta::default();
    meta.image_sha256 = expected_hash;
    mgr.nv_mut().write_fw_meta(BankSet::Os1, Bank::A, &mut meta).unwrap();

    let result = mgr.verify_image(BankSet::Os1, Bank::A, image_data);
    assert_eq!(result, HashCheck::Ok);
}

#[test]
fn verify_image_wrong_hash() {
    let mut mgr = make_bootmgr();
    mgr.process_boot().unwrap();

    let image_data = b"this is a test firmware image";
    let wrong_data = b"this is a DIFFERENT firmware image";

    let mut meta = NvFwMeta::default();
    meta.image_sha256 = Sha256::digest(wrong_data).into();
    mgr.nv_mut().write_fw_meta(BankSet::Os1, Bank::A, &mut meta).unwrap();

    let result = mgr.verify_image(BankSet::Os1, Bank::A, image_data);
    match result {
        HashCheck::Mismatch { expected, actual } => {
            assert_eq!(expected, Sha256::digest(wrong_data).as_slice());
            assert_eq!(actual, Sha256::digest(image_data).as_slice());
        }
        other => panic!("expected Mismatch, got {other:?}"),
    }
}

#[test]
fn verify_image_no_meta() {
    let mut mgr = make_bootmgr();
    mgr.process_boot().unwrap();

    let result = mgr.verify_image(BankSet::Os1, Bank::A, b"anything");
    assert_eq!(result, HashCheck::NoMeta);
}

#[test]
fn verify_image_zero_hash_is_no_meta() {
    let mut mgr = make_bootmgr();
    mgr.process_boot().unwrap();

    let mut meta = NvFwMeta::default(); // all zeros including hash
    mgr.nv_mut().write_fw_meta(BankSet::Os1, Bank::A, &mut meta).unwrap();

    let result = mgr.verify_image(BankSet::Os1, Bank::A, b"anything");
    assert_eq!(result, HashCheck::NoMeta);
}

// --- Hash failure handling ---

#[test]
fn hash_failure_in_trial_triggers_rollback() {
    let mut mgr = make_bootmgr();
    mgr.process_boot().unwrap();

    // Put OS1 in trial on Bank B
    let mut state = mgr.nv().read_boot_state().unwrap();
    state.banks[1].active_bank = Bank::B;
    state.banks[1].committed = false;
    state.banks[1].boot_count = 3;
    mgr.nv_mut().write_boot_state(&mut state).unwrap();

    let action = mgr.handle_hash_failure(BankSet::Os1).unwrap();
    assert_eq!(action, BootAction::HashRollback { from: Bank::B, to: Bank::A });

    // Verify NV state
    let state = mgr.nv().read_boot_state().unwrap();
    assert_eq!(state.banks[1].active_bank, Bank::A);
    assert!(state.banks[1].committed);
    assert_eq!(state.banks[1].boot_count, 0);
}

#[test]
fn hash_failure_in_committed_is_fatal() {
    let mut mgr = make_bootmgr();
    mgr.process_boot().unwrap();

    let action = mgr.handle_hash_failure(BankSet::Os1).unwrap();
    assert_eq!(action, BootAction::HashFatal { bank: Bank::A });

    // NV state unchanged — committed image is corrupt, nothing to do
    let state = mgr.nv().read_boot_state().unwrap();
    assert!(state.banks[1].committed);
}

// --- Helper methods ---

#[test]
fn active_bank_query() {
    let mut mgr = make_bootmgr();
    mgr.process_boot().unwrap();

    assert_eq!(mgr.active_bank(BankSet::Hypervisor), Some(Bank::A));
    assert_eq!(mgr.active_bank(BankSet::Os1), Some(Bank::A));
    assert_eq!(mgr.active_bank(BankSet::Os2), Some(Bank::A));
}

#[test]
fn is_trial_query() {
    let mut mgr = make_bootmgr();
    mgr.process_boot().unwrap();

    assert_eq!(mgr.is_trial(BankSet::Os1), Some(false));

    // Put into trial
    let mut state = mgr.nv().read_boot_state().unwrap();
    state.banks[1].committed = false;
    mgr.nv_mut().write_boot_state(&mut state).unwrap();

    assert_eq!(mgr.is_trial(BankSet::Os1), Some(true));
}

// --- Simulated OTA + boot cycle ---

#[test]
fn ota_trial_commit_cycle() {
    let mut mgr = make_bootmgr();
    mgr.process_boot().unwrap(); // init

    // Simulate OTA: diagserver writes to inactive bank and updates boot state
    let image = b"new firmware image v2";
    let hash: [u8; 32] = Sha256::digest(image).into();

    // Write FW Meta for target bank
    let mut meta = NvFwMeta::default();
    meta.fw_version[..2].copy_from_slice(b"v2");
    meta.fw_secver = 2;
    meta.min_security_ver = 1;
    meta.image_sha256 = hash;
    mgr.nv_mut().write_fw_meta(BankSet::Os1, Bank::B, &mut meta).unwrap();

    // Switch to trial
    let mut state = mgr.nv().read_boot_state().unwrap();
    state.banks[1].active_bank = Bank::B;
    state.banks[1].committed = false;
    state.banks[1].boot_count = 0;
    mgr.nv_mut().write_boot_state(&mut state).unwrap();

    // Boot 1: trial
    let actions = mgr.process_boot().unwrap();
    assert_eq!(actions[1], BootAction::TrialBoot { bank: Bank::B, boot_count: 1 });

    // Verify image
    assert_eq!(mgr.verify_image(BankSet::Os1, Bank::B, image), HashCheck::Ok);

    // Commit (simulating diagserver command)
    let mut state = mgr.nv().read_boot_state().unwrap();
    state.banks[1].committed = true;
    state.banks[1].boot_count = 0;
    mgr.nv_mut().write_boot_state(&mut state).unwrap();

    // Raise anti-rollback floor
    let mut meta = mgr.nv().read_fw_meta(BankSet::Os1, Bank::B).unwrap();
    if meta.fw_secver > meta.min_security_ver {
        meta.min_security_ver = meta.fw_secver;
    }
    mgr.nv_mut().write_fw_meta(BankSet::Os1, Bank::B, &mut meta).unwrap();

    // Next boot: committed on B
    let actions = mgr.process_boot().unwrap();
    assert_eq!(actions[1], BootAction::Boot { bank: Bank::B });

    // Verify anti-rollback floor was raised
    let meta = mgr.nv().read_fw_meta(BankSet::Os1, Bank::B).unwrap();
    assert_eq!(meta.min_security_ver, 2);
}

#[test]
fn ota_trial_auto_rollback_cycle() {
    let mut mgr = make_bootmgr();
    mgr.process_boot().unwrap();

    // OTA: switch OS1 to Bank B, trial mode
    let mut state = mgr.nv().read_boot_state().unwrap();
    state.banks[1].active_bank = Bank::B;
    state.banks[1].committed = false;
    state.banks[1].boot_count = 0;
    mgr.nv_mut().write_boot_state(&mut state).unwrap();

    // Boot 10 times without committing
    for _ in 0..MAX_TRIAL_BOOTS {
        let actions = mgr.process_boot().unwrap();
        match actions[1] {
            BootAction::TrialBoot { bank: Bank::B, .. } => {}
            _ => panic!("expected trial boot on B"),
        }
    }

    // 11th boot: auto-rollback
    let actions = mgr.process_boot().unwrap();
    assert_eq!(actions[1], BootAction::AutoRollback { from: Bank::B, to: Bank::A });

    // Now committed on A
    let actions = mgr.process_boot().unwrap();
    assert_eq!(actions[1], BootAction::Boot { bank: Bank::A });
}

// ============================================================
// Config parsing tests
// ============================================================

#[test]
fn parse_dev_profile() {
    let toml = r#"
[vm]
bank_set = "os1"
ram_mb = 2048
cpus = 4
kernel = "Image"

[[devices]]
type = "can"
index = 0
backend = "simulated"

[[devices]]
type = "health"
backend = "simulated"

[[devices]]
type = "time"
backend = "simulated"

[[devices]]
type = "hsm"
backend = "vsock"
keystore = "/tmp/vhsm-keys"

[[devices]]
type = "network"
ssh_port = 2222

[[devices]]
type = "disk"
role = "swap"
path = "swap.img"

[[devices]]
type = "disk"
role = "data"
path = "data.img"
"#;

    let profile = VmProfile::from_toml(toml).unwrap();
    assert_eq!(profile.vm.bank_set, "os1");
    assert_eq!(profile.vm.ram_mb, 2048);
    assert_eq!(profile.vm.cpus, 4);
    assert_eq!(profile.can_count(), 1);
    assert_eq!(profile.ssh_port(), Some(2222));
    assert_eq!(profile.devices.len(), 7);
}

#[test]
fn parse_minimal_profile() {
    let toml = r#"
[vm]
bank_set = "os1"
kernel = "Image"

[[devices]]
type = "network"
ssh_port = 2222
"#;

    let profile = VmProfile::from_toml(toml).unwrap();
    assert_eq!(profile.vm.ram_mb, 2048); // default
    assert_eq!(profile.vm.cpus, 4); // default
    assert_eq!(profile.can_count(), 0);
    assert_eq!(profile.devices.len(), 1);
}

#[test]
fn parse_host_passthrough_can() {
    let toml = r#"
[vm]
bank_set = "os1"

[[devices]]
type = "can"
index = 0
backend = "host-passthrough"
interface = "vcan0"
"#;

    let profile = VmProfile::from_toml(toml).unwrap();
    match &profile.devices[0] {
        DeviceConfig::Can { index, backend, interface } => {
            assert_eq!(*index, 0);
            assert_eq!(backend, "host-passthrough");
            assert_eq!(interface.as_deref(), Some("vcan0"));
        }
        _ => panic!("expected CAN device"),
    }
}

#[test]
fn parse_multiple_can() {
    let toml = r#"
[vm]
bank_set = "os1"

[[devices]]
type = "can"
index = 0
backend = "simulated"

[[devices]]
type = "can"
index = 1
backend = "simulated"

[[devices]]
type = "can"
index = 2
backend = "host-passthrough"
interface = "can0"
"#;

    let profile = VmProfile::from_toml(toml).unwrap();
    assert_eq!(profile.can_count(), 3);
}

// ============================================================
// QEMU backend command generation tests
// ============================================================

#[test]
fn qemu_build_command_minimal() {
    let toml = r#"
[vm]
bank_set = "os1"
ram_mb = 1024
cpus = 2
kernel = "Image"

[[devices]]
type = "network"
ssh_port = 2222
"#;

    let profile = VmProfile::from_toml(toml).unwrap();
    let backend = qemu::QemuBackend::new().try_kvm(false);
    let cmd = backend.build_command(&profile, BankSet::Os1, Bank::A, Path::new("/images")).unwrap();

    // Check key args are present
    assert!(cmd.contains(&"-machine".to_string()));
    assert!(cmd.contains(&"virt,gic-version=3".to_string()));
    assert!(cmd.contains(&"-cpu".to_string()));
    assert!(cmd.contains(&"cortex-a76".to_string()));
    assert!(cmd.contains(&"-m".to_string()));
    assert!(cmd.contains(&"1024M".to_string()));
    assert!(cmd.contains(&"-smp".to_string()));
    assert!(cmd.contains(&"2".to_string()));
    assert!(cmd.contains(&"-nographic".to_string()));
    assert!(cmd.contains(&"-kernel".to_string()));

    // Rootfs image should reference the bank
    let rootfs_arg = cmd.iter().find(|a| a.contains("os1-a.img")).unwrap();
    assert!(rootfs_arg.contains("/images/os1-a.img"));

    // SSH port forwarding
    let netdev = cmd.iter().find(|a| a.contains("hostfwd")).unwrap();
    assert!(netdev.contains("2222"));
}

#[test]
fn qemu_build_command_bank_b() {
    let toml = r#"
[vm]
bank_set = "os1"
kernel = "Image"

[[devices]]
type = "network"
"#;

    let profile = VmProfile::from_toml(toml).unwrap();
    let backend = qemu::QemuBackend::new().try_kvm(false);
    let cmd = backend.build_command(&profile, BankSet::Os1, Bank::B, Path::new("/images")).unwrap();

    // Should use bank B image
    assert!(cmd.iter().any(|a| a.contains("os1-b.img")));
    assert!(!cmd.iter().any(|a| a.contains("os1-a.img")));
}

#[test]
fn qemu_build_command_with_ivshmem() {
    let toml = r#"
[vm]
bank_set = "os1"
kernel = "Image"

[[devices]]
type = "can"
index = 0
backend = "simulated"

[[devices]]
type = "health"
backend = "simulated"

[[devices]]
type = "time"
backend = "simulated"

[[devices]]
type = "network"
"#;

    let profile = VmProfile::from_toml(toml).unwrap();
    let backend = qemu::QemuBackend::new().try_kvm(false);
    let cmd = backend.build_command(&profile, BankSet::Os1, Bank::A, Path::new("/images")).unwrap();

    // Should have ivshmem-doorbell for each simulated device
    let doorbell_count = cmd.iter().filter(|a| a.contains("ivshmem-doorbell")).count();
    assert_eq!(doorbell_count, 3); // can0, health, time

    // Kernel cmdline should have CAN params
    let append_idx = cmd.iter().position(|a| a == "-append").unwrap();
    let cmdline = &cmd[append_idx + 1];
    assert!(cmdline.contains("vcan_shm.backend=ivshmem"));
    assert!(cmdline.contains("vcan_shm.num_devices=1"));
}

#[test]
fn qemu_build_command_with_disks() {
    let toml = r#"
[vm]
bank_set = "os1"
kernel = "Image"

[[devices]]
type = "disk"
role = "swap"
path = "swap.img"

[[devices]]
type = "disk"
role = "data"
path = "data.img"

[[devices]]
type = "network"
"#;

    let profile = VmProfile::from_toml(toml).unwrap();
    let backend = qemu::QemuBackend::new().try_kvm(false);
    let cmd = backend.build_command(&profile, BankSet::Os1, Bank::A, Path::new("/images")).unwrap();

    // Should have drives for swap, data, and rootfs
    let drive_count = cmd.iter().filter(|a| a.starts_with("file=")).count();
    assert!(drive_count >= 3);

    // Cmdline should have resume= for swap
    let append_idx = cmd.iter().position(|a| a == "-append").unwrap();
    let cmdline = &cmd[append_idx + 1];
    assert!(cmdline.contains("resume=/dev/vdc"));
}

use std::path::Path;
