use nv_store::block::MemBlockDevice;
use nv_store::store::MIN_NV_DEVICE_SIZE;
use nv_store::types::*;
use sha2::{Sha256, Digest};

use crate::*;
use crate::config::*;

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

    // Put VM1 into trial mode on Bank B
    let mut state = mgr.nv().read_boot_state().unwrap();
    state.banks[1].active_bank = Bank::B;
    state.banks[1].committed = false;
    state.banks[1].boot_count = 0;
    mgr.nv_mut().write_boot_state(&mut state).unwrap();

    let actions = mgr.process_boot().unwrap();
    assert_eq!(actions[1], BootAction::TrialBoot { bank: Bank::B, boot_count: 1 });

    let actions = mgr.process_boot().unwrap();
    assert_eq!(actions[1], BootAction::TrialBoot { bank: Bank::B, boot_count: 2 });

    // Hyp and VM2 should still be committed
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

    // Set VM1 to trial with count at MAX (next boot triggers rollback)
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

    // VM1 in trial, Hyp and VM2 committed
    let mut state = mgr.nv().read_boot_state().unwrap();
    state.banks[1].active_bank = Bank::B;
    state.banks[1].committed = false;
    state.banks[1].boot_count = 0;
    mgr.nv_mut().write_boot_state(&mut state).unwrap();

    let actions = mgr.process_boot().unwrap();
    assert_eq!(actions[0], BootAction::Boot { bank: Bank::A }); // hyp committed
    assert_eq!(actions[1], BootAction::TrialBoot { bank: Bank::B, boot_count: 1 }); // vm1 trial
    assert_eq!(actions[2], BootAction::Boot { bank: Bank::A }); // vm2 committed
}

#[test]
fn multiple_bank_sets_in_trial() {
    let mut mgr = make_bootmgr();
    mgr.process_boot().unwrap();

    let mut state = mgr.nv().read_boot_state().unwrap();
    // Hyp on trial (bank B), VM2 on trial (bank B)
    state.banks[0].active_bank = Bank::B;
    state.banks[0].committed = false;
    state.banks[0].boot_count = 0;
    state.banks[2].active_bank = Bank::B;
    state.banks[2].committed = false;
    state.banks[2].boot_count = 5;
    mgr.nv_mut().write_boot_state(&mut state).unwrap();

    let actions = mgr.process_boot().unwrap();
    assert_eq!(actions[0], BootAction::TrialBoot { bank: Bank::B, boot_count: 1 });
    assert_eq!(actions[1], BootAction::Boot { bank: Bank::A }); // VM1 committed
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
    mgr.nv_mut().write_fw_meta(BankSet::Vm1, Bank::A, &mut meta).unwrap();

    let result = mgr.verify_image(BankSet::Vm1, Bank::A, image_data);
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
    mgr.nv_mut().write_fw_meta(BankSet::Vm1, Bank::A, &mut meta).unwrap();

    let result = mgr.verify_image(BankSet::Vm1, Bank::A, image_data);
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

    let result = mgr.verify_image(BankSet::Vm1, Bank::A, b"anything");
    assert_eq!(result, HashCheck::NoMeta);
}

#[test]
fn verify_image_zero_hash_is_no_meta() {
    let mut mgr = make_bootmgr();
    mgr.process_boot().unwrap();

    let mut meta = NvFwMeta::default(); // all zeros including hash
    mgr.nv_mut().write_fw_meta(BankSet::Vm1, Bank::A, &mut meta).unwrap();

    let result = mgr.verify_image(BankSet::Vm1, Bank::A, b"anything");
    assert_eq!(result, HashCheck::NoMeta);
}

// --- Hash failure handling ---

#[test]
fn hash_failure_in_trial_triggers_rollback() {
    let mut mgr = make_bootmgr();
    mgr.process_boot().unwrap();

    // Put VM1 in trial on Bank B
    let mut state = mgr.nv().read_boot_state().unwrap();
    state.banks[1].active_bank = Bank::B;
    state.banks[1].committed = false;
    state.banks[1].boot_count = 3;
    mgr.nv_mut().write_boot_state(&mut state).unwrap();

    let action = mgr.handle_hash_failure(BankSet::Vm1).unwrap();
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

    let action = mgr.handle_hash_failure(BankSet::Vm1).unwrap();
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

    assert_eq!(mgr.active_bank(BankSet::HostOs), Some(Bank::A));
    assert_eq!(mgr.active_bank(BankSet::Vm1), Some(Bank::A));
    assert_eq!(mgr.active_bank(BankSet::Vm2), Some(Bank::A));
}

#[test]
fn is_trial_query() {
    let mut mgr = make_bootmgr();
    mgr.process_boot().unwrap();

    assert_eq!(mgr.is_trial(BankSet::Vm1), Some(false));

    // Put into trial
    let mut state = mgr.nv().read_boot_state().unwrap();
    state.banks[1].committed = false;
    mgr.nv_mut().write_boot_state(&mut state).unwrap();

    assert_eq!(mgr.is_trial(BankSet::Vm1), Some(true));
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
    mgr.nv_mut().write_fw_meta(BankSet::Vm1, Bank::B, &mut meta).unwrap();

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
    assert_eq!(mgr.verify_image(BankSet::Vm1, Bank::B, image), HashCheck::Ok);

    // Commit (simulating diagserver command)
    let mut state = mgr.nv().read_boot_state().unwrap();
    state.banks[1].committed = true;
    state.banks[1].boot_count = 0;
    mgr.nv_mut().write_boot_state(&mut state).unwrap();

    // Raise anti-rollback floor
    let mut meta = mgr.nv().read_fw_meta(BankSet::Vm1, Bank::B).unwrap();
    if meta.fw_secver > meta.min_security_ver {
        meta.min_security_ver = meta.fw_secver;
    }
    mgr.nv_mut().write_fw_meta(BankSet::Vm1, Bank::B, &mut meta).unwrap();

    // Next boot: committed on B
    let actions = mgr.process_boot().unwrap();
    assert_eq!(actions[1], BootAction::Boot { bank: Bank::B });

    // Verify anti-rollback floor was raised
    let meta = mgr.nv().read_fw_meta(BankSet::Vm1, Bank::B).unwrap();
    assert_eq!(meta.min_security_ver, 2);
}

#[test]
fn ota_trial_auto_rollback_cycle() {
    let mut mgr = make_bootmgr();
    mgr.process_boot().unwrap();

    // OTA: switch VM1 to Bank B, trial mode
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
bank_set = "vm1"
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
    assert_eq!(profile.vm.bank_set, "vm1");
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
bank_set = "vm1"
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
bank_set = "vm1"

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
bank_set = "vm1"

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
// YAML config parsing tests
// ============================================================

use crate::config::VmMgrConfig;

#[test]
fn parse_yaml_config() {
    let yaml = r#"
nv_store: /tmp/test-nv.bin
images_dir: /opt/images

components:
  vm1:
    bank_set: vm1
    backend: qemu
    profile: profiles/vm1.toml
    shutdown:
      timeout_secs: 15
      method: health
    readiness:
      method: health
      timeout_secs: 30
  vm2:
    bank_set: vm2
    backend: dummy
  hsm:
    bank_set: hsm
    backend: dummy
    single_bank: true
"#;

    let config = VmMgrConfig::from_yaml(yaml).unwrap();
    assert_eq!(config.nv_store.to_str().unwrap(), "/tmp/test-nv.bin");
    assert_eq!(config.images_dir.to_str().unwrap(), "/opt/images");
    assert_eq!(config.components.len(), 3);

    let vm1 = &config.components["vm1"];
    assert_eq!(vm1.bank_set, "vm1");
    assert_eq!(vm1.backend, "qemu");
    assert_eq!(vm1.profile.as_ref().unwrap().to_str().unwrap(), "profiles/vm1.toml");
    assert!(!vm1.single_bank);
    assert_eq!(vm1.shutdown.as_ref().unwrap().timeout_secs, 15);
    assert_eq!(vm1.readiness.as_ref().unwrap().timeout_secs, 30);

    let vm2 = &config.components["vm2"];
    assert_eq!(vm2.backend, "dummy");
    assert!(vm2.profile.is_none());

    let hsm = &config.components["hsm"];
    assert!(hsm.single_bank);
}

#[test]
fn parse_yaml_config_defaults() {
    let yaml = r#"
nv_store: /tmp/nv.bin
images_dir: /images

components:
  vm1:
    bank_set: vm1
"#;

    let config = VmMgrConfig::from_yaml(yaml).unwrap();
    let vm1 = &config.components["vm1"];
    assert_eq!(vm1.backend, "dummy"); // default backend
    assert!(!vm1.single_bank);
    assert!(vm1.shutdown.is_none());
    assert!(vm1.readiness.is_none());
}

#[test]
fn device_needs_ivshmem() {
    use crate::config::DeviceConfig;

    // Health and Time always need ivshmem
    assert!(DeviceConfig::Health { backend: "simulated".into() }.needs_ivshmem());
    assert!(DeviceConfig::Health { backend: "native".into() }.needs_ivshmem());
    assert!(DeviceConfig::Time { backend: "simulated".into() }.needs_ivshmem());
    assert!(DeviceConfig::Time { backend: "native".into() }.needs_ivshmem());

    // CAN needs ivshmem unless host-passthrough
    assert!(DeviceConfig::Can { index: 0, backend: "simulated".into(), interface: None }.needs_ivshmem());
    assert!(DeviceConfig::Can { index: 0, backend: "native".into(), interface: None }.needs_ivshmem());
    assert!(!DeviceConfig::Can { index: 0, backend: "host-passthrough".into(), interface: Some("vcan0".into()) }.needs_ivshmem());

    // HSM, Network, Disk, Console never need ivshmem
    assert!(!DeviceConfig::Hsm { keystore: None, keygen_bin: None, port: 5100 }.needs_ivshmem());
    assert!(!DeviceConfig::Network { mac: None, ssh_port: None }.needs_ivshmem());
    assert!(!DeviceConfig::Disk { role: "data".into(), path: "d.img".into(), readonly: false }.needs_ivshmem());
    assert!(!DeviceConfig::Console.needs_ivshmem());
}

#[test]
fn device_needs_simulator() {
    use crate::config::DeviceConfig;

    // Only "simulated" backend needs a simulator
    assert!(DeviceConfig::Health { backend: "simulated".into() }.needs_simulator());
    assert!(!DeviceConfig::Health { backend: "native".into() }.needs_simulator());
    assert!(DeviceConfig::Time { backend: "simulated".into() }.needs_simulator());
    assert!(!DeviceConfig::Time { backend: "native".into() }.needs_simulator());
    assert!(DeviceConfig::Can { index: 0, backend: "simulated".into(), interface: None }.needs_simulator());
    assert!(!DeviceConfig::Can { index: 0, backend: "native".into(), interface: None }.needs_simulator());
    assert!(!DeviceConfig::Can { index: 0, backend: "host-passthrough".into(), interface: Some("vcan0".into()) }.needs_simulator());

    // Non-ivshmem devices never need a simulator (via this method)
    assert!(!DeviceConfig::Hsm { keystore: None, keygen_bin: None, port: 5100 }.needs_simulator());
    assert!(!DeviceConfig::Network { mac: None, ssh_port: None }.needs_simulator());
    assert!(!DeviceConfig::Console.needs_simulator());
}

// --- Arch enum ---

#[test]
fn arch_from_str_accepts_common_aliases() {
    assert_eq!(Arch::from_str("aarch64"), Some(Arch::Aarch64));
    assert_eq!(Arch::from_str("arm64"), Some(Arch::Aarch64));
    assert_eq!(Arch::from_str("x86_64"), Some(Arch::X86_64));
    assert_eq!(Arch::from_str("amd64"), Some(Arch::X86_64));
    assert_eq!(Arch::from_str("riscv64"), None);
    assert_eq!(Arch::from_str(""), None);
}

#[test]
fn arch_selects_distinct_qemu_binary_per_arch() {
    assert_ne!(Arch::Aarch64.qemu_binary(), Arch::X86_64.qemu_binary());
    assert!(Arch::Aarch64.qemu_binary().contains("aarch64"));
    assert!(Arch::X86_64.qemu_binary().contains("x86_64"));
}

#[test]
fn arch_machine_type_console_and_cpu_defaults_are_distinct() {
    // These go straight onto the QEMU command line — smoke-test they're non-empty and differ.
    for (a, b) in [
        (Arch::Aarch64.machine_type(), Arch::X86_64.machine_type()),
        (Arch::Aarch64.console_device(), Arch::X86_64.console_device()),
        (Arch::Aarch64.default_cpu(), Arch::X86_64.default_cpu()),
    ] {
        assert!(!a.is_empty());
        assert!(!b.is_empty());
        assert_ne!(a, b);
    }
}

#[test]
fn arch_virtio_device_uses_expected_transport_suffix() {
    assert_eq!(Arch::Aarch64.virtio_device("blk"), "virtio-blk-device");
    assert_eq!(Arch::X86_64.virtio_device("net"), "virtio-net-pci");
}

#[test]
fn arch_reverse_disk_order_true_only_on_aarch64() {
    assert!(Arch::Aarch64.reverse_disk_order());
    assert!(!Arch::X86_64.reverse_disk_order());
}

#[test]
fn vm_profile_arch_default_is_aarch64() {
    let toml = r#"
[vm]
bank_set = "vm1"
"#;
    let profile = VmProfile::from_toml(toml).unwrap();
    assert_eq!(profile.arch(), Arch::Aarch64);
}

#[test]
fn vm_profile_arch_parses_x86_64() {
    let toml = r#"
[vm]
bank_set = "vm1"
arch = "x86_64"
"#;
    let profile = VmProfile::from_toml(toml).unwrap();
    assert_eq!(profile.arch(), Arch::X86_64);
}

#[test]
fn vm_profile_unknown_arch_falls_back_to_aarch64() {
    // arch() is the only consumer and is defined to fall back on unknown strings.
    let toml = r#"
[vm]
bank_set = "vm1"
arch = "potato"
"#;
    let profile = VmProfile::from_toml(toml).unwrap();
    assert_eq!(profile.arch(), Arch::Aarch64);
}

// --- DeviceConfig::ivshmem_label / ivshmem_magic ---

#[test]
fn ivshmem_label_for_health_time_and_can() {
    use crate::config::DeviceConfig;
    assert_eq!(
        DeviceConfig::Health { backend: "simulated".into() }.ivshmem_label().as_deref(),
        Some("health")
    );
    assert_eq!(
        DeviceConfig::Time { backend: "simulated".into() }.ivshmem_label().as_deref(),
        Some("time")
    );
    assert_eq!(
        DeviceConfig::Can { index: 3, backend: "simulated".into(), interface: None }
            .ivshmem_label()
            .as_deref(),
        Some("can3")
    );
}

#[test]
fn ivshmem_label_none_for_non_shm_devices() {
    use crate::config::DeviceConfig;
    assert!(DeviceConfig::Hsm { keystore: None, keygen_bin: None, port: 1 }.ivshmem_label().is_none());
    assert!(DeviceConfig::Network { mac: None, ssh_port: None }.ivshmem_label().is_none());
    assert!(DeviceConfig::Console.ivshmem_label().is_none());
    // CAN passthrough: needs_ivshmem=false → label=None
    assert!(DeviceConfig::Can {
        index: 0,
        backend: "host-passthrough".into(),
        interface: Some("vcan0".into())
    }
    .ivshmem_label()
    .is_none());
}

#[test]
fn ivshmem_magic_matches_guest_driver_constants() {
    // These magics are read by the guest drivers — wire-format-freeze check.
    use crate::config::DeviceConfig;
    assert_eq!(
        DeviceConfig::Health { backend: "simulated".into() }.ivshmem_magic(),
        Some(0x48544C48) // "HLTH"
    );
    assert_eq!(
        DeviceConfig::Time { backend: "simulated".into() }.ivshmem_magic(),
        Some(0x54494D45) // "TIME"
    );
    assert_eq!(
        DeviceConfig::Can { index: 0, backend: "simulated".into(), interface: None }
            .ivshmem_magic(),
        Some(0x4E414356) // "VCAN"
    );
    assert!(DeviceConfig::Console.ivshmem_magic().is_none());
}
