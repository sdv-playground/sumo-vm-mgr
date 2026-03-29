/// Generate demo SUIT artifacts: signing keys, dummy firmware, signed envelopes.
///
/// Run with:
///   cargo run --example build
///
/// Outputs:
///   example/keys/signing.key       — ES256 private key (COSE_Key CBOR)
///   example/keys/signing.pub       — ES256 public key (COSE_Key CBOR)
///   example/output/os1-v1.suit     — OS1 v1.0.0 (seq=1, 1MB firmware)
///   example/output/os1-v2.suit     — OS1 v2.0.0 (seq=2, 1MB firmware)
///   example/output/os2-v1.suit     — OS2 v1.0.0 (seq=1, 1MB firmware)
///   example/output/os2-v2.suit     — OS2 v2.0.0 (seq=2, 1MB firmware)

use std::fs;
use std::path::Path;

use sumo_crypto::{CryptoBackend, RustCryptoBackend};
use sumo_offboard::keygen;
use sumo_offboard::ImageManifestBuilder;

const FIRMWARE_SIZE: usize = 1024 * 1024; // 1MB

struct FwConfig {
    component: &'static str,
    seq: u64,
    security_version: u64,
    version: &'static str,
    model_name: &'static str,
    spare_part: &'static str,
    filename: &'static str,
}

fn build_envelope(
    crypto: &RustCryptoBackend,
    signing_key: &sumo_offboard::CoseKey,
    cfg: &FwConfig,
) -> Vec<u8> {
    let mut firmware = vec![0u8; FIRMWARE_SIZE];
    crypto.random_bytes(&mut firmware).unwrap();
    let digest = crypto.sha256(&firmware);

    ImageManifestBuilder::new()
        .component_id(vec![cfg.component.to_string()])
        .sequence_number(cfg.seq)
        .security_version(cfg.security_version)
        .payload_digest(&digest, firmware.len() as u64)
        .integrated_payload("#firmware".to_string(), firmware)
        .text_version(cfg.version)
        .text_vendor_name("vm-mgr")
        .text_model_name(cfg.model_name)
        .text_model_info(format!("{}-SW-{:03}", cfg.component.to_uppercase(), cfg.seq))
        .text_description(cfg.spare_part)
        .build(signing_key)
        .unwrap()
}

fn build_crl_envelope(
    signing_key: &sumo_offboard::CoseKey,
    component: &str,
    seq: u64,
    security_version: u64,
) -> Vec<u8> {
    // Security-floor-only manifest — no payload, just raises the anti-rollback floor.
    ImageManifestBuilder::new()
        .component_id(vec![component.to_string()])
        .sequence_number(seq)
        .security_version(security_version)
        .text_description(format!("CRL: block security_version < {security_version}"))
        .build(signing_key)
        .unwrap()
}

fn main() {
    let base = Path::new("example");
    let keys_dir = base.join("keys");
    let output_dir = base.join("output");
    fs::create_dir_all(&keys_dir).unwrap();
    fs::create_dir_all(&output_dir).unwrap();

    let crypto = RustCryptoBackend::new();

    // 1. Generate signing key
    println!("[build] generating ES256 signing key...");
    let signing_key = keygen::generate_signing_key(keygen::ES256).unwrap();

    let private_bytes = signing_key.to_cose_key_bytes();
    fs::write(keys_dir.join("signing.key"), &private_bytes).unwrap();
    println!("[build] wrote {}", keys_dir.join("signing.key").display());

    let public_bytes = signing_key.public_key_bytes();
    fs::write(keys_dir.join("signing.pub"), &public_bytes).unwrap();
    println!("[build] wrote {}", keys_dir.join("signing.pub").display());

    // 2. Build firmware envelopes
    //
    // All 1.x versions have security_version=1, freely up/downgradable.
    // After discovering a critical bug in < 1.2.0, a CRL manifest bumps
    // security_version to 2 — blocking 1.0.0 and 1.1.0 permanently.
    // 1.2.0 and 1.3.0 also carry security_version=2 so they survive the bump.
    let images = [
        // Freely interchangeable (secver=1)
        FwConfig { component: "os1", seq: 1, security_version: 1, version: "1.0.0", model_name: "OS1-Linux", spare_part: "OS1-SP-100", filename: "os1-v1.0.0.suit" },
        FwConfig { component: "os1", seq: 2, security_version: 1, version: "1.1.0", model_name: "OS1-Linux", spare_part: "OS1-SP-110", filename: "os1-v1.1.0.suit" },
        // Post-security-fix (secver=2) — still installable before CRL, required after
        FwConfig { component: "os1", seq: 3, security_version: 2, version: "1.2.0", model_name: "OS1-Linux", spare_part: "OS1-SP-120", filename: "os1-v1.2.0.suit" },
        FwConfig { component: "os1", seq: 4, security_version: 2, version: "1.3.0", model_name: "OS1-Linux", spare_part: "OS1-SP-130", filename: "os1-v1.3.0.suit" },
    ];

    for cfg in &images {
        println!("[build] building {} ({} v{} seq={} secver={})...",
            cfg.filename, cfg.component, cfg.version, cfg.seq, cfg.security_version);
        let envelope = build_envelope(&crypto, &signing_key, cfg);
        let path = output_dir.join(cfg.filename);
        fs::write(&path, &envelope).unwrap();
        println!("[build] wrote {} ({} bytes)", path.display(), envelope.len());
    }

    // 3. CRL manifest — bumps security floor to 2, blocking 1.0.0 and 1.1.0
    println!("[build] building CRL manifest (block secver < 2)...");
    let crl = build_crl_envelope(&signing_key, "os1", 100, 2);
    let crl_path = output_dir.join("os1-crl-secver2.suit");
    fs::write(&crl_path, &crl).unwrap();
    println!("[build] wrote {} ({} bytes)", crl_path.display(), crl.len());

    // 4. Print usage
    println!();
    println!("=== Demo artifacts ready ===");
    println!();
    println!("Firmware images:");
    println!("  os1-v1.0.0.suit  (secver=1)  freely installable");
    println!("  os1-v1.1.0.suit  (secver=1)  freely installable");
    println!("  os1-v1.2.0.suit  (secver=2)  survives CRL bump");
    println!("  os1-v1.3.0.suit  (secver=2)  survives CRL bump");
    println!("  os1-crl-secver2.suit          CRL: blocks secver < 2");
    println!();
    println!("Test scenario:");
    println!("  1. Flash 1.0.0, commit, flash 1.1.0, commit → both work (A/B testing)");
    println!("  2. Flash 1.0.0 again → works (same security floor)");
    println!("  3. Flash CRL manifest, commit → raises floor to 2");
    println!("  4. Flash 1.0.0 → REJECTED (secver 1 < floor 2)");
    println!("  5. Flash 1.1.0 → REJECTED (secver 1 < floor 2)");
    println!("  6. Flash 1.2.0 → works (secver 2 >= floor 2)");
    println!("  7. Flash 1.3.0 → works (secver 2 >= floor 2)");
    println!();
    println!("Or use SOVD Explorer → connect to http://localhost:4000");
}
