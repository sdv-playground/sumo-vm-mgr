/// Generate demo SUIT artifacts demonstrating the firmware/manifest separation.
///
/// Firmware binaries are content-addressable (stored by SHA-256 hash).
/// Manifests are tiny signed policy documents (~500 bytes) referencing
/// the firmware by digest. The same firmware can be re-signed with
/// different security_version without changing the binary.
///
/// Run with:
///   cargo run --example build

use std::fs;
use std::path::Path;

use sumo_crypto::{CryptoBackend, RustCryptoBackend};
use sumo_offboard::keygen;
use sumo_offboard::ImageManifestBuilder;

const FIRMWARE_SIZE: usize = 1024 * 1024; // 1MB

/// Build a firmware binary and return (binary, sha256_hash).
fn build_firmware(crypto: &RustCryptoBackend) -> (Vec<u8>, [u8; 32]) {
    let mut firmware = vec![0u8; FIRMWARE_SIZE];
    crypto.random_bytes(&mut firmware).unwrap();
    let hash = crypto.sha256(&firmware);
    (firmware, hash)
}

/// Sign a manifest wrapping a firmware binary (integrated payload — single blob).
fn sign_integrated(
    signing_key: &sumo_offboard::CoseKey,
    component: &str,
    seq: u64,
    security_version: u64,
    version: &str,
    model_name: &str,
    spare_part: &str,
    firmware: &[u8],
    digest: &[u8; 32],
) -> Vec<u8> {
    ImageManifestBuilder::new()
        .component_id(vec![component.to_string()])
        .sequence_number(seq)
        .security_version(security_version)
        .payload_digest(digest, firmware.len() as u64)
        .integrated_payload("#firmware".to_string(), firmware.to_vec())
        .text_version(version)
        .text_vendor_name("vm-mgr")
        .text_model_name(model_name)
        .text_model_info(format!("{}-SW-{:03}", component.to_uppercase(), seq))
        .text_description(spare_part)
        .build(signing_key)
        .unwrap()
}

/// Sign a manifest referencing firmware by digest only (no payload — tiny manifest).
/// The firmware must be available separately (content-addressable storage, tester cache, etc.)
fn sign_reference(
    signing_key: &sumo_offboard::CoseKey,
    component: &str,
    seq: u64,
    security_version: u64,
    version: &str,
    model_name: &str,
    spare_part: &str,
    firmware_size: u64,
    digest: &[u8; 32],
) -> Vec<u8> {
    ImageManifestBuilder::new()
        .component_id(vec![component.to_string()])
        .sequence_number(seq)
        .security_version(security_version)
        .payload_digest(digest, firmware_size)
        .text_version(version)
        .text_vendor_name("vm-mgr")
        .text_model_name(model_name)
        .text_model_info(format!("{}-SW-{:03}", component.to_uppercase(), seq))
        .text_description(spare_part)
        .build(signing_key)
        .unwrap()
}

/// Sign a CRL manifest — no payload, just raises the anti-rollback floor.
fn sign_crl(
    signing_key: &sumo_offboard::CoseKey,
    component: &str,
    seq: u64,
    security_version: u64,
) -> Vec<u8> {
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
    let fw_dir = output_dir.join("firmware");
    fs::create_dir_all(&keys_dir).unwrap();
    fs::create_dir_all(&fw_dir).unwrap();

    let crypto = RustCryptoBackend::new();

    // ---------------------------------------------------------------
    // 1. Generate signing key
    // ---------------------------------------------------------------
    println!("[build] generating ES256 signing key...");
    let signing_key = keygen::generate_signing_key(keygen::ES256).unwrap();
    fs::write(keys_dir.join("signing.key"), signing_key.to_cose_key_bytes()).unwrap();
    fs::write(keys_dir.join("signing.pub"), signing_key.public_key_bytes()).unwrap();
    println!("[build] wrote keys to {}", keys_dir.display());

    // ---------------------------------------------------------------
    // 2. Build 4 firmware binaries (content-addressable by SHA-256)
    // ---------------------------------------------------------------
    println!("\n[build] === Firmware binaries ===");

    struct FwBuild {
        version: &'static str,
        binary: Vec<u8>,
        digest: [u8; 32],
    }

    let builds: Vec<FwBuild> = ["1.0.0", "1.1.0", "1.2.0", "1.3.0"]
        .iter()
        .map(|v| {
            let (binary, digest) = build_firmware(&crypto);
            let hash_hex: String = digest.iter().map(|b| format!("{b:02x}")).collect();
            let fw_path = fw_dir.join(format!("{}.bin", hash_hex));
            fs::write(&fw_path, &binary).unwrap();
            println!("[build] v{v} → {} ({} bytes, hash: {}…)",
                fw_path.display(), binary.len(), &hash_hex[..16]);
            FwBuild { version: v, binary, digest }
        })
        .collect();

    // ---------------------------------------------------------------
    // 3. Initial release — all versions get security_version=1
    //    (freely up/downgradable, A/B testing between any of them)
    // ---------------------------------------------------------------
    println!("\n[build] === Initial manifests (secver=1, integrated) ===");

    for (i, fw) in builds.iter().enumerate() {
        let filename = format!("os1-v{}.suit", fw.version);
        let envelope = sign_integrated(
            &signing_key, "os1", (i + 1) as u64, 1,
            fw.version, "OS1-Linux",
            &format!("OS1-SP-{}", fw.version.replace('.', "")),
            &fw.binary, &fw.digest,
        );
        let path = output_dir.join(&filename);
        fs::write(&path, &envelope).unwrap();
        println!("[build] {} ({} bytes, secver=1)", filename, envelope.len());
    }

    // ---------------------------------------------------------------
    // 4. Security incident — re-sign 1.2.0 and 1.3.0 with secver=2
    //    (reference-only manifests — firmware is in content-addressable store)
    // ---------------------------------------------------------------
    println!("\n[build] === Re-signed manifests after security incident (secver=2, reference-only) ===");

    for (i, fw) in builds.iter().enumerate().skip(2) {
        let filename = format!("os1-v{}-secver2.suit", fw.version);
        let envelope = sign_reference(
            &signing_key, "os1", (i + 1) as u64, 2,
            fw.version, "OS1-Linux",
            &format!("OS1-SP-{}", fw.version.replace('.', "")),
            fw.binary.len() as u64, &fw.digest,
        );
        let path = output_dir.join(&filename);
        fs::write(&path, &envelope).unwrap();
        println!("[build] {} ({} bytes, secver=2, no payload)", filename, envelope.len());
    }

    // ---------------------------------------------------------------
    // 5. CRL manifest — raises floor to 2, blocking 1.0.0 and 1.1.0
    // ---------------------------------------------------------------
    println!("\n[build] === CRL manifest ===");
    let crl = sign_crl(&signing_key, "os1", 100, 2);
    let crl_path = output_dir.join("os1-crl-secver2.suit");
    fs::write(&crl_path, &crl).unwrap();
    println!("[build] os1-crl-secver2.suit ({} bytes)", crl.len());

    // ---------------------------------------------------------------
    // 6. Usage
    // ---------------------------------------------------------------
    println!("\n=== Test scenarios ===");
    println!();
    println!("A/B testing (before security incident):");
    println!("  Flash 1.0.0, commit, flash 1.1.0, commit → both work");
    println!("  Flash 1.0.0 again → works (same security floor)");
    println!();
    println!("Security incident response:");
    println!("  Flash os1-crl-secver2.suit → raises floor to 2");
    println!("  Flash 1.0.0 → REJECTED (secver 1 < floor 2)");
    println!("  Flash 1.1.0 → REJECTED (secver 1 < floor 2)");
    println!("  Flash 1.2.0 (original, secver=1) → REJECTED");
    println!("  Flash os1-v1.2.0-secver2.suit → works (re-signed, secver=2)");
    println!("  Flash os1-v1.3.0-secver2.suit → works (re-signed, secver=2)");
    println!();
    println!("Content-addressable workflow:");
    println!("  Re-signed manifests are ~500 bytes (no firmware payload)");
    println!("  Firmware binaries are in example/output/firmware/ (by SHA-256)");
    println!("  Tester caches firmware locally, receives only manifests from fleet server");
    println!();
    println!("SOVD Explorer → connect to http://localhost:4000");
}
