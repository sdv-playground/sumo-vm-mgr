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
use sumo_offboard::cose_key::CoseKey;
use sumo_offboard::encryptor;
use sumo_offboard::keygen;
use sumo_offboard::recipient::Recipient;
use sumo_offboard::ImageManifestBuilder;

const FIRMWARE_SIZE: usize = 1024 * 1024; // 1MB

/// Build a firmware binary and return (binary, sha256_hash).
fn build_firmware(crypto: &RustCryptoBackend) -> (Vec<u8>, [u8; 32]) {
    let mut firmware = vec![0u8; FIRMWARE_SIZE];
    crypto.random_bytes(&mut firmware).unwrap();
    let hash = crypto.sha256(&firmware);
    (firmware, hash)
}

/// Sign a manifest wrapping encrypted firmware (integrated payload).
///
/// Pipeline: firmware → compress (zstd) → encrypt (AES-GCM + ECDH-ES+A128KW per device)
/// The manifest carries encryption_info (COSE_Encrypt with wrapped CEK per recipient).
/// payload_digest is the plaintext hash (verified after decryption on device).
fn sign_integrated_encrypted(
    signing_key: &sumo_offboard::CoseKey,
    sender_key: &sumo_offboard::CoseKey,
    device_pub: &sumo_offboard::CoseKey,
    component: &str,
    seq: u64,
    security_version: u64,
    version: &str,
    model_name: &str,
    spare_part: &str,
    firmware: &[u8],
    digest: &[u8; 32],
) -> Vec<u8> {
    // Compress
    let compressed = encryptor::compress_firmware(firmware, 3).unwrap();

    // Encrypt (one CEK, wrapped per device)
    let recipients = [Recipient {
        public_key: CoseKey::from_cose_key_bytes(&device_pub.to_cose_key_bytes()).unwrap(),
        kid: b"device-1".to_vec(),
    }];
    let encrypted = encryptor::encrypt_firmware_ecdh(&compressed, sender_key, &recipients).unwrap();

    ImageManifestBuilder::new()
        .component_id(vec![component.to_string()])
        .sequence_number(seq)
        .security_version(security_version)
        .payload_digest(digest, firmware.len() as u64)
        .payload_uri("#firmware".to_string())
        .encryption_info(&encrypted.encryption_info)
        .integrated_payload("#firmware".to_string(), encrypted.ciphertext)
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
    // 1. Generate signing key + device key + sender key
    // ---------------------------------------------------------------
    println!("[build] generating keys...");
    let signing_key = keygen::generate_signing_key(keygen::ES256).unwrap();
    fs::write(keys_dir.join("signing.key"), signing_key.to_cose_key_bytes()).unwrap();
    fs::write(keys_dir.join("signing.pub"), signing_key.public_key_bytes()).unwrap();

    // Device ECDH key (on-device, for decrypting firmware)
    let device_key = keygen::generate_device_key(keygen::ES256).unwrap();
    fs::write(keys_dir.join("device.key"), device_key.to_cose_key_bytes()).unwrap();
    fs::write(keys_dir.join("device.pub"), device_key.public_key_bytes()).unwrap();

    // Sender ECDH key (build server, ephemeral per release)
    let sender_key = keygen::generate_device_key(keygen::ES256).unwrap();

    println!("[build] wrote keys to {}", keys_dir.display());

    // ---------------------------------------------------------------
    // 2. Build firmware binaries (content-addressable by SHA-256)
    // ---------------------------------------------------------------
    println!("\n[build] === Firmware binaries ===");

    struct FwBuild {
        version: &'static str,
        binary: Vec<u8>,
        digest: [u8; 32],
    }

    let build_fw = |component: &'static str, version: &'static str| -> FwBuild {
        let (binary, digest) = build_firmware(&crypto);
        let hash_hex: String = digest.iter().map(|b| format!("{b:02x}")).collect();
        let fw_path = fw_dir.join(format!("{}.bin", hash_hex));
        fs::write(&fw_path, &binary).unwrap();
        println!("[build] {component} v{version} → {} ({} bytes, hash: {}…)",
            fw_path.display(), binary.len(), &hash_hex[..16]);
        FwBuild { version, binary, digest }
    };

    // OS1: upgrade path 1.0.0 → 1.1.0 → 1.2.0 → 1.3.0
    let os1_builds: Vec<FwBuild> = ["1.0.0", "1.1.0", "1.2.0", "1.3.0"]
        .iter().map(|v| build_fw("os1", v)).collect();

    // HSM: single-bank firmware
    let hsm_build = build_fw("hsm", "1.1.0");

    // QTD: A/B banked firmware
    let qtd_build = build_fw("qtd", "1.1.0");

    // ---------------------------------------------------------------
    // 3. OS1 release — all versions get security_version=1
    // ---------------------------------------------------------------
    println!("\n[build] === OS1 manifests (secver=1, integrated) ===");

    for (i, fw) in os1_builds.iter().enumerate() {
        let filename = format!("os1-v{}.suit", fw.version);
        let envelope = sign_integrated_encrypted(
            &signing_key, &sender_key, &device_key,
            "os1", (i + 1) as u64, 1,
            fw.version, "OS1-Linux",
            &format!("OS1-SP-{}", fw.version.replace('.', "")),
            &fw.binary, &fw.digest,
        );
        let path = output_dir.join(&filename);
        fs::write(&path, &envelope).unwrap();
        println!("[build] {} ({} bytes, secver=1)", filename, envelope.len());
    }

    // ---------------------------------------------------------------
    // 4. HSM + QTD manifests
    // ---------------------------------------------------------------
    println!("\n[build] === HSM manifest (secver=1, integrated) ===");
    {
        let filename = format!("hsm-v{}.suit", hsm_build.version);
        let envelope = sign_integrated_encrypted(
            &signing_key, &sender_key, &device_key,
            "hsm", 1, 1,
            hsm_build.version, "HSM-Firmware",
            &format!("HSM-SP-{}", hsm_build.version.replace('.', "")),
            &hsm_build.binary, &hsm_build.digest,
        );
        let path = output_dir.join(&filename);
        fs::write(&path, &envelope).unwrap();
        println!("[build] {} ({} bytes, secver=1)", filename, envelope.len());
    }

    println!("\n[build] === QTD manifest (secver=1, integrated) ===");
    {
        let filename = format!("qtd-v{}.suit", qtd_build.version);
        let envelope = sign_integrated_encrypted(
            &signing_key, &sender_key, &device_key,
            "qtd", 1, 1,
            qtd_build.version, "QTD-QNX",
            &format!("QTD-SP-{}", qtd_build.version.replace('.', "")),
            &qtd_build.binary, &qtd_build.digest,
        );
        let path = output_dir.join(&filename);
        fs::write(&path, &envelope).unwrap();
        println!("[build] {} ({} bytes, secver=1)", filename, envelope.len());
    }

    // ---------------------------------------------------------------
    // 5. Security incident — re-sign OS1 1.2.0 and 1.3.0 with secver=2
    //    (reference-only manifests — firmware is in content-addressable store)
    // ---------------------------------------------------------------
    println!("\n[build] === Re-signed OS1 manifests after security incident (secver=2) ===");

    for (i, fw) in os1_builds.iter().enumerate().skip(2) {
        // Reference-only (no payload, for content-addressable workflow)
        let filename = format!("os1-v{}-secver2.suit", fw.version);
        let envelope = sign_reference(
            &signing_key, "os1", (i + 1) as u64, 2,
            fw.version, "OS1-Linux",
            &format!("OS1-SP-{}", fw.version.replace('.', "")),
            fw.binary.len() as u64, &fw.digest,
        );
        let path = output_dir.join(&filename);
        fs::write(&path, &envelope).unwrap();
        println!("[build] {} ({} bytes, secver=2, reference)", filename, envelope.len());

        // Integrated (with payload, for direct upload)
        let filename = format!("os1-v{}-secver2-full.suit", fw.version);
        let envelope = sign_integrated_encrypted(
            &signing_key, &sender_key, &device_key,
            "os1", (i + 1) as u64, 2,
            fw.version, "OS1-Linux",
            &format!("OS1-SP-{}", fw.version.replace('.', "")),
            &fw.binary, &fw.digest,
        );
        let path = output_dir.join(&filename);
        fs::write(&path, &envelope).unwrap();
        println!("[build] {} ({} bytes, secver=2, integrated)", filename, envelope.len());
    }

    // ---------------------------------------------------------------
    // 6. CRL manifest — raises floor to 2, blocking 1.0.0 and 1.1.0
    // ---------------------------------------------------------------
    println!("\n[build] === CRL manifest ===");
    let crl = sign_crl(&signing_key, "os1", 100, 2);
    let crl_path = output_dir.join("os1-crl-secver2.suit");
    fs::write(&crl_path, &crl).unwrap();
    println!("[build] os1-crl-secver2.suit ({} bytes)", crl.len());

    // ---------------------------------------------------------------
    // 7. Usage
    // ---------------------------------------------------------------
    println!("\n=== Components ===");
    println!();
    println!("  os1  — OS1 Linux VM (A/B banked, rollbackable)");
    println!("  os2  — OS2 Linux VM (A/B banked, rollbackable)");
    println!("  hsm  — Hardware Security Module (single-bank, non-rollbackable)");
    println!("  qtd  — QNX Target Partition (A/B banked, rollbackable)");
    println!("  hyp  — Hypervisor (A/B banked, rollbackable)");
    println!();
    println!("=== Test scenarios ===");
    println!();
    println!("Upgrade path (os1):");
    println!("  Flash 1.1.0 → commit → flash 1.2.0 → commit → flash 1.3.0 → commit");
    println!();
    println!("A/B testing:");
    println!("  Flash 1.3.0 → rollback (stay on 1.2.0) → flash 1.3.0 → commit");
    println!();
    println!("Security incident response:");
    println!("  Flash os1-crl-secver2.suit → raises floor to 2");
    println!("  Flash 1.0.0 → REJECTED (secver 1 < floor 2)");
    println!("  Flash os1-v1.2.0-secver2.suit → works (re-signed, secver=2)");
    println!();
    println!("HSM (single-bank):");
    println!("  Flash hsm-v1.1.0.suit → immediate commit, no rollback available");
    println!();
    println!("Content-addressable workflow:");
    println!("  Re-signed manifests are ~500 bytes (no firmware payload)");
    println!("  Firmware binaries are in example/output/firmware/ (by SHA-256)");
    println!();
    println!("SOVD Explorer → connect to http://localhost:4000");
}
