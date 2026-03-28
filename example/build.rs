/// Generate demo SUIT artifacts: signing keys, dummy firmware, signed envelope.
///
/// Run with:
///   cargo run --example build
///
/// Outputs:
///   example/keys/signing.key   — ES256 private key (COSE_Key CBOR)
///   example/keys/signing.pub   — ES256 public key (COSE_Key CBOR)
///   example/output/os1.suit    — Signed SUIT envelope with integrated 1MB firmware

use std::fs;
use std::path::Path;

use sumo_crypto::{CryptoBackend, RustCryptoBackend};
use sumo_offboard::keygen;
use sumo_offboard::ImageManifestBuilder;

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

    // Save private key
    let private_bytes = signing_key.to_cose_key_bytes();
    fs::write(keys_dir.join("signing.key"), &private_bytes).unwrap();
    println!("[build] wrote {}", keys_dir.join("signing.key").display());

    // Save public key
    let public_bytes = signing_key.public_key_bytes();
    fs::write(keys_dir.join("signing.pub"), &public_bytes).unwrap();
    println!("[build] wrote {}", keys_dir.join("signing.pub").display());

    // 2. Generate 1MB dummy firmware
    println!("[build] generating 1MB dummy firmware...");
    let mut firmware = vec![0u8; 1024 * 1024];
    crypto.random_bytes(&mut firmware).unwrap();

    // 3. Build SUIT envelope with integrated payload
    println!("[build] building signed SUIT envelope...");
    let digest = crypto.sha256(&firmware);

    let envelope = ImageManifestBuilder::new()
        .component_id(vec!["os1".to_string()])
        .sequence_number(1)
        .payload_digest(&digest, firmware.len() as u64)
        .integrated_payload("#firmware".to_string(), firmware)
        .build(&signing_key)
        .unwrap();

    let suit_path = output_dir.join("os1.suit");
    fs::write(&suit_path, &envelope).unwrap();
    println!("[build] wrote {} ({} bytes)", suit_path.display(), envelope.len());

    // 4. Print usage instructions
    println!();
    println!("=== Demo artifacts ready ===");
    println!();
    println!("Start the SOVD server:");
    println!("  cargo run --bin vm-sovd -- /tmp/vm-mgr-nv.bin example/keys/signing.pub");
    println!();
    println!("Upload the SUIT envelope:");
    println!("  curl -X POST http://localhost:8080/vehicle/v1/components/os1/files \\");
    println!("    -H 'Content-Type: application/octet-stream' \\");
    println!("    --data-binary @example/output/os1.suit");
    println!();
    println!("Then verify, transfer, and commit:");
    println!("  curl -X POST http://localhost:8080/vehicle/v1/components/os1/files/1/verify");
    println!("  curl -X POST http://localhost:8080/vehicle/v1/components/os1/flash/transfer \\");
    println!("    -H 'Content-Type: application/json' -d '{{\"file_id\": \"1\"}}'");
    println!("  curl -X POST http://localhost:8080/vehicle/v1/components/os1/flash/commit");
}
