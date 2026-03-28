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

fn build_envelope(
    crypto: &RustCryptoBackend,
    signing_key: &sumo_offboard::CoseKey,
    component: &str,
    seq: u64,
) -> Vec<u8> {
    let mut firmware = vec![0u8; FIRMWARE_SIZE];
    crypto.random_bytes(&mut firmware).unwrap();
    let digest = crypto.sha256(&firmware);

    ImageManifestBuilder::new()
        .component_id(vec![component.to_string()])
        .sequence_number(seq)
        .payload_digest(&digest, firmware.len() as u64)
        .integrated_payload("#firmware".to_string(), firmware)
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

    // 2. Build firmware envelopes — two components, two versions each
    let images = [
        ("os1", 1u64, "os1-v1.suit"),
        ("os1", 2,    "os1-v2.suit"),
        ("os2", 1,    "os2-v1.suit"),
        ("os2", 2,    "os2-v2.suit"),
    ];

    for (component, seq, filename) in &images {
        println!("[build] building {filename} ({component} seq={seq})...");
        let envelope = build_envelope(&crypto, &signing_key, component, *seq);
        let path = output_dir.join(filename);
        fs::write(&path, &envelope).unwrap();
        println!("[build] wrote {} ({} bytes)", path.display(), envelope.len());
    }

    // 3. Print usage
    println!();
    println!("=== Demo artifacts ready ===");
    println!();
    println!("Start the SOVD server:");
    println!("  ./scripts/run.sh");
    println!();
    println!("Flash OS1 v1 then upgrade to v2:");
    println!("  curl -X POST http://localhost:4000/vehicle/v1/components/os1/files \\");
    println!("    --data-binary @example/output/os1-v1.suit");
    println!("  curl -X POST http://localhost:4000/vehicle/v1/components/os1/files/1/verify");
    println!("  curl -X POST http://localhost:4000/vehicle/v1/components/os1/flash/transfer \\");
    println!("    -H 'Content-Type: application/json' -d '{{\"file_id\": \"1\"}}'");
    println!("  curl -X POST http://localhost:4000/vehicle/v1/components/os1/flash/commit");
    println!();
    println!("  # Now upgrade to v2:");
    println!("  curl -X POST http://localhost:4000/vehicle/v1/components/os1/files \\");
    println!("    --data-binary @example/output/os1-v2.suit");
    println!("  # ... verify, transfer, commit as above");
    println!();
    println!("Or use SOVD Explorer → connect to http://localhost:4000");
}
