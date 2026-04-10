/// Generate HSM key material as signed + encrypted SUIT envelopes.
///
/// All envelopes are compressed + encrypted (same code path). Factory
/// envelopes use the well-known factory KEK (scalar=1, public=G).
/// Re-provision envelopes use the real KEK from slot 0.
///
/// Output (default mode):
///   <output-dir>/hsm-keys-v1.suit — factory envelope (encrypted with factory KEK)
///   <output-dir>/hsm-keys-v2.suit — re-provision envelope (encrypted with real KEK)
///   <keys-dir>/hsm-kek.pub        — real KEK public key (COSE_Key CBOR)
///   <keys-dir>/hsm-kek.key        — real KEK full key (for decryption tests)
///
/// Output (--cbor-only mode):
///   stdout                         — raw CBOR keystore (pipe to sumo-tool build --manifest)
///   <keys-dir>/hsm-kek.pub        — real KEK public key
///   <keys-dir>/hsm-kek.key        — real KEK full key
///
/// Run with:
///   cargo run --example build_hsm_keys -- --signing-key <path> --device-key <path> --output-dir <path>
///
/// Or pipe to sumo-tool:
///   cargo run --example build_hsm_keys -- --cbor-only --signing-key <path> --device-key <path> \
///     | sumo-tool build --manifest hsm-keys.yaml

use std::fs;
use std::path::{Path, PathBuf};

use coset::iana;
use coset::CborSerializable;
use sumo_crypto::{CryptoBackend, RustCryptoBackend};
use sumo_offboard::cose_key::CoseKey;
use sumo_offboard::encryptor;
use sumo_offboard::keygen;
use sumo_offboard::recipient::Recipient;
use sumo_offboard::ImageManifestBuilder;

use hsm::payload::*;

/// Number of "application" key slots (in addition to 5 well-known + 3 test slots).
const NUM_APP_SLOTS: usize = 92;

/// Guest identities that can register with the HSM.
const GUESTS: &[&str] = &["bali-vm-1", "bali-vm-2", "bali-vm-3"];

fn usage() {
    eprintln!("Usage: build_hsm_keys --signing-key <path> --device-key <path> [--output-dir <path>] [--cbor-only]");
    eprintln!();
    eprintln!("  --signing-key <path>   Signing key (COSE_Key CBOR) — used for sw-authority slot");
    eprintln!("  --device-key <path>    Device key (ECDH P-256) — used for device-decrypt slot");
    eprintln!("  --output-dir <path>    Directory for .suit output files (required unless --cbor-only)");
    eprintln!("  --cbor-only            Write raw CBOR keystore to stdout, skip SUIT wrapping.");
    eprintln!("                         KEK key files are still written to --output-dir or example/keys/.");
    eprintln!("                         Pipe to: sumo-tool build --manifest hsm-keys.yaml");
}

fn main() {
    let args: Vec<String> = std::env::args().collect();

    let mut signing_key_path: Option<String> = None;
    let mut device_key_path: Option<String> = None;
    let mut output_dir_path: Option<String> = None;
    let mut cbor_only = false;
    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--signing-key" if i + 1 < args.len() => {
                signing_key_path = Some(args[i + 1].clone());
                i += 2;
            }
            "--device-key" if i + 1 < args.len() => {
                device_key_path = Some(args[i + 1].clone());
                i += 2;
            }
            "--output-dir" if i + 1 < args.len() => {
                output_dir_path = Some(args[i + 1].clone());
                i += 2;
            }
            "--cbor-only" => {
                cbor_only = true;
                i += 1;
            }
            other => {
                usage();
                eprintln!("\nUnknown argument: {other}");
                std::process::exit(1);
            }
        }
    }

    let signing_key_path = signing_key_path.unwrap_or_else(|| {
        usage();
        eprintln!("\nError: --signing-key is required");
        std::process::exit(1);
    });
    let device_key_path = device_key_path.unwrap_or_else(|| {
        usage();
        eprintln!("\nError: --device-key is required (ECDH P-256 for firmware decryption)");
        std::process::exit(1);
    });

    let output_dir = if let Some(ref p) = output_dir_path {
        PathBuf::from(p)
    } else if !cbor_only {
        usage();
        eprintln!("\nError: --output-dir is required (or use --cbor-only)");
        std::process::exit(1);
    } else {
        PathBuf::new() // not used in cbor-only mode
    };

    let keys_dir = if let Some(ref p) = output_dir_path {
        // Write KEK files next to output
        PathBuf::from(p)
    } else {
        Path::new("example").join("keys")
    };
    fs::create_dir_all(&keys_dir).unwrap();
    if !cbor_only {
        fs::create_dir_all(&output_dir).unwrap();
    }

    let crypto = RustCryptoBackend::new();

    let signing_key = {
        let bytes = fs::read(&signing_key_path)
            .unwrap_or_else(|e| panic!("failed to read signing key {signing_key_path}: {e}"));
        CoseKey::from_cose_key_bytes(&bytes).unwrap()
    };

    // Load device key (ECDH P-256) — same key pair used for firmware decryption
    let device_key = {
        let bytes = fs::read(&device_key_path)
            .unwrap_or_else(|e| panic!("failed to read device key {device_key_path}: {e}"));
        CoseKey::from_cose_key_bytes(&bytes).unwrap()
    };

    // ---------------------------------------------------------------
    // 1. Generate key slots
    // ---------------------------------------------------------------
    println!("[hsm-keys] generating {} key slots...", NUM_APP_SLOTS + 8);

    let mut slots = Vec::with_capacity(NUM_APP_SLOTS + 8);

    // Slot 0: Real KEK (EC-P256) — its public key encrypts future envelopes
    let (kek_priv, kek_pub) = generate_ec_p256_raw();
    slots.push(KeySlotDef {
        key_id: "kek".to_string(),
        key_type: KEY_TYPE_EC_P256,
        private_key: kek_priv,
        public_key: Some(kek_pub.clone()),
        certificate: None,
        allowed_guests: None,
        allowed_ops: None,
    });

    // Slot 1: Software authority — public key of the signing key pair.
    // This is the trust anchor that verifies firmware SUIT envelopes on-device.
    // Must be the same key pair as signing.key so firmware signatures match.
    let (sw_auth_priv, sw_auth_pub) = extract_ec_raw(&signing_key);
    slots.push(KeySlotDef {
        key_id: "sw-authority".to_string(),
        key_type: KEY_TYPE_EC_P256,
        private_key: sw_auth_priv,
        public_key: Some(sw_auth_pub),
        certificate: None,
        allowed_guests: None,
        allowed_ops: Some(vec![OP_VERIFY, OP_GET_PUBKEY]),
    });

    // Slot 2: Device decryption key — ECDH P-256 for firmware decryption.
    // Must be the same key pair as device.key so encrypted firmware can be decrypted.
    let (dk_priv, dk_pub) = extract_ec_raw(&device_key);
    slots.push(KeySlotDef {
        key_id: "device-decrypt".to_string(),
        key_type: KEY_TYPE_EC_P256,
        private_key: dk_priv,
        public_key: Some(dk_pub),
        certificate: None,
        allowed_guests: None,
        allowed_ops: None, // ECDH key, not signing
    });

    // Slot 3: General ECU signing key with certificate
    let (priv_key, pub_key) = generate_ec_p256_raw();
    slots.push(KeySlotDef {
        key_id: "ecu-signing".to_string(),
        key_type: KEY_TYPE_EC_P256,
        private_key: priv_key,
        public_key: Some(pub_key),
        certificate: Some(dummy_self_signed_cert(&crypto)),
        allowed_guests: Some(vec!["bali-vm-1".into()]),
        allowed_ops: Some(vec![OP_SIGN, OP_VERIFY, OP_GET_CERT, OP_GET_PUBKEY]),
    });

    // Slot 4: JWT signing key for jwt-mgr
    let (priv_key, pub_key) = generate_ec_p256_raw();
    slots.push(KeySlotDef {
        key_id: "jwt-signing".to_string(),
        key_type: KEY_TYPE_EC_P256,
        private_key: priv_key,
        public_key: Some(pub_key),
        certificate: None,
        allowed_guests: Some(vec!["bali-vm-1".into()]),
        allowed_ops: Some(vec![OP_SIGN, OP_VERIFY, OP_GET_PUBKEY]),
    });

    // ---------------------------------------------------------------
    // Test keys (matching vhsm-test / test_all.sh expectations)
    // ---------------------------------------------------------------

    // "mykey" — EC-P256 for sign/verify tests
    let (priv_key, pub_key) = generate_ec_p256_raw();
    slots.push(KeySlotDef {
        key_id: "mykey".to_string(),
        key_type: KEY_TYPE_EC_P256,
        private_key: priv_key,
        public_key: Some(pub_key),
        certificate: Some(dummy_self_signed_cert(&crypto)),
        allowed_guests: Some(vec!["bali-vm-1".into()]),
        allowed_ops: Some(vec![OP_SIGN, OP_VERIFY, OP_GET_CERT, OP_GET_PUBKEY]),
    });

    // "storage-key" — AES-256 for encrypt/decrypt/derive tests
    let mut aes_data = vec![0u8; 32];
    crypto.random_bytes(&mut aes_data).unwrap();
    slots.push(KeySlotDef {
        key_id: "storage-key".to_string(),
        key_type: KEY_TYPE_AES_256,
        private_key: aes_data,
        public_key: None,
        certificate: None,
        allowed_guests: Some(vec!["bali-vm-1".into()]),
        allowed_ops: Some(vec![OP_ENCRYPT, OP_DECRYPT, OP_DERIVE]),
    });

    // "restricted-key" — ACL test: only bali-vm-2 can use it
    let mut aes_restricted = vec![0u8; 32];
    crypto.random_bytes(&mut aes_restricted).unwrap();
    slots.push(KeySlotDef {
        key_id: "restricted-key".to_string(),
        key_type: KEY_TYPE_AES_256,
        private_key: aes_restricted,
        public_key: None,
        certificate: None,
        allowed_guests: Some(vec!["bali-vm-2".into()]),
        allowed_ops: Some(vec![OP_ENCRYPT, OP_DECRYPT]),
    });

    // Generate remaining application slots
    for i in 0..NUM_APP_SLOTS {
        let slot_num = i + 7;
        if i % 3 == 0 {
            let mut key_data = vec![0u8; 32];
            crypto.random_bytes(&mut key_data).unwrap();
            let guest = GUESTS[i % GUESTS.len()];
            slots.push(KeySlotDef {
                key_id: format!("aes-{slot_num:03}"),
                key_type: KEY_TYPE_AES_256,
                private_key: key_data,
                public_key: None,
                certificate: None,
                allowed_guests: Some(vec![guest.to_string()]),
                allowed_ops: Some(vec![OP_ENCRYPT, OP_DECRYPT, OP_DERIVE]),
            });
        } else {
            let (priv_key, pub_key) = generate_ec_p256_raw();
            let guest = GUESTS[i % GUESTS.len()];
            slots.push(KeySlotDef {
                key_id: format!("ec-{slot_num:03}"),
                key_type: KEY_TYPE_EC_P256,
                private_key: priv_key,
                public_key: Some(pub_key),
                certificate: None,
                allowed_guests: Some(vec![guest.to_string()]),
                allowed_ops: Some(vec![OP_SIGN, OP_VERIFY, OP_GET_PUBKEY]),
            });
        }
    }

    println!("[hsm-keys] {} slots: {} EC-P256, {} AES-256",
        slots.len(),
        slots.iter().filter(|s| s.key_type == KEY_TYPE_EC_P256).count(),
        slots.iter().filter(|s| s.key_type == KEY_TYPE_AES_256).count(),
    );

    // ---------------------------------------------------------------
    // 2. Generate guest identities
    // ---------------------------------------------------------------
    let identities: Vec<IdentityDef> = GUESTS
        .iter()
        .map(|guest| {
            let (_priv_key, pub_key) = generate_ec_p256_raw();
            IdentityDef {
                identity_id: guest.to_string(),
                public_key: pub_key,
            }
        })
        .collect();

    println!("[hsm-keys] {} guest identities", identities.len());

    // ---------------------------------------------------------------
    // 3. Build keystores and serialize to CBOR
    // ---------------------------------------------------------------
    let keystore = HsmKeystore {
        schema_version: SCHEMA_VERSION,
        security_version: 1,
        identities: identities.clone(),
        slots: slots.clone(),
        kek_slot_index: Some(0),
    };

    let cbor = encode(&keystore).unwrap();
    eprintln!("[hsm-keys] CBOR payload: {} bytes", cbor.len());

    let digest = crypto.sha256(&cbor);

    // ---------------------------------------------------------------
    // Export KEK key files (needed for encryption by external tools)
    // ---------------------------------------------------------------
    let (kek_priv_raw, kek_pub_ref) = (kek_priv_bytes(&slots[0]), &kek_pub);
    let real_kek_cose = build_device_cose_key(
        &kek_priv_raw,
        &kek_pub_ref[1..33],
        &kek_pub_ref[33..65],
    );
    let real_kek_pub_cose = build_public_cose_key(
        &kek_pub_ref[1..33],
        &kek_pub_ref[33..65],
    );

    let kek_pub_path = keys_dir.join("hsm-kek.pub");
    fs::write(&kek_pub_path, &real_kek_pub_cose).unwrap();
    let kek_key_path = keys_dir.join("hsm-kek.key");
    fs::write(&kek_key_path, &real_kek_cose).unwrap();
    eprintln!("[hsm-keys] KEK public key: {}", kek_pub_path.display());
    eprintln!("[hsm-keys] KEK private key: {}", kek_key_path.display());

    // ---------------------------------------------------------------
    // --cbor-only: write raw CBOR to stdout, skip SUIT envelope wrapping
    // ---------------------------------------------------------------
    if cbor_only {
        use std::io::Write;
        std::io::stdout().write_all(&cbor).unwrap();
        std::io::stdout().flush().unwrap();
        eprintln!(
            "[hsm-keys] wrote {} bytes CBOR to stdout ({} slots, {} identities)",
            cbor.len(),
            keystore.slots.len(),
            keystore.identities.len(),
        );
        eprintln!("[hsm-keys] pipe to: sumo-tool build --manifest <yaml>");
        return;
    }

    // ---------------------------------------------------------------
    // 4. Factory envelope (compressed + encrypted with factory KEK)
    // ---------------------------------------------------------------
    println!("\n[hsm-keys] === Factory envelope (encrypted with factory KEK) ===");

    let factory_kek_cose = build_device_cose_key(
        &FACTORY_KEK_SCALAR,
        &FACTORY_KEK_PUBLIC[1..33],  // x
        &FACTORY_KEK_PUBLIC[33..65], // y
    );
    let factory_kek_pub_cose = build_public_cose_key(
        &FACTORY_KEK_PUBLIC[1..33],
        &FACTORY_KEK_PUBLIC[33..65],
    );

    let factory_envelope = build_encrypted_envelope(
        &signing_key,
        &factory_kek_cose,
        &factory_kek_pub_cose,
        &cbor,
        &digest,
        1, // sequence_number
        1, // security_version
        "1.0.0",
        "Factory HSM key provisioning (100 slots, factory KEK)",
    );

    let factory_path = output_dir.join("hsm-keys-v1.suit");
    fs::write(&factory_path, &factory_envelope).unwrap();
    println!("[hsm-keys] {} ({} bytes)",
        factory_path.display(), factory_envelope.len());

    // ---------------------------------------------------------------
    // 5. Re-provision envelope (compressed + encrypted with real KEK)
    // ---------------------------------------------------------------
    println!("\n[hsm-keys] === Re-provision envelope (encrypted with real KEK) ===");

    let mut keystore_v2 = keystore.clone();
    keystore_v2.security_version = 2;
    let cbor_v2 = encode(&keystore_v2).unwrap();
    let digest_v2 = crypto.sha256(&cbor_v2);

    let reprov_envelope = build_encrypted_envelope(
        &signing_key,
        &real_kek_cose,
        &real_kek_pub_cose,
        &cbor_v2,
        &digest_v2,
        2,
        2,
        "2.0.0",
        "Re-provision HSM keys (100 slots, real KEK)",
    );

    let reprov_path = output_dir.join("hsm-keys-v2.suit");
    fs::write(&reprov_path, &reprov_envelope).unwrap();
    println!("[hsm-keys] {} ({} bytes)",
        reprov_path.display(), reprov_envelope.len());

    // ---------------------------------------------------------------
    // 6. Summary
    // ---------------------------------------------------------------
    println!("\n=== HSM Key Provisioning Artifacts ===");
    println!();
    println!("  Factory envelope:      {} ({} bytes, factory KEK)",
        factory_path.display(), factory_envelope.len());
    println!("  Re-provision envelope: {} ({} bytes, real KEK)",
        reprov_path.display(), reprov_envelope.len());
    println!("  KEK public key:        {}", kek_pub_path.display());
    println!("  Signing key:           {}", keys_dir.join("signing.key").display());
    println!();
    println!("  Key slots:     {}", keystore.slots.len());
    println!("  Identities:    {}", keystore.identities.len());
    println!("  CBOR payload:  {} bytes", cbor.len());
    println!();
    println!("Both envelopes use the same pipeline: CBOR → zstd → AES-GCM → SUIT.");
    println!("Factory uses well-known KEK (scalar=1). Re-provision uses real KEK.");
}

/// Build a compressed + encrypted SUIT envelope.
fn build_encrypted_envelope(
    signing_key: &CoseKey,
    sender_key_cbor: &[u8],
    recipient_pub_cbor: &[u8],
    cbor_payload: &[u8],
    plaintext_digest: &[u8; 32],
    seq: u64,
    security_version: u64,
    version: &str,
    description: &str,
) -> Vec<u8> {
    let _sender_key = CoseKey::from_cose_key_bytes(sender_key_cbor).unwrap();
    let recipient_pub = CoseKey::from_cose_key_bytes(recipient_pub_cbor).unwrap();

    // Compress
    let compressed = encryptor::compress_firmware(cbor_payload, 3).unwrap();

    // Encrypt (ECDH-ES+A128KW + AES-128-GCM)
    // Use a fresh ephemeral sender key for each envelope
    let ephemeral_sender = keygen::generate_device_key(keygen::ES256).unwrap();
    let recipients = [Recipient {
        public_key: recipient_pub,
        kid: b"hsm-kek".to_vec(),
    }];
    let encrypted = encryptor::encrypt_firmware_ecdh(
        &compressed,
        &ephemeral_sender,
        &recipients,
    ).unwrap();

    // Build SUIT envelope
    ImageManifestBuilder::new()
        .component_id(vec!["hsm".to_string(), "keys".to_string()])
        .sequence_number(seq)
        .security_version(security_version)
        .payload_digest(plaintext_digest, cbor_payload.len() as u64)
        .payload_uri("#hsm-keys".to_string())
        .encryption_info(&encrypted.encryption_info)
        .integrated_payload("#hsm-keys".to_string(), encrypted.ciphertext)
        .text_version(version)
        .text_vendor_name("vm-mgr")
        .text_model_name("HSM-Keys")
        .text_description(description)
        .build(signing_key)
        .unwrap()
}

/// Build a COSE_Key (EC2, P-256, private) as CBOR bytes.
fn build_device_cose_key(d: &[u8], x: &[u8], y: &[u8]) -> Vec<u8> {
    let mut key = coset::CoseKeyBuilder::new_ec2_priv_key(
        iana::EllipticCurve::P_256,
        x.to_vec(),
        y.to_vec(),
        d.to_vec(),
    )
    .build();
    key.alg = None; // Device key — ECDH, not signing
    key.to_vec().unwrap()
}

/// Build a COSE_Key (EC2, P-256, public only) as CBOR bytes.
fn build_public_cose_key(x: &[u8], y: &[u8]) -> Vec<u8> {
    let mut key = coset::CoseKeyBuilder::new_ec2_pub_key(
        iana::EllipticCurve::P_256,
        x.to_vec(),
        y.to_vec(),
    )
    .build();
    key.alg = None;
    key.to_vec().unwrap()
}

/// Extract raw EC-P256 key material from an existing CoseKey.
/// Returns (32-byte scalar, 65-byte uncompressed public).
fn extract_ec_raw(key: &CoseKey) -> (Vec<u8>, Vec<u8>) {
    let cose_bytes = key.to_cose_key_bytes();
    let cose_key: coset::CoseKey = coset::CoseKey::from_slice(&cose_bytes).unwrap();

    let mut d = Vec::new();
    let mut x = Vec::new();
    let mut y = Vec::new();

    for (label, value) in &cose_key.params {
        if let (coset::Label::Int(n), ciborium::Value::Bytes(bytes)) = (label, value) {
            match *n {
                -4 => d = bytes.clone(),
                -2 => x = bytes.clone(),
                -3 => y = bytes.clone(),
                _ => {}
            }
        }
    }

    let mut pub_key = Vec::with_capacity(65);
    pub_key.push(0x04);
    pub_key.extend_from_slice(&x);
    pub_key.extend_from_slice(&y);

    (d, pub_key)
}

/// Generate a raw EC-P256 key pair: (32-byte scalar, 65-byte uncompressed public).
fn generate_ec_p256_raw() -> (Vec<u8>, Vec<u8>) {
    let key = keygen::generate_device_key(keygen::ES256).unwrap();
    let cose_bytes = key.to_cose_key_bytes();
    let cose_key: coset::CoseKey = coset::CoseKey::from_slice(&cose_bytes).unwrap();

    let mut d = Vec::new();
    let mut x = Vec::new();
    let mut y = Vec::new();

    for (label, value) in &cose_key.params {
        if let (coset::Label::Int(n), ciborium::Value::Bytes(bytes)) = (label, value) {
            match *n {
                -4 => d = bytes.clone(), // EC2 d
                -2 => x = bytes.clone(), // EC2 x
                -3 => y = bytes.clone(), // EC2 y
                _ => {}
            }
        }
    }

    let mut pub_key = Vec::with_capacity(65);
    pub_key.push(0x04);
    pub_key.extend_from_slice(&x);
    pub_key.extend_from_slice(&y);

    (d, pub_key)
}

/// Extract private key bytes from a KeySlotDef.
fn kek_priv_bytes(slot: &KeySlotDef) -> Vec<u8> {
    slot.private_key.clone()
}

/// Generate a dummy self-signed certificate (fake DER for testing).
fn dummy_self_signed_cert(crypto: &RustCryptoBackend) -> Vec<u8> {
    let mut cert = vec![0x30, 0x82, 0x01, 0x00];
    let mut body = vec![0u8; 252];
    crypto.random_bytes(&mut body).unwrap();
    cert.extend_from_slice(&body);
    cert
}
