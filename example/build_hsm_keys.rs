/// Generate HSM key material as signed + encrypted SUIT envelopes.
///
/// Trust model:
///   - Factory envelope: signed with factory signing key, encrypted to device public key.
///   - Re-provision envelope: signed with Key Authority, encrypted to device public key.
///   - Key Authority (slot 0): generated fresh, delivered in factory envelope.
///     Device uses it to verify subsequent HSM key envelopes.
///
/// Output (default mode):
///   <output-dir>/hsm-keys-v1.suit       — factory envelope (signed: factory key, encrypted: device key)
///   <output-dir>/hsm-keys-v2.suit       — re-provision envelope (signed: key authority, encrypted: device key)
///   <keys-dir>/key-authority.pub        — Key Authority public key (COSE_Key CBOR)
///   <keys-dir>/key-authority.key        — Key Authority full key (for re-provisioning)
///
/// Output (--cbor-only mode):
///   stdout                              — raw CBOR keystore (pipe to sumo-tool build --manifest)
///   <keys-dir>/key-authority.pub        — Key Authority public key
///   <keys-dir>/key-authority.key        — Key Authority full key
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
    eprintln!("Usage: build_hsm_keys [--signing-key <path>] [--device-pub <path>|--device-csr <path>] [--output-dir <path>] [--cbor-only]");
    eprintln!();
    eprintln!("  --signing-key <path>   Signing key (COSE_Key CBOR) — used for sw-authority slot.");
    eprintln!("                         Default: factory signing key (P-256 generator, scalar=1).");
    eprintln!("  --device-pub <path>    Device public key (COSE_Key CBOR) — encryption target.");
    eprintln!("  --device-csr <path>    Device CSR (PKCS#10 DER) — extracts public key.");
    eprintln!("                         Either --device-pub or --device-csr is required.");
    eprintln!("  --output-dir <path>    Directory for .suit output files (required unless --cbor-only)");
    eprintln!("  --cbor-only            Write raw CBOR keystore to stdout, skip SUIT wrapping.");
    eprintln!("                         Key Authority files are still written to --output-dir or example/keys/.");
    eprintln!("                         Pipe to: sumo-tool build --manifest hsm-keys.yaml");
}

fn main() {
    let args: Vec<String> = std::env::args().collect();

    let mut signing_key_path: Option<String> = None;
    let mut device_pub_path: Option<String> = None;
    let mut device_csr_path: Option<String> = None;
    let mut output_dir_path: Option<String> = None;
    let mut cbor_only = false;
    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--signing-key" if i + 1 < args.len() => {
                signing_key_path = Some(args[i + 1].clone());
                i += 2;
            }
            "--device-pub" if i + 1 < args.len() => {
                device_pub_path = Some(args[i + 1].clone());
                i += 2;
            }
            "--device-csr" if i + 1 < args.len() => {
                device_csr_path = Some(args[i + 1].clone());
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

    let signing_key_path = signing_key_path;
    if device_pub_path.is_none() && device_csr_path.is_none() {
        usage();
        eprintln!("\nError: one of --device-pub or --device-csr is required");
        std::process::exit(1);
    }
    if device_pub_path.is_some() && device_csr_path.is_some() {
        usage();
        eprintln!("\nError: --device-pub and --device-csr are mutually exclusive");
        std::process::exit(1);
    }

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
        PathBuf::from(p)
    } else {
        Path::new("example").join("keys")
    };
    fs::create_dir_all(&keys_dir).unwrap();
    if !cbor_only {
        fs::create_dir_all(&output_dir).unwrap();
    }

    let crypto = RustCryptoBackend::new();

    // Factory signing key — signs the first (factory) envelope.
    let envelope_signing_key = {
        let key = coset::CoseKeyBuilder::new_ec2_priv_key(
            iana::EllipticCurve::P_256,
            FACTORY_SIGNING_PUBLIC[1..33].to_vec(),
            FACTORY_SIGNING_PUBLIC[33..65].to_vec(),
            FACTORY_SIGNING_SCALAR.to_vec(),
        )
        .algorithm(iana::Algorithm::ES256)
        .build();
        CoseKey::from_cose_key_bytes(&key.to_vec().unwrap()).unwrap()
    };

    // Software authority key — its public half goes into the HSM keystore
    // for firmware signature verification. Defaults to factory signing key if not provided.
    let signing_key = if let Some(ref path) = signing_key_path {
        let bytes = fs::read(path)
            .unwrap_or_else(|e| panic!("failed to read signing key {path}: {e}"));
        CoseKey::from_cose_key_bytes(&bytes).unwrap()
    } else {
        eprintln!("[hsm-keys] using factory signing key as software authority (no --signing-key)");
        let key = coset::CoseKeyBuilder::new_ec2_priv_key(
            iana::EllipticCurve::P_256,
            FACTORY_SIGNING_PUBLIC[1..33].to_vec(),
            FACTORY_SIGNING_PUBLIC[33..65].to_vec(),
            FACTORY_SIGNING_SCALAR.to_vec(),
        )
        .algorithm(iana::Algorithm::ES256)
        .build();
        CoseKey::from_cose_key_bytes(&key.to_vec().unwrap()).unwrap()
    };

    // Load device public key — from CSR or public key file.
    // Private key never leaves the device.
    let dk_pub = if let Some(ref csr_path) = device_csr_path {
        let csr_der = fs::read(csr_path)
            .unwrap_or_else(|e| panic!("failed to read device CSR {csr_path}: {e}"));
        let pub_key = extract_ec_pubkey_from_csr(&csr_der)
            .unwrap_or_else(|e| panic!("failed to extract public key from CSR: {e}"));
        eprintln!("[hsm-keys] device public key extracted from CSR ({} bytes)", pub_key.len());
        pub_key
    } else {
        let pub_path = device_pub_path.unwrap();
        let bytes = fs::read(&pub_path)
            .unwrap_or_else(|e| panic!("failed to read device public key {pub_path}: {e}"));
        let pub_bytes = extract_ec_pub_only(&bytes);
        eprintln!("[hsm-keys] device public key loaded ({} bytes)", pub_bytes.len());
        pub_bytes
    };

    // ---------------------------------------------------------------
    // 1. Generate key slots
    // ---------------------------------------------------------------
    println!("[hsm-keys] generating {} key slots...", NUM_APP_SLOTS + 8);

    let mut slots = Vec::with_capacity(NUM_APP_SLOTS + 8);

    // Slot 0: Key Authority (EC-P256) — public key only, verifies subsequent HSM key envelopes.
    // Private key stays with the backend (never sent to device).
    let (ka_priv, ka_pub) = generate_ec_p256_raw();
    slots.push(KeySlotDef {
        key_id: "key-authority".to_string(),
        key_type: KEY_TYPE_EC_P256,
        private_key: None,
        public_key: Some(ka_pub.clone()),
        certificate: None,
        allowed_guests: None,
        allowed_ops: Some(vec![OP_VERIFY]),
    });

    // Slot 1: Software authority — public key only, verifies firmware SUIT envelopes.
    // Private key stays with the backend (never sent to device).
    let (_sw_auth_priv, sw_auth_pub) = extract_ec_raw(&signing_key);
    slots.push(KeySlotDef {
        key_id: "sw-authority".to_string(),
        key_type: KEY_TYPE_EC_P256,
        private_key: None,
        public_key: Some(sw_auth_pub),
        certificate: None,
        allowed_guests: None,
        allowed_ops: Some(vec![OP_VERIFY, OP_GET_PUBKEY]),
    });

    // Slot 2: Device decryption key — public key only.
    // Private key is generated and held on-device; we only need the public
    // half to encrypt firmware envelopes to this device.
    slots.push(KeySlotDef {
        key_id: "device-decrypt".to_string(),
        key_type: KEY_TYPE_EC_P256,
        private_key: None,
        public_key: Some(dk_pub.clone()),
        certificate: None,
        allowed_guests: None,
        allowed_ops: None,
    });

    // Slot 3: General ECU signing key with certificate
    let (priv_key, pub_key) = generate_ec_p256_raw();
    slots.push(KeySlotDef {
        key_id: "ecu-signing".to_string(),
        key_type: KEY_TYPE_EC_P256,
        private_key: Some(priv_key),
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
        private_key: Some(priv_key),
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
        private_key: Some(priv_key),
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
        private_key: Some(aes_data),
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
        private_key: Some(aes_restricted),
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
                private_key: Some(key_data),
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
                private_key: Some(priv_key),
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
    };

    let cbor = encode(&keystore).unwrap();
    eprintln!("[hsm-keys] CBOR payload: {} bytes", cbor.len());

    let digest = crypto.sha256(&cbor);

    // ---------------------------------------------------------------
    // Export Key Authority files (needed for re-provisioning)
    // ---------------------------------------------------------------
    let ka_full_cose = build_device_cose_key(
        &ka_priv,
        &ka_pub[1..33],
        &ka_pub[33..65],
    );
    let ka_pub_cose = build_public_cose_key(
        &ka_pub[1..33],
        &ka_pub[33..65],
    );

    let ka_pub_path = keys_dir.join("key-authority.pub");
    fs::write(&ka_pub_path, &ka_pub_cose).unwrap();
    let ka_key_path = keys_dir.join("key-authority.key");
    fs::write(&ka_key_path, &ka_full_cose).unwrap();
    eprintln!("[hsm-keys] Key Authority public: {}", ka_pub_path.display());
    eprintln!("[hsm-keys] Key Authority private: {}", ka_key_path.display());

    // Export device public key as COSE_Key (needed by sumo-tool --encrypt)
    let device_pub_cose = build_public_cose_key(
        &dk_pub[1..33],
        &dk_pub[33..65],
    );
    let device_pub_path = keys_dir.join("device-decrypt.cosekey");
    fs::write(&device_pub_path, &device_pub_cose).unwrap();
    eprintln!("[hsm-keys] Device public key (COSE): {}", device_pub_path.display());

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
    // 4. Factory envelope (signed: factory key, encrypted: device key)
    // ---------------------------------------------------------------
    println!("\n[hsm-keys] === Factory envelope (signed: factory, encrypted: device key) ===");

    let factory_envelope = build_encrypted_envelope(
        &envelope_signing_key,
        &device_pub_cose,
        &cbor,
        &digest,
        1, // sequence_number
        1, // security_version
        "1.0.0",
        "Factory HSM key provisioning (100 slots)",
    );

    let factory_path = output_dir.join("hsm-keys-v1.suit");
    fs::write(&factory_path, &factory_envelope).unwrap();
    println!("[hsm-keys] {} ({} bytes)",
        factory_path.display(), factory_envelope.len());

    // ---------------------------------------------------------------
    // 5. Re-provision envelope (signed: key authority, encrypted: device key)
    // ---------------------------------------------------------------
    println!("\n[hsm-keys] === Re-provision envelope (signed: key authority, encrypted: device key) ===");

    let mut keystore_v2 = keystore.clone();
    keystore_v2.security_version = 2;
    let cbor_v2 = encode(&keystore_v2).unwrap();
    let digest_v2 = crypto.sha256(&cbor_v2);

    // Build CoseKey for Key Authority signing
    let ka_signing_key = {
        let key = coset::CoseKeyBuilder::new_ec2_priv_key(
            iana::EllipticCurve::P_256,
            ka_pub[1..33].to_vec(),
            ka_pub[33..65].to_vec(),
            ka_priv.clone(),
        )
        .algorithm(iana::Algorithm::ES256)
        .build();
        CoseKey::from_cose_key_bytes(&key.to_vec().unwrap()).unwrap()
    };

    let reprov_envelope = build_encrypted_envelope(
        &ka_signing_key,
        &device_pub_cose,
        &cbor_v2,
        &digest_v2,
        2,
        2,
        "2.0.0",
        "Re-provision HSM keys (100 slots, key authority signed)",
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
    println!("  Factory envelope:      {} ({} bytes, signed: factory, encrypted: device)",
        factory_path.display(), factory_envelope.len());
    println!("  Re-provision envelope: {} ({} bytes, signed: key-authority, encrypted: device)",
        reprov_path.display(), reprov_envelope.len());
    println!("  Key Authority public:  {}", ka_pub_path.display());
    println!("  Key Authority private: {}", ka_key_path.display());
    println!("  Device public key:     {}", device_pub_path.display());
    println!();
    println!("  Key slots:     {}", keystore.slots.len());
    println!("  Identities:    {}", keystore.identities.len());
    println!("  CBOR payload:  {} bytes", cbor.len());
    println!();
    println!("Both envelopes: CBOR → zstd → AES-GCM (to device key) → SUIT.");
    println!("Factory signed with built-in factory key. Re-provision signed with Key Authority.");
}

/// Build a compressed + encrypted SUIT envelope.
fn build_encrypted_envelope(
    signing_key: &CoseKey,
    recipient_pub_cbor: &[u8],
    cbor_payload: &[u8],
    plaintext_digest: &[u8; 32],
    seq: u64,
    security_version: u64,
    version: &str,
    description: &str,
) -> Vec<u8> {
    let recipient_pub = CoseKey::from_cose_key_bytes(recipient_pub_cbor).unwrap();

    // Compress
    let compressed = encryptor::compress_firmware(cbor_payload, 3, None).unwrap();

    // Encrypt (ECDH-ES+A128KW + AES-128-GCM) with fresh ephemeral sender key
    let ephemeral_sender = keygen::generate_device_key(keygen::ES256).unwrap();
    let recipients = [Recipient {
        public_key: recipient_pub,
        kid: b"device-decrypt".to_vec(),
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

/// Extract public key (65 bytes uncompressed) from COSE_Key CBOR bytes.
fn extract_ec_pub_only(cose_bytes: &[u8]) -> Vec<u8> {
    let cose_key: coset::CoseKey = coset::CoseKey::from_slice(cose_bytes).unwrap();

    let mut x = Vec::new();
    let mut y = Vec::new();

    for (label, value) in &cose_key.params {
        if let (coset::Label::Int(n), ciborium::Value::Bytes(bytes)) = (label, value) {
            match *n {
                -2 => x = bytes.clone(),
                -3 => y = bytes.clone(),
                _ => {}
            }
        }
    }

    assert_eq!(x.len(), 32, "EC-P256 x coordinate must be 32 bytes");
    assert_eq!(y.len(), 32, "EC-P256 y coordinate must be 32 bytes");

    let mut pub_key = Vec::with_capacity(65);
    pub_key.push(0x04);
    pub_key.extend_from_slice(&x);
    pub_key.extend_from_slice(&y);
    pub_key
}

/// Extract raw EC-P256 key material from an existing CoseKey (signing key).
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

/// Generate a dummy self-signed certificate (fake DER for testing).
fn dummy_self_signed_cert(crypto: &RustCryptoBackend) -> Vec<u8> {
    let mut cert = vec![0x30, 0x82, 0x01, 0x00];
    let mut body = vec![0u8; 252];
    crypto.random_bytes(&mut body).unwrap();
    cert.extend_from_slice(&body);
    cert
}

/// Extract EC-P256 uncompressed public key (65 bytes) from a PKCS#10 CSR DER.
///
/// Minimal parser: walks the ASN.1 to find SubjectPublicKeyInfo → BIT STRING
/// containing the 65-byte uncompressed point (0x04 || x || y).
fn extract_ec_pubkey_from_csr(der: &[u8]) -> Result<Vec<u8>, String> {
    // CertificationRequest ::= SEQUENCE { certificationRequestInfo, ... }
    // certificationRequestInfo ::= SEQUENCE { version, subject, subjectPKInfo, ... }
    // subjectPKInfo ::= SEQUENCE { algorithm, BIT STRING { 0x00 || pubkey } }
    //
    // We need to find the 65-byte uncompressed point (starts with 0x04).
    // Strategy: scan for the EC P-256 OID followed by a BIT STRING containing 66 bytes.

    // Look for the P-256 OID: 06 08 2A 86 48 CE 3D 03 01 07
    let p256_oid: &[u8] = &[0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07];

    let oid_pos = der
        .windows(p256_oid.len())
        .position(|w| w == p256_oid)
        .ok_or_else(|| "P-256 OID not found in CSR".to_string())?;

    // After the OID, find the next BIT STRING (tag 0x03) containing 66 bytes (0x00 + 65)
    let search_start = oid_pos + p256_oid.len();
    for i in search_start..der.len().saturating_sub(67) {
        if der[i] == 0x03 {
            // Parse length
            let (len, hdr_size) = if der[i + 1] < 0x80 {
                (der[i + 1] as usize, 2usize)
            } else if der[i + 1] == 0x81 && i + 2 < der.len() {
                (der[i + 2] as usize, 3usize)
            } else {
                continue;
            };

            if len == 66 && i + hdr_size + len <= der.len() {
                // First byte is unused-bits count (should be 0x00)
                if der[i + hdr_size] != 0x00 {
                    continue;
                }
                let point = &der[i + hdr_size + 1..i + hdr_size + len];
                if point[0] == 0x04 && point.len() == 65 {
                    return Ok(point.to_vec());
                }
            }
        }
    }

    Err("EC public key point not found in CSR".to_string())
}
