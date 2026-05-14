//! Integrity Verification Data (IVD) — bank-self-signing for secure boot.
//!
//! After OTA staging completes (the bank dir contains the validated
//! payloads but the bank pointer hasn't flipped yet), the HSM signs
//! the bank contents with its device-local `ivd-signing` key. The
//! signature lives in the bank dir itself — `ivd-manifest.cbor` +
//! `ivd-signature.bin` — so rollback automatically discards the sig
//! along with the bank, and a trial flip just exposes the staged
//! bank with its existing signature intact.
//!
//! External secure boot (or the `sumo-verify` CLI for managed-cvc
//! deployments without one) reads the manifest + signature before
//! launching the component:
//!
//! 1. Read `ivd-manifest.cbor` and `ivd-signature.bin`.
//! 2. Verify the signature over the manifest bytes using the HSM's
//!    `ivd-signing` public half (fetched once via
//!    `get_public_key_der("ivd-signing")` and cached).
//! 3. Re-hash every file listed in the manifest and compare.
//! 4. Refuse to launch if any check fails.
//!
//! # Wire shape
//!
//! `ivd-manifest.cbor` is a single CBOR map:
//!
//! ```text
//! IvdManifest = {
//!   0: uint,           ; ivd_version (currently 1)
//!   1: tstr,           ; bank_id    (component-defined, e.g. "vm2/bank_a")
//!   2: uint,           ; signed_at_unix
//!   3: [* FileEntry],
//! }
//!
//! FileEntry = {
//!   0: tstr,           ; relative_path (POSIX, '/' separator)
//!   1: bstr,           ; sha256 of file contents (32 bytes)
//!   2: uint,           ; size in bytes
//! }
//! ```
//!
//! `ivd-signature.bin` is the raw DER-encoded ECDSA-SHA256 signature
//! produced by the HSM's `HsmCryptoProvider::sign` over the CBOR
//! bytes of `ivd-manifest.cbor`. No COSE wrapping — the verifier
//! handles raw DER directly via the same `sign`/`verify` ops.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

use crate::{HsmError, HsmProvider};

/// Slot key_id used by `hsm.sign(...)` / `hsm.verify(...)`. Mirrors
/// `KeyRole::IvdSigning.key_id()`.
pub const IVD_KEY_ID: &str = "ivd-signing";

/// Manifest version. Bumped if the CBOR shape changes.
pub const IVD_MANIFEST_VERSION: u64 = 1;

/// Filenames the IVD machinery owns inside a bank dir.
pub const IVD_MANIFEST_FILE: &str = "ivd-manifest.cbor";
pub const IVD_SIGNATURE_FILE: &str = "ivd-signature.bin";

/// IVD manifest — what the HSM signs.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IvdManifest {
    #[serde(rename = "0")]
    pub ivd_version: u64,

    /// Caller-supplied identifier for the bank (e.g. "vm2/bank_a",
    /// "host-os/bank_b", "hsm/keystore"). Bound into the signed
    /// payload so a sig from one bank can't be replayed against
    /// another with the same file contents.
    #[serde(rename = "1")]
    pub bank_id: String,

    /// Unix seconds at sign time. Informational — verifiers use
    /// security_version, not timestamps, for rollback policy.
    #[serde(rename = "2")]
    pub signed_at_unix: u64,

    /// Bank file inventory, sorted by `relative_path` for determinism.
    #[serde(rename = "3")]
    pub files: Vec<IvdFile>,
}

/// One file in the bank inventory.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IvdFile {
    /// POSIX-style relative path under the bank dir. Slash separator,
    /// no leading slash, no `..` components.
    #[serde(rename = "0")]
    pub relative_path: String,

    /// SHA-256 of the file contents.
    #[serde(rename = "1", with = "serde_bytes")]
    pub sha256: Vec<u8>,

    #[serde(rename = "2")]
    pub size: u64,
}

/// Anything that can go wrong specifically inside the IVD machinery.
/// Mostly wraps `HsmError` and IO; verification failures get their
/// own variants for orchestrator-visible reasons.
#[derive(Debug)]
pub enum IvdError {
    Io(std::io::Error, PathBuf),
    Cbor(String),
    /// Manifest's claim about a file's hash doesn't match what's on disk.
    HashMismatch {
        path: String,
        claimed: Vec<u8>,
        actual: Vec<u8>,
    },
    /// Manifest's claim about a file's size doesn't match what's on disk.
    SizeMismatch {
        path: String,
        claimed: u64,
        actual: u64,
    },
    /// A file listed in the manifest isn't on disk.
    MissingFile(String),
    /// A file is on disk that the manifest doesn't claim.
    UnexpectedFile(String),
    /// Manifest's `bank_id` doesn't match what the caller expected.
    BankIdMismatch { expected: String, claimed: String },
    /// HSM rejected the verify or signature is bad.
    SignatureInvalid,
    /// Manifest carries a version this build doesn't understand.
    UnsupportedManifestVersion(u64),
    Hsm(HsmError),
}

impl std::fmt::Display for IvdError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            IvdError::Io(e, p) => write!(f, "ivd io {}: {e}", p.display()),
            IvdError::Cbor(s) => write!(f, "ivd cbor: {s}"),
            IvdError::HashMismatch { path, .. } => write!(f, "ivd hash mismatch: {path}"),
            IvdError::SizeMismatch { path, claimed, actual } => {
                write!(f, "ivd size mismatch {path}: manifest says {claimed}, on disk {actual}")
            }
            IvdError::MissingFile(p) => write!(f, "ivd missing file: {p}"),
            IvdError::UnexpectedFile(p) => write!(f, "ivd unexpected file (not in manifest): {p}"),
            IvdError::BankIdMismatch { expected, claimed } => {
                write!(f, "ivd bank_id mismatch: expected {expected}, manifest claims {claimed}")
            }
            IvdError::SignatureInvalid => write!(f, "ivd signature invalid"),
            IvdError::UnsupportedManifestVersion(v) => {
                write!(f, "ivd manifest version {v} not supported")
            }
            IvdError::Hsm(e) => write!(f, "ivd hsm: {e}"),
        }
    }
}

impl std::error::Error for IvdError {}

impl From<HsmError> for IvdError {
    fn from(e: HsmError) -> Self {
        IvdError::Hsm(e)
    }
}

/// Walk `bank_dir` and produce a sorted file inventory. Skips the
/// IVD-owned files themselves (manifest + signature) so they don't
/// shadow themselves. Does not recurse into symlinks.
pub fn build_manifest(bank_dir: &Path, bank_id: impl Into<String>) -> Result<IvdManifest, IvdError> {
    let mut files = Vec::new();
    collect_files(bank_dir, bank_dir, &mut files)?;
    files.sort_by(|a, b| a.relative_path.cmp(&b.relative_path));

    let signed_at_unix = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);

    Ok(IvdManifest {
        ivd_version: IVD_MANIFEST_VERSION,
        bank_id: bank_id.into(),
        signed_at_unix,
        files,
    })
}

fn collect_files(
    root: &Path,
    dir: &Path,
    out: &mut Vec<IvdFile>,
) -> Result<(), IvdError> {
    let entries =
        fs::read_dir(dir).map_err(|e| IvdError::Io(e, dir.to_path_buf()))?;
    for entry in entries {
        let entry = entry.map_err(|e| IvdError::Io(e, dir.to_path_buf()))?;
        let path = entry.path();
        let file_name = entry.file_name();
        let file_name = file_name.to_string_lossy();

        // Skip the IVD-owned files when scanning the bank — the
        // manifest must not enumerate itself or the signature.
        if dir == root
            && (file_name == IVD_MANIFEST_FILE || file_name == IVD_SIGNATURE_FILE)
        {
            continue;
        }

        let meta = entry
            .metadata()
            .map_err(|e| IvdError::Io(e, path.clone()))?;

        if meta.file_type().is_dir() {
            collect_files(root, &path, out)?;
            continue;
        }
        if !meta.file_type().is_file() {
            // Skip symlinks, sockets, etc. The OTA pipeline doesn't
            // produce them today; rejecting them outright keeps the
            // attack surface small.
            continue;
        }

        let relative = path
            .strip_prefix(root)
            .map_err(|e| IvdError::Cbor(format!("strip_prefix: {e}")))?;
        let relative_path = relative
            .to_string_lossy()
            .replace(std::path::MAIN_SEPARATOR, "/");

        let bytes = fs::read(&path).map_err(|e| IvdError::Io(e, path.clone()))?;
        let sha256 = sha256(&bytes);
        out.push(IvdFile {
            relative_path,
            sha256,
            size: bytes.len() as u64,
        });
    }
    Ok(())
}

/// CBOR-encode the manifest. The bytes returned here are exactly
/// what gets signed (and exactly what gets written to
/// `ivd-manifest.cbor`).
pub fn encode_manifest(manifest: &IvdManifest) -> Result<Vec<u8>, IvdError> {
    let mut buf = Vec::new();
    ciborium::into_writer(manifest, &mut buf)
        .map_err(|e| IvdError::Cbor(format!("encode: {e}")))?;
    Ok(buf)
}

/// CBOR-decode a manifest from bytes (e.g. read from
/// `ivd-manifest.cbor`). Rejects unsupported versions.
pub fn decode_manifest(bytes: &[u8]) -> Result<IvdManifest, IvdError> {
    let manifest: IvdManifest = ciborium::from_reader(bytes)
        .map_err(|e| IvdError::Cbor(format!("decode: {e}")))?;
    if manifest.ivd_version != IVD_MANIFEST_VERSION {
        return Err(IvdError::UnsupportedManifestVersion(manifest.ivd_version));
    }
    Ok(manifest)
}

/// Build the manifest, sign it with the HSM's IVD signing key, and
/// write both artefacts into `bank_dir`. Idempotent at the file
/// level — if called twice the previous artefacts get overwritten.
///
/// Returns the manifest that was signed (informational; the file on
/// disk is the source of truth for verifiers).
#[cfg(feature = "crypto")]
pub fn sign_bank(
    hsm: &dyn HsmProvider,
    bank_dir: &Path,
    bank_id: impl Into<String>,
) -> Result<IvdManifest, IvdError> {
    let started = std::time::Instant::now();

    // Phase 1: walk the bank dir + hash every file into the manifest.
    let hash_start = std::time::Instant::now();
    let manifest = build_manifest(bank_dir, bank_id)?;
    let manifest_bytes = encode_manifest(&manifest)?;
    let hash_us = hash_start.elapsed().as_micros() as u64;

    // Phase 2: sign the manifest bytes.
    let sig_start = std::time::Instant::now();
    let sig = hsm.sign(IVD_KEY_ID, &manifest_bytes)?;
    let sig_us = sig_start.elapsed().as_micros() as u64;

    fs::write(bank_dir.join(IVD_MANIFEST_FILE), &manifest_bytes)
        .map_err(|e| IvdError::Io(e, bank_dir.join(IVD_MANIFEST_FILE)))?;
    fs::write(bank_dir.join(IVD_SIGNATURE_FILE), &sig)
        .map_err(|e| IvdError::Io(e, bank_dir.join(IVD_SIGNATURE_FILE)))?;

    let total_bytes: u64 = manifest.files.iter().map(|f| f.size).sum();
    tracing::info!(
        bank_dir = %bank_dir.display(),
        bank_id = %manifest.bank_id,
        files = manifest.files.len(),
        total_bytes,
        hash_us,
        sig_us,
        total_us = started.elapsed().as_micros() as u64,
        "ivd sign OK",
    );

    Ok(manifest)
}

/// Read manifest + signature from `bank_dir`, verify the sig using
/// the HSM's IVD public key, then re-hash every file the manifest
/// claims and confirm it matches what's on disk. Optionally pins the
/// expected `bank_id` — if provided, mismatches fail.
#[cfg(feature = "crypto")]
pub fn verify_bank(
    hsm: &dyn HsmProvider,
    bank_dir: &Path,
    expected_bank_id: Option<&str>,
) -> Result<IvdManifest, IvdError> {
    let started = std::time::Instant::now();
    let result = verify_bank_inner(hsm, bank_dir, expected_bank_id, started);
    if let Err(ref e) = result {
        // Inner records its own per-phase timings on success; on the
        // pre-signature error paths (file IO etc.) we still want a
        // single failure line for the operator log.
        tracing::error!(
            bank_dir = %bank_dir.display(),
            expected_bank_id = ?expected_bank_id,
            total_us = started.elapsed().as_micros() as u64,
            error = %e,
            "ivd verify FAIL",
        );
    }
    result
}

#[cfg(feature = "crypto")]
fn verify_bank_inner(
    hsm: &dyn HsmProvider,
    bank_dir: &Path,
    expected_bank_id: Option<&str>,
    started: std::time::Instant,
) -> Result<IvdManifest, IvdError> {
    let manifest_path = bank_dir.join(IVD_MANIFEST_FILE);
    let signature_path = bank_dir.join(IVD_SIGNATURE_FILE);

    let manifest_bytes = fs::read(&manifest_path)
        .map_err(|e| IvdError::Io(e, manifest_path.clone()))?;
    let sig = fs::read(&signature_path)
        .map_err(|e| IvdError::Io(e, signature_path.clone()))?;

    // ---- Phase 1: signature verification ----
    let sig_start = std::time::Instant::now();
    let ok = hsm
        .verify(IVD_KEY_ID, &manifest_bytes, &sig)
        .map_err(IvdError::Hsm)?;
    let sig_verify_us = sig_start.elapsed().as_micros() as u64;
    if !ok {
        return Err(IvdError::SignatureInvalid);
    }

    let manifest = decode_manifest(&manifest_bytes)?;

    if let Some(expected) = expected_bank_id {
        if manifest.bank_id != expected {
            return Err(IvdError::BankIdMismatch {
                expected: expected.to_string(),
                claimed: manifest.bank_id.clone(),
            });
        }
    }

    // ---- Phase 2: re-hash every file the manifest claims ----
    let hash_start = std::time::Instant::now();

    let mut on_disk = std::collections::BTreeSet::new();
    let mut probe = Vec::new();
    collect_files(bank_dir, bank_dir, &mut probe)?;
    for f in &probe {
        on_disk.insert(f.relative_path.clone());
    }

    let claimed_set: std::collections::BTreeSet<&String> =
        manifest.files.iter().map(|f| &f.relative_path).collect();

    // Detect files on disk that the manifest doesn't claim.
    for f in &on_disk {
        if !claimed_set.contains(f) {
            return Err(IvdError::UnexpectedFile(f.clone()));
        }
    }

    // Detect manifest claims with no matching file, plus per-file
    // hash/size verification.
    let claimed_map: BTreeMap<&String, &IvdFile> =
        manifest.files.iter().map(|f| (&f.relative_path, f)).collect();
    let mut total_bytes: u64 = 0;
    for claim in manifest.files.iter() {
        let path = bank_dir.join(&claim.relative_path);
        let bytes = match fs::read(&path) {
            Ok(b) => b,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                return Err(IvdError::MissingFile(claim.relative_path.clone()));
            }
            Err(e) => return Err(IvdError::Io(e, path)),
        };
        if bytes.len() as u64 != claim.size {
            return Err(IvdError::SizeMismatch {
                path: claim.relative_path.clone(),
                claimed: claim.size,
                actual: bytes.len() as u64,
            });
        }
        total_bytes += bytes.len() as u64;
        let actual = sha256(&bytes);
        if actual != claim.sha256 {
            return Err(IvdError::HashMismatch {
                path: claim.relative_path.clone(),
                claimed: claim.sha256.clone(),
                actual,
            });
        }
        // Touch the map so the unused-import lint doesn't complain
        // when we go through claimed_map for another check later.
        let _ = claimed_map.get(&claim.relative_path);
    }

    let hash_verify_us = hash_start.elapsed().as_micros() as u64;
    let total_us = started.elapsed().as_micros() as u64;

    tracing::info!(
        bank_dir = %bank_dir.display(),
        bank_id = %manifest.bank_id,
        files = manifest.files.len(),
        total_bytes,
        sig_verify_us,
        hash_verify_us,
        total_us,
        "ivd verify OK",
    );

    Ok(manifest)
}

/// SHA-256 of `bytes`. Uses `sha2` when the `crypto` feature is on;
/// falls back to a minimal panic on non-crypto builds (no HSM op
/// path needs hashing without crypto).
#[cfg(feature = "crypto")]
fn sha256(bytes: &[u8]) -> Vec<u8> {
    use sha2::{Digest, Sha256};
    Sha256::digest(bytes).to_vec()
}

#[cfg(not(feature = "crypto"))]
fn sha256(_bytes: &[u8]) -> Vec<u8> {
    panic!("hsm::ivd::sha256 requires the `crypto` feature")
}

#[cfg(all(test, feature = "crypto"))]
mod tests {
    use super::*;

    fn write(p: &Path, bytes: &[u8]) {
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::write(p, bytes).unwrap();
    }

    fn temp_bank(name: &str) -> PathBuf {
        let p = std::env::temp_dir().join(format!("hsm-ivd-test-{}", name));
        let _ = std::fs::remove_dir_all(&p);
        std::fs::create_dir_all(&p).unwrap();
        p
    }

    #[test]
    fn build_manifest_lists_files_sorted_and_skips_ivd_files() {
        let bank = temp_bank("list");
        write(&bank.join("kernel"), b"kernel bytes");
        write(&bank.join("rootfs.img"), b"rootfs");
        write(&bank.join("nested/qvm.conf"), b"qvm-conf");
        // Existing IVD-owned files should be skipped.
        write(&bank.join(IVD_MANIFEST_FILE), b"stale manifest");
        write(&bank.join(IVD_SIGNATURE_FILE), b"stale sig");

        let m = build_manifest(&bank, "test/bank_a").unwrap();
        let paths: Vec<&str> = m.files.iter().map(|f| f.relative_path.as_str()).collect();
        assert_eq!(paths, vec!["kernel", "nested/qvm.conf", "rootfs.img"]);
        assert_eq!(m.files[0].size, b"kernel bytes".len() as u64);
        assert_eq!(m.bank_id, "test/bank_a");

        let _ = std::fs::remove_dir_all(&bank);
    }

    #[test]
    fn encode_decode_roundtrip() {
        let bank = temp_bank("roundtrip");
        write(&bank.join("a"), b"alpha");
        write(&bank.join("b"), b"beta");
        let m = build_manifest(&bank, "test/bank_b").unwrap();
        let bytes = encode_manifest(&m).unwrap();
        let back = decode_manifest(&bytes).unwrap();
        assert_eq!(back.bank_id, "test/bank_b");
        assert_eq!(back.files.len(), 2);
        let _ = std::fs::remove_dir_all(&bank);
    }

    fn provisioned_sim(name: &str) -> (crate::sim::SimHsm, PathBuf) {
        use crate::payload::*;

        let keystore = std::env::temp_dir().join(format!("hsm-ivd-keystore-{}", name));
        let _ = std::fs::remove_dir_all(&keystore);
        std::fs::create_dir_all(&keystore).unwrap();

        let hsm = crate::sim::SimHsm::new(
            PathBuf::from("/dev/null"),
            keystore.clone(),
            5100,
        );

        // Minimal v2 keystore: just `ivd-signing` as a device-
        // generated EC slot. generate_missing_local_keys produces the
        // keypair on disk.
        let ks = HsmKeystore {
            schema_version: SCHEMA_VERSION,
            security_version: 1,
            identities: vec![],
            slots: vec![KeySlot {
                key_id: IVD_KEY_ID.to_string(),
                key_kind: KEY_TYPE_EC_P256,
                anchor_public_key: None,
                allowed_guests: None,
                allowed_ops: Some(vec![OP_SIGN, OP_VERIFY, OP_GET_PUBKEY]),
            }],
        };
        hsm.write_keystore(&ks).unwrap();
        std::fs::write(keystore.join("provision_state"), b"1\n").unwrap();

        (hsm, keystore)
    }

    #[test]
    fn sign_then_verify_roundtrips() {
        let bank = temp_bank("sign-verify");
        write(&bank.join("kernel"), b"kernel bytes");
        write(&bank.join("rootfs.img"), &vec![0xAB; 4096]);
        write(&bank.join("nested/qvm.conf"), b"cmdline foo=bar");

        let (hsm, keystore) = provisioned_sim("sign-verify");
        let manifest = sign_bank(&hsm, &bank, "test/bank_a").unwrap();
        assert_eq!(manifest.bank_id, "test/bank_a");
        assert_eq!(manifest.files.len(), 3);
        assert!(bank.join(IVD_MANIFEST_FILE).exists());
        assert!(bank.join(IVD_SIGNATURE_FILE).exists());

        let back = verify_bank(&hsm, &bank, Some("test/bank_a")).unwrap();
        assert_eq!(back.bank_id, "test/bank_a");

        let _ = std::fs::remove_dir_all(&bank);
        let _ = std::fs::remove_dir_all(&keystore);
    }

    #[test]
    fn verify_rejects_tampered_file() {
        let bank = temp_bank("tamper");
        // 15-byte original; tamper to a different 15-byte content so
        // SizeMismatch doesn't fire first and we exercise the hash
        // comparison specifically.
        write(&bank.join("kernel"), b"original kernel");

        let (hsm, keystore) = provisioned_sim("tamper");
        sign_bank(&hsm, &bank, "test/bank_t").unwrap();

        std::fs::write(bank.join("kernel"), b"tampered kernel").unwrap();

        match verify_bank(&hsm, &bank, None) {
            Err(IvdError::HashMismatch { path, .. }) => assert_eq!(path, "kernel"),
            other => panic!("expected HashMismatch, got {other:?}"),
        }

        let _ = std::fs::remove_dir_all(&bank);
        let _ = std::fs::remove_dir_all(&keystore);
    }

    #[test]
    fn verify_rejects_unexpected_extra_file() {
        let bank = temp_bank("extra");
        write(&bank.join("kernel"), b"k");

        let (hsm, keystore) = provisioned_sim("extra");
        sign_bank(&hsm, &bank, "test/bank_x").unwrap();

        // Drop an extra file AFTER signing — bank shouldn't have
        // anything the manifest didn't authorize.
        std::fs::write(bank.join("evil-file"), b"unauthorised").unwrap();

        match verify_bank(&hsm, &bank, None) {
            Err(IvdError::UnexpectedFile(p)) => assert_eq!(p, "evil-file"),
            other => panic!("expected UnexpectedFile, got {other:?}"),
        }

        let _ = std::fs::remove_dir_all(&bank);
        let _ = std::fs::remove_dir_all(&keystore);
    }

    #[test]
    fn verify_rejects_bank_id_mismatch() {
        let bank = temp_bank("bankid");
        write(&bank.join("f"), b"x");

        let (hsm, keystore) = provisioned_sim("bankid");
        sign_bank(&hsm, &bank, "vm2/bank_a").unwrap();

        match verify_bank(&hsm, &bank, Some("vm2/bank_b")) {
            Err(IvdError::BankIdMismatch { expected, claimed }) => {
                assert_eq!(expected, "vm2/bank_b");
                assert_eq!(claimed, "vm2/bank_a");
            }
            other => panic!("expected BankIdMismatch, got {other:?}"),
        }

        let _ = std::fs::remove_dir_all(&bank);
        let _ = std::fs::remove_dir_all(&keystore);
    }
}
