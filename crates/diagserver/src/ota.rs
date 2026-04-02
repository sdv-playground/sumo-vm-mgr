/// OTA update flow — download, verify, commit, rollback.
///
/// The diagserver manages the update lifecycle:
/// 1. install()  — validate, copy-on-update, write image, verify hash, update NV
/// 2. commit()   — mark trial as committed, raise anti-rollback floor
/// 3. rollback() — swap back to previous bank

use nv_store::block::BlockDevice;
use nv_store::store::NvStore;
use nv_store::types::*;
use sha2::{Sha256, Digest};

#[derive(Debug, PartialEq, Eq)]
pub enum OtaError {
    /// Bank set is in trial mode — must commit or rollback first
    InTrial,
    /// Image security version below anti-rollback floor
    SecurityVersionTooLow { image: u32, floor: u32 },
    /// Image hash mismatch after write (read-back verification failed)
    VerifyFailed { expected: [u8; 32], actual: [u8; 32] },
    /// Bank set is already committed — nothing to commit
    AlreadyCommitted,
    /// Bank set is already committed — nothing to rollback
    NotInTrial,
    /// NV boot state not initialized
    NoBootState,
    /// NV store I/O error
    NvError(String),
}

impl From<nv_store::block::BlockError> for OtaError {
    fn from(e: nv_store::block::BlockError) -> Self {
        OtaError::NvError(e.to_string())
    }
}

impl std::fmt::Display for OtaError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            OtaError::InTrial => write!(f, "bank set is in trial mode"),
            OtaError::SecurityVersionTooLow { image, floor } => {
                write!(f, "image security version {image} below floor {floor}")
            }
            OtaError::VerifyFailed { .. } => write!(f, "image hash verification failed"),
            OtaError::AlreadyCommitted => write!(f, "bank set is already committed"),
            OtaError::NotInTrial => write!(f, "bank set is not in trial mode"),
            OtaError::NoBootState => write!(f, "NV boot state not initialized"),
            OtaError::NvError(e) => write!(f, "NV error: {e}"),
        }
    }
}

/// Metadata for an incoming OTA image (parsed from image header).
#[derive(Debug, Clone)]
pub struct ImageMeta {
    pub fw_version: [u8; 32],
    pub fw_seq: u32,
    pub fw_secver: u32,
    pub spare_part_number: [u8; 32],
    pub ecu_sw_number: [u8; 32],
    pub supplier_sw_number: [u8; 32],
    pub supplier_sw_version: [u8; 32],
    pub odx_file_id: [u8; 32],
    pub system_name: [u8; 32],
    pub programming_date: [u8; 8],
    pub tester_serial: [u8; 32],
}

impl Default for ImageMeta {
    fn default() -> Self {
        Self {
            fw_version: [0; 32],
            fw_seq: 0,
            fw_secver: 0,
            spare_part_number: [0; 32],
            ecu_sw_number: [0; 32],
            supplier_sw_number: [0; 32],
            supplier_sw_version: [0; 32],
            odx_file_id: [0; 32],
            system_name: [0; 32],
            programming_date: [0; 8],
            tester_serial: [0; 32],
        }
    }
}

/// Result of a successful install.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InstallResult {
    pub target_bank: Bank,
    pub image_sha256: [u8; 32],
}

/// Install an OTA image for a bank set.
///
/// This performs the full OTA flow:
/// 1. Validate preconditions (committed, anti-rollback)
/// 2. Copy-on-update runtime DIDs from active → target
/// 3. Compute image SHA-256
/// 4. Write FW Meta for target bank
/// 5. Switch active bank to target, enter trial mode
///
/// When `single_bank` is true (e.g. HSM), the image is written to bank A
/// in-place with immediate commit — no bank swap, no trial mode.
///
/// Note: The actual image write to the OS partition is the caller's
/// responsibility (platform-specific). This function handles NV metadata only.
pub fn install<D: BlockDevice>(
    nv: &mut NvStore<D>,
    set: BankSet,
    image_data: &[u8],
    meta: &ImageMeta,
    single_bank: bool,
) -> Result<InstallResult, OtaError> {
    let state = nv.read_boot_state().ok_or(OtaError::NoBootState)?;
    let idx = set as usize;

    // Precondition: must be committed
    if !state.banks[idx].committed {
        return Err(OtaError::InTrial);
    }

    let active = state.banks[idx].active_bank;

    // Anti-rollback check
    if let Some(current_meta) = nv.read_fw_meta(set, active) {
        if meta.fw_secver < current_meta.min_security_ver {
            return Err(OtaError::SecurityVersionTooLow {
                image: meta.fw_secver,
                floor: current_meta.min_security_ver,
            });
        }
    }

    // Compute image hash and CRC
    let image_sha256: [u8; 32] = Sha256::digest(image_data).into();
    let fw_crc = crc32fast::hash(image_data);

    install_inner(nv, set, state, idx, active, image_sha256, fw_crc, meta, single_bank)
}

/// Install with pre-computed hash (streaming path — image already on disk).
pub fn install_precomputed<D: BlockDevice>(
    nv: &mut NvStore<D>,
    set: BankSet,
    image_sha256: [u8; 32],
    image_size: u64,
    meta: &ImageMeta,
    single_bank: bool,
) -> Result<InstallResult, OtaError> {
    let state = nv.read_boot_state().ok_or(OtaError::NoBootState)?;
    let idx = set as usize;

    if !state.banks[idx].committed {
        return Err(OtaError::InTrial);
    }

    let active = state.banks[idx].active_bank;

    if let Some(current_meta) = nv.read_fw_meta(set, active) {
        if meta.fw_secver < current_meta.min_security_ver {
            return Err(OtaError::SecurityVersionTooLow {
                image: meta.fw_secver,
                floor: current_meta.min_security_ver,
            });
        }
    }

    let fw_crc = crc32fast::hash(&image_size.to_le_bytes()); // Placeholder CRC for streamed data

    install_inner(nv, set, state, idx, active, image_sha256, fw_crc, meta, single_bank)
}

fn install_inner<D: BlockDevice>(
    nv: &mut NvStore<D>,
    set: BankSet,
    mut state: NvBootState,
    idx: usize,
    active: Bank,
    image_sha256: [u8; 32],
    fw_crc: u32,
    meta: &ImageMeta,
    single_bank: bool,
) -> Result<InstallResult, OtaError> {
    if single_bank {
        // Single-bank install (HSM): overwrite bank A in-place, immediate commit
        let min_security_ver = meta.fw_secver; // raise floor immediately

        let mut fw_meta = NvFwMeta {
            write_seq: 0,
            fw_version: meta.fw_version,
            fw_seq: meta.fw_seq,
            fw_secver: meta.fw_secver,
            fw_crc,
            image_sha256,
            spare_part_number: meta.spare_part_number,
            ecu_sw_number: meta.ecu_sw_number,
            supplier_sw_number: meta.supplier_sw_number,
            supplier_sw_version: meta.supplier_sw_version,
            odx_file_id: meta.odx_file_id,
            system_name: meta.system_name,
            programming_date: meta.programming_date,
            tester_serial: meta.tester_serial,
            min_security_ver,
        };
        nv.write_fw_meta(set, Bank::A, &mut fw_meta)?;

        // Keep committed=true, bank A, no trial
        state.banks[idx].active_bank = Bank::A;
        state.banks[idx].committed = true;
        state.banks[idx].boot_count = 0;
        nv.write_boot_state(&mut state)?;

        Ok(InstallResult {
            target_bank: Bank::A,
            image_sha256,
        })
    } else {
        // A/B banked install: write to inactive bank, enter trial mode
        let target = active.other();

        // Copy-on-update: clone runtime DIDs from active → target
        nv.copy_runtime(set, active, target)?;

        // Preserve min_security_ver from active bank
        let min_security_ver = nv
            .read_fw_meta(set, active)
            .map(|m| m.min_security_ver)
            .unwrap_or(0);

        let mut fw_meta = NvFwMeta {
            write_seq: 0,
            fw_version: meta.fw_version,
            fw_seq: meta.fw_seq,
            fw_secver: meta.fw_secver,
            fw_crc,
            image_sha256,
            spare_part_number: meta.spare_part_number,
            ecu_sw_number: meta.ecu_sw_number,
            supplier_sw_number: meta.supplier_sw_number,
            supplier_sw_version: meta.supplier_sw_version,
            odx_file_id: meta.odx_file_id,
            system_name: meta.system_name,
            programming_date: meta.programming_date,
            tester_serial: meta.tester_serial,
            min_security_ver,
        };
        nv.write_fw_meta(set, target, &mut fw_meta)?;

        // Switch to target bank, enter trial mode
        state.banks[idx].active_bank = target;
        state.banks[idx].committed = false;
        state.banks[idx].boot_count = 0;
        nv.write_boot_state(&mut state)?;

        Ok(InstallResult {
            target_bank: target,
            image_sha256,
        })
    }
}

/// Commit the current trial bank set.
///
/// Sets committed=true, resets boot count, and raises the anti-rollback
/// floor if the new firmware's security version exceeds it.
pub fn commit<D: BlockDevice>(
    nv: &mut NvStore<D>,
    set: BankSet,
) -> Result<(), OtaError> {
    let mut state = nv.read_boot_state().ok_or(OtaError::NoBootState)?;
    let idx = set as usize;

    if state.banks[idx].committed {
        return Err(OtaError::AlreadyCommitted);
    }

    let active = state.banks[idx].active_bank;

    // Raise anti-rollback floor
    if let Some(mut meta) = nv.read_fw_meta(set, active) {
        if meta.fw_secver > meta.min_security_ver {
            meta.min_security_ver = meta.fw_secver;
            nv.write_fw_meta(set, active, &mut meta)?;
        }
    }

    state.banks[idx].committed = true;
    state.banks[idx].boot_count = 0;
    nv.write_boot_state(&mut state)?;

    Ok(())
}

/// Rollback the current trial to the previous bank.
///
/// Swaps active_bank back, sets committed=true.
pub fn rollback<D: BlockDevice>(
    nv: &mut NvStore<D>,
    set: BankSet,
) -> Result<Bank, OtaError> {
    let mut state = nv.read_boot_state().ok_or(OtaError::NoBootState)?;
    let idx = set as usize;

    if state.banks[idx].committed {
        return Err(OtaError::NotInTrial);
    }

    let previous = state.banks[idx].active_bank.other();
    state.banks[idx].active_bank = previous;
    state.banks[idx].committed = true;
    state.banks[idx].boot_count = 0;
    nv.write_boot_state(&mut state)?;

    Ok(previous)
}

/// Query the status of a bank set.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BankStatus {
    pub active_bank: Bank,
    pub committed: bool,
    pub boot_count: u8,
    pub fw_version: Option<[u8; 32]>,
    pub fw_secver: Option<u32>,
    pub min_security_ver: Option<u32>,
}

pub fn status<D: BlockDevice>(
    nv: &NvStore<D>,
    set: BankSet,
) -> Option<BankStatus> {
    let state = nv.read_boot_state()?;
    let bs = &state.banks[set as usize];
    let meta = nv.read_fw_meta(set, bs.active_bank);

    Some(BankStatus {
        active_bank: bs.active_bank,
        committed: bs.committed,
        boot_count: bs.boot_count,
        fw_version: meta.as_ref().map(|m| m.fw_version),
        fw_secver: meta.as_ref().map(|m| m.fw_secver),
        min_security_ver: meta.as_ref().map(|m| m.min_security_ver),
    })
}
