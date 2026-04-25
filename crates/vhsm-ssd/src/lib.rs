//! vHSM SSD — host-side daemon terminating the handle-based vHSM v2 wire
//! protocol spoken by the guest `/dev/vhsm` driver.
//!
//! Guest → host transports: vsock (Linux QEMU) or QNX-native shm/IPC (QNX
//! hypervisor) — abstracted in [`transport`]. Requests are binary frames
//! (see [`proto`] + [`codec`]); every op carries a handle in the
//! 0x0001..=0x00FF well-known range or 0x0100+ dynamic range, and resolves
//! through the [`handle_table`] to a keystore entry validated by [`policy`].
//!
//! Implemented ops: get_random, key_generate, key_delete, encrypt, decrypt,
//! mac_generate/verify, sign, verify, get_handle_info, get_pubkey, get_cert.
//!
//! Crypto is delegated to an `HsmCryptoProvider` (see the `hsm` crate).
//! Today that's `SimHsm` (RustCrypto + on-disk keys); production brings up
//! a board-specific provider talking to HSE/TRNG hardware.

pub mod proto;
pub mod codec;
pub mod handle_table;
pub mod policy;
pub mod handler;
pub mod transport;
