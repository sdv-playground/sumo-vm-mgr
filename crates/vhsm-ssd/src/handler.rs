/// Request dispatch (v2) — routes opcodes via handle table + policy.

use hsm::{HsmCryptoProvider, HsmError};

use crate::handle_table::HandleTable;
use crate::policy::Policy;
use crate::proto::*;

/// Handle a single request. Returns the response to send.
pub fn handle_request(
    req: &Request,
    caller_cid: u32,
    handle_table: &mut HandleTable,
    policy: &Policy,
    crypto: &dyn HsmCryptoProvider,
) -> Response {
    let Some(op) = Op::from_u32(req.op) else {
        return Response::err(req.op, req.session_id, StatusCode::InvalidParam);
    };

    // Reject host-only ops from vsock guests
    if op.is_host_only() {
        return Response::err(req.op, req.session_id, StatusCode::PolicyReject);
    }

    // Policy check: is this CID allowed to perform this op at all?
    if let Some(required) = op.required_perm() {
        if let Err(status) = policy.check(caller_cid, required) {
            return Response::err(req.op, req.session_id, status);
        }
    }

    match op {
        Op::GetRandom => handle_get_random(req, crypto),
        Op::KeyGenerate => handle_key_generate(req, caller_cid, handle_table, crypto),
        Op::Encrypt => handle_crypto_with_handle(req, op, caller_cid, handle_table, crypto),
        Op::Decrypt => handle_crypto_with_handle(req, op, caller_cid, handle_table, crypto),
        Op::MacGenerate => handle_crypto_with_handle(req, op, caller_cid, handle_table, crypto),
        Op::MacVerify => handle_crypto_with_handle(req, op, caller_cid, handle_table, crypto),
        Op::Sign => handle_crypto_with_handle(req, op, caller_cid, handle_table, crypto),
        Op::Verify => handle_verify(req, caller_cid, handle_table, crypto),
        Op::GetHandleInfo => handle_get_handle_info(req, caller_cid, handle_table),
        Op::GetPubkey => handle_get_pubkey(req, caller_cid, handle_table, crypto),
        Op::GetCert => handle_get_cert(req, caller_cid, handle_table, crypto),
        // Host-only ops already rejected above
        Op::KeyImport | Op::KeyDerive | Op::KeyDelete => unreachable!(),
    }
}

fn handle_get_random(req: &Request, crypto: &dyn HsmCryptoProvider) -> Response {
    if req.payload.len() < 4 {
        return Response::err(req.op, req.session_id, StatusCode::InvalidParam);
    }
    let count =
        u32::from_le_bytes([req.payload[0], req.payload[1], req.payload[2], req.payload[3]])
            as usize;
    if count == 0 || count > MAX_RANDOM {
        return Response::err(req.op, req.session_id, StatusCode::InvalidParam);
    }
    match crypto.random(count) {
        Ok(bytes) => Response::ok(req.op, req.session_id, bytes),
        Err(e) => {
            tracing::warn!(error = %e, "random failed");
            Response::err(req.op, req.session_id, StatusCode::Internal)
        }
    }
}

fn handle_key_generate(
    req: &Request,
    caller_cid: u32,
    handle_table: &mut HandleTable,
    crypto: &dyn HsmCryptoProvider,
) -> Response {
    // Parse: algorithm(4) + permitted_ops(4) + persistent(1) + pad(3) + label(32) = 44 bytes
    if req.payload.len() < 44 {
        return Response::err(req.op, req.session_id, StatusCode::InvalidParam);
    }

    let algorithm = u32::from_le_bytes([
        req.payload[0],
        req.payload[1],
        req.payload[2],
        req.payload[3],
    ]);
    let permitted_ops = u32::from_le_bytes([
        req.payload[4],
        req.payload[5],
        req.payload[6],
        req.payload[7],
    ]);
    let persistent = req.payload[8] != 0;
    let mut label = [0u8; LABEL_LEN];
    label.copy_from_slice(&req.payload[12..12 + LABEL_LEN]);

    // Generate a key_id for internal use
    let key_id = format!("gen-{}-{}", caller_cid, handle_table.len());

    // TODO: call crypto.generate_key() when trait is extended
    // For now, generate EC key pair using existing infrastructure
    let pubkey = match algorithm {
        ALG_ECC_P256 => match crypto.get_public_key_der(&key_id) {
            Ok(pk) => pk,
            Err(_) => Vec::new(), // Key doesn't exist yet — placeholder
        },
        _ => Vec::new(),
    };

    let handle = match handle_table.allocate(
        &key_id,
        algorithm,
        permitted_ops,
        caller_cid,
        persistent,
        &label,
    ) {
        Some(h) => h,
        None => return Response::err(req.op, req.session_id, StatusCode::NoResource),
    };

    // Response: handle(4) + pubkey_len(4) + pubkey
    let mut result = Vec::with_capacity(8 + pubkey.len());
    result.extend_from_slice(&handle.to_le_bytes());
    result.extend_from_slice(&(pubkey.len() as u32).to_le_bytes());
    result.extend_from_slice(&pubkey);
    Response::ok(req.op, req.session_id, result)
}

/// Resolve handle from first 4 bytes of payload, check permissions, dispatch.
fn handle_crypto_with_handle(
    req: &Request,
    op: Op,
    caller_cid: u32,
    handle_table: &HandleTable,
    crypto: &dyn HsmCryptoProvider,
) -> Response {
    if req.payload.len() < 4 {
        return Response::err(req.op, req.session_id, StatusCode::InvalidParam);
    }

    let handle = u32::from_le_bytes([
        req.payload[0],
        req.payload[1],
        req.payload[2],
        req.payload[3],
    ]);

    let entry = match handle_table.resolve(handle, caller_cid) {
        Some(e) => e,
        None => return Response::err(req.op, req.session_id, StatusCode::InvalidHandle),
    };

    // Per-handle permission check
    if let Some(required) = op.required_perm() {
        if entry.permitted_ops & required == 0 {
            return Response::err(req.op, req.session_id, StatusCode::PermissionDeny);
        }
    }

    let key_id = &entry.key_id;
    let data = &req.payload[4..];

    match op {
        Op::Sign => match crypto.sign(key_id, data) {
            Ok(sig) => Response::ok(req.op, req.session_id, sig),
            Err(e) => {
                tracing::warn!(key = %key_id, error = %e, "sign failed");
                Response::err(req.op, req.session_id, StatusCode::CryptoError)
            }
        },
        Op::Encrypt => match crypto.encrypt(key_id, data) {
            Ok(ct) => Response::ok(req.op, req.session_id, ct),
            Err(e) => {
                tracing::warn!(key = %key_id, error = %e, "encrypt failed");
                Response::err(req.op, req.session_id, StatusCode::CryptoError)
            }
        },
        Op::Decrypt => match crypto.decrypt(key_id, data) {
            Ok(pt) => Response::ok(req.op, req.session_id, pt),
            Err(e) => {
                tracing::warn!(key = %key_id, error = %e, "decrypt failed");
                Response::err(req.op, req.session_id, StatusCode::CryptoError)
            }
        },
        Op::MacGenerate => {
            // data = data_len(4) + data
            if data.len() < 4 {
                return Response::err(req.op, req.session_id, StatusCode::InvalidParam);
            }
            let mac_data = &data[4..];
            // TODO: call crypto.mac_generate() when trait is extended
            // For now, use HKDF-derive as placeholder for CMAC
            match crypto.derive(key_id, mac_data, 16) {
                Ok(mac) => Response::ok(req.op, req.session_id, mac),
                Err(e) => {
                    tracing::warn!(key = %key_id, error = %e, "mac_generate failed");
                    Response::err(req.op, req.session_id, StatusCode::CryptoError)
                }
            }
        },
        Op::MacVerify => {
            // TODO: implement MAC verify when trait is extended
            Response::err(req.op, req.session_id, StatusCode::Internal)
        },
        _ => Response::err(req.op, req.session_id, StatusCode::InvalidParam),
    }
}

fn handle_verify(
    req: &Request,
    caller_cid: u32,
    handle_table: &HandleTable,
    crypto: &dyn HsmCryptoProvider,
) -> Response {
    // Payload: handle(4) + sig_len(4) + signature + hash_len(4) + hash
    if req.payload.len() < 12 {
        return Response::err(req.op, req.session_id, StatusCode::InvalidParam);
    }

    let handle = u32::from_le_bytes([
        req.payload[0],
        req.payload[1],
        req.payload[2],
        req.payload[3],
    ]);

    let entry = match handle_table.resolve(handle, caller_cid) {
        Some(e) => e,
        None => return Response::err(req.op, req.session_id, StatusCode::InvalidHandle),
    };

    if entry.permitted_ops & PERM_VERIFY == 0 {
        return Response::err(req.op, req.session_id, StatusCode::PermissionDeny);
    }

    let rest = &req.payload[4..];
    if rest.len() < 4 {
        return Response::err(req.op, req.session_id, StatusCode::InvalidParam);
    }
    let sig_len = u32::from_le_bytes([rest[0], rest[1], rest[2], rest[3]]) as usize;
    if rest.len() < 4 + sig_len + 4 {
        return Response::err(req.op, req.session_id, StatusCode::InvalidParam);
    }
    let signature = &rest[4..4 + sig_len];
    let hash_start = 4 + sig_len;
    let hash_len =
        u32::from_le_bytes([rest[hash_start], rest[hash_start + 1], rest[hash_start + 2], rest[hash_start + 3]])
            as usize;
    if rest.len() < hash_start + 4 + hash_len {
        return Response::err(req.op, req.session_id, StatusCode::InvalidParam);
    }
    let hash = &rest[hash_start + 4..hash_start + 4 + hash_len];

    match crypto.verify(&entry.key_id, hash, signature) {
        Ok(true) => Response::ok(req.op, req.session_id, Vec::new()),
        Ok(false) => Response::err(req.op, req.session_id, StatusCode::CryptoError),
        Err(e) => {
            tracing::warn!(key = %entry.key_id, error = %e, "verify failed");
            Response::err(req.op, req.session_id, StatusCode::CryptoError)
        }
    }
}

fn handle_get_handle_info(
    req: &Request,
    caller_cid: u32,
    handle_table: &HandleTable,
) -> Response {
    if req.payload.len() < 4 {
        return Response::err(req.op, req.session_id, StatusCode::InvalidParam);
    }

    let handle = u32::from_le_bytes([
        req.payload[0],
        req.payload[1],
        req.payload[2],
        req.payload[3],
    ]);

    let entry = match handle_table.resolve(handle, caller_cid) {
        Some(e) => e,
        None => return Response::err(req.op, req.session_id, StatusCode::InvalidHandle),
    };

    // Response: handle(4) + algorithm(4) + permitted_ops(4) + persistent(1) + pad(3) + label(32) = 48
    let mut result = Vec::with_capacity(48);
    result.extend_from_slice(&entry.handle.to_le_bytes());
    result.extend_from_slice(&entry.algorithm.to_le_bytes());
    result.extend_from_slice(&entry.permitted_ops.to_le_bytes());
    result.push(if entry.persistent { 1 } else { 0 });
    result.extend_from_slice(&[0u8; 3]); // pad
    result.extend_from_slice(&entry.label);
    Response::ok(req.op, req.session_id, result)
}

fn handle_get_pubkey(
    req: &Request,
    caller_cid: u32,
    handle_table: &HandleTable,
    crypto: &dyn HsmCryptoProvider,
) -> Response {
    if req.payload.len() < 4 {
        return Response::err(req.op, req.session_id, StatusCode::InvalidParam);
    }

    let handle = u32::from_le_bytes([
        req.payload[0],
        req.payload[1],
        req.payload[2],
        req.payload[3],
    ]);

    let entry = match handle_table.resolve(handle, caller_cid) {
        Some(e) => e,
        None => return Response::err(req.op, req.session_id, StatusCode::InvalidHandle),
    };

    if entry.permitted_ops & PERM_GET_PUBKEY == 0 {
        return Response::err(req.op, req.session_id, StatusCode::PermissionDeny);
    }

    match crypto.get_public_key_der(&entry.key_id) {
        Ok(pk) => {
            let mut result = Vec::with_capacity(4 + pk.len());
            result.extend_from_slice(&(pk.len() as u32).to_le_bytes());
            result.extend_from_slice(&pk);
            Response::ok(req.op, req.session_id, result)
        }
        Err(HsmError::KeyNotFound(_)) => {
            Response::err(req.op, req.session_id, StatusCode::InvalidHandle)
        }
        Err(e) => {
            tracing::warn!(key = %entry.key_id, error = %e, "get_pubkey failed");
            Response::err(req.op, req.session_id, StatusCode::Internal)
        }
    }
}

fn handle_get_cert(
    req: &Request,
    caller_cid: u32,
    handle_table: &HandleTable,
    crypto: &dyn HsmCryptoProvider,
) -> Response {
    if req.payload.len() < 4 {
        return Response::err(req.op, req.session_id, StatusCode::InvalidParam);
    }

    let handle = u32::from_le_bytes([
        req.payload[0],
        req.payload[1],
        req.payload[2],
        req.payload[3],
    ]);

    let entry = match handle_table.resolve(handle, caller_cid) {
        Some(e) => e,
        None => return Response::err(req.op, req.session_id, StatusCode::InvalidHandle),
    };

    if entry.permitted_ops & PERM_GET_CERT == 0 {
        return Response::err(req.op, req.session_id, StatusCode::PermissionDeny);
    }

    match crypto.get_certificate_der(&entry.key_id) {
        Ok(cert) => {
            let mut result = Vec::with_capacity(4 + cert.len());
            result.extend_from_slice(&(cert.len() as u32).to_le_bytes());
            result.extend_from_slice(&cert);
            Response::ok(req.op, req.session_id, result)
        }
        Err(HsmError::KeyNotFound(_)) => {
            Response::err(req.op, req.session_id, StatusCode::InvalidHandle)
        }
        Err(e) => {
            tracing::warn!(key = %entry.key_id, error = %e, "get_cert failed");
            Response::err(req.op, req.session_id, StatusCode::Internal)
        }
    }
}
