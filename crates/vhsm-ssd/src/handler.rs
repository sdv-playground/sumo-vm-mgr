/// Request dispatch — routes opcodes to HsmCryptoProvider.

use hsm::{HsmCryptoProvider, HsmError};

use crate::acl;
use crate::proto::*;
use crate::session::SessionManager;

/// Handle a single request. Returns the response to send.
pub fn handle_request(
    req: &Request,
    sessions: &mut SessionManager,
    crypto: &dyn HsmCryptoProvider,
    key_count: u32,
) -> Response {
    let Some(op) = Op::from_u8(req.op) else {
        return Response::err(req.op, req.seq, StatusCode::InvalidRequest);
    };

    match op {
        Op::ProvisionIdentity => handle_provision_identity(req, sessions),
        Op::Register => handle_register(req, sessions),
        Op::Status => handle_status(req, sessions, key_count),
        _ => handle_crypto_op(req, op, sessions, crypto),
    }
}

fn handle_provision_identity(req: &Request, sessions: &mut SessionManager) -> Response {
    // Parse guest_id\0 from payload
    let null_pos = match req.payload.iter().position(|&b| b == 0) {
        Some(p) if p > 0 && p <= 127 => p,
        _ => return Response::err(req.op, req.seq, StatusCode::InvalidRequest),
    };

    let guest_id = match String::from_utf8(req.payload[..null_pos].to_vec()) {
        Ok(id) => id,
        Err(_) => return Response::err(req.op, req.seq, StatusCode::InvalidRequest),
    };

    let scalar = sessions.provision_identity(&guest_id);
    tracing::info!(guest = %guest_id, "identity key provisioned (per-boot)");
    Response::ok(req.op, req.seq, scalar)
}

fn handle_register(req: &Request, sessions: &mut SessionManager) -> Response {
    if req.flags & FLAG_REGISTER_RESPONSE != 0 {
        // Phase 2: verify signature
        let guest_id = match sessions.pending_guest_id() {
            Some(id) => id.to_string(),
            None => return Response::err(req.op, req.seq, StatusCode::InvalidRequest),
        };

        let identity_pubkey = match sessions.get_provisioned_pubkey(&guest_id) {
            Some(pk) => pk.to_vec(),
            None => {
                tracing::warn!(guest = %guest_id, "no provisioned identity — call PROVISION_IDENTITY first");
                return Response::err(req.op, req.seq, StatusCode::AccessDenied);
            }
        };

        match sessions.register_phase2(&req.payload, &identity_pubkey) {
            Ok(token) => {
                tracing::info!(guest = %guest_id, "guest registered (challenge-response)");
                Response::ok(req.op, req.seq, token)
            }
            Err(status) => {
                tracing::warn!(guest = %guest_id, "REGISTER phase 2 failed");
                Response::err(req.op, req.seq, status)
            }
        }
    } else {
        // Phase 1: generate challenge
        match sessions.register_phase1(&req.payload) {
            Ok((guest_id, challenge_response)) => {
                if sessions.get_provisioned_pubkey(&guest_id).is_none() {
                    tracing::warn!(guest = %guest_id, "no provisioned identity — call PROVISION_IDENTITY first");
                    return Response::err(req.op, req.seq, StatusCode::AccessDenied);
                }
                Response::ok(req.op, req.seq, challenge_response)
            }
            Err(status) => Response::err(req.op, req.seq, status),
        }
    }
}

fn handle_status(req: &Request, sessions: &SessionManager, key_count: u32) -> Response {
    // Response: uptime_secs(4 LE) + key_count(4 LE)
    let mut result = Vec::with_capacity(8);
    result.extend_from_slice(&sessions.uptime_secs().to_le_bytes());
    result.extend_from_slice(&key_count.to_le_bytes());
    Response::ok(req.op, req.seq, result)
}

fn handle_crypto_op(
    req: &Request,
    op: Op,
    sessions: &SessionManager,
    crypto: &dyn HsmCryptoProvider,
) -> Response {
    // Validate session token
    let has_token = req.flags & FLAG_SESSION_TOKEN != 0;
    let (guest_id, payload) = if has_token {
        match sessions.validate_token(&req.payload) {
            Ok((guest, rest)) => (guest, rest),
            Err(status) => return Response::err(req.op, req.seq, status),
        }
    } else {
        return Response::err(req.op, req.seq, StatusCode::NotRegistered);
    };

    // Operations that need a key_id
    let needs_key = matches!(
        op,
        Op::Sign | Op::Verify | Op::Encrypt | Op::Decrypt | Op::Derive | Op::GetCert | Op::GetPubkey
    );

    if needs_key && req.key_id.is_empty() {
        return Response::err(req.op, req.seq, StatusCode::InvalidRequest);
    }

    // ACL check for key-based operations
    if needs_key {
        match crypto.get_key_info(&req.key_id) {
            Ok(info) => {
                if let Err(status) = acl::check_access(&info, guest_id, op) {
                    return Response::err(req.op, req.seq, status);
                }
            }
            Err(HsmError::KeyNotFound(_)) => {
                return Response::err(req.op, req.seq, StatusCode::KeyNotFound);
            }
            Err(_) => {
                return Response::err(req.op, req.seq, StatusCode::InternalError);
            }
        }
    }

    // Dispatch to crypto provider
    match op {
        Op::Sign => match crypto.sign(&req.key_id, payload) {
            Ok(sig) => Response::ok(req.op, req.seq, sig),
            Err(e) => {
                tracing::warn!(key = %req.key_id, error = %e, "sign failed");
                Response::err(req.op, req.seq, StatusCode::CryptoError)
            }
        },
        Op::Verify => {
            // Payload: sig_len(4 LE) + signature + data
            if payload.len() < 4 {
                return Response::err(req.op, req.seq, StatusCode::InvalidRequest);
            }
            let sig_len = u32::from_le_bytes([payload[0], payload[1], payload[2], payload[3]])
                as usize;
            if payload.len() < 4 + sig_len {
                return Response::err(req.op, req.seq, StatusCode::InvalidRequest);
            }
            let signature = &payload[4..4 + sig_len];
            let data = &payload[4 + sig_len..];

            match crypto.verify(&req.key_id, data, signature) {
                Ok(true) => Response::ok(req.op, req.seq, Vec::new()),
                Ok(false) => Response::err(req.op, req.seq, StatusCode::CryptoError),
                Err(e) => {
                    tracing::warn!(key = %req.key_id, error = %e, "verify failed");
                    Response::err(req.op, req.seq, StatusCode::CryptoError)
                }
            }
        },
        Op::Encrypt => match crypto.encrypt(&req.key_id, payload) {
            Ok(ct) => Response::ok(req.op, req.seq, ct),
            Err(e) => {
                tracing::warn!(key = %req.key_id, error = %e, "encrypt failed");
                Response::err(req.op, req.seq, StatusCode::CryptoError)
            }
        },
        Op::Decrypt => match crypto.decrypt(&req.key_id, payload) {
            Ok(pt) => Response::ok(req.op, req.seq, pt),
            Err(e) => {
                tracing::warn!(key = %req.key_id, error = %e, "decrypt failed");
                Response::err(req.op, req.seq, StatusCode::CryptoError)
            }
        },
        Op::Derive => match crypto.derive(&req.key_id, payload, 32) {
            Ok(derived) => Response::ok(req.op, req.seq, derived),
            Err(e) => {
                tracing::warn!(key = %req.key_id, error = %e, "derive failed");
                Response::err(req.op, req.seq, StatusCode::CryptoError)
            }
        },
        Op::GetCert => match crypto.get_certificate_der(&req.key_id) {
            Ok(cert) => Response::ok(req.op, req.seq, cert),
            Err(HsmError::KeyNotFound(_)) => {
                Response::err(req.op, req.seq, StatusCode::KeyNotFound)
            }
            Err(e) => {
                tracing::warn!(key = %req.key_id, error = %e, "get_cert failed");
                Response::err(req.op, req.seq, StatusCode::InternalError)
            }
        },
        Op::GetPubkey => match crypto.get_public_key_der(&req.key_id) {
            Ok(pk) => Response::ok(req.op, req.seq, pk),
            Err(HsmError::KeyNotFound(_)) => {
                Response::err(req.op, req.seq, StatusCode::KeyNotFound)
            }
            Err(e) => {
                tracing::warn!(key = %req.key_id, error = %e, "get_pubkey failed");
                Response::err(req.op, req.seq, StatusCode::InternalError)
            }
        },
        Op::Random => {
            // Payload: count(4 LE)
            if payload.len() < 4 {
                return Response::err(req.op, req.seq, StatusCode::InvalidRequest);
            }
            let count =
                u32::from_le_bytes([payload[0], payload[1], payload[2], payload[3]]) as usize;
            if count == 0 || count > MAX_RANDOM {
                return Response::err(req.op, req.seq, StatusCode::InvalidRequest);
            }
            match crypto.random(count) {
                Ok(bytes) => Response::ok(req.op, req.seq, bytes),
                Err(e) => {
                    tracing::warn!(error = %e, "random failed");
                    Response::err(req.op, req.seq, StatusCode::InternalError)
                }
            }
        },
        Op::ProvisionIdentity | Op::Register | Op::Status => unreachable!(),
    }
}
