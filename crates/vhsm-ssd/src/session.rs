/// REGISTER challenge-response session management.
///
/// Flow:
/// 1. Guest sends REGISTER (flags=0): guest_id\0 + sw_version(4) + nonce(32)
/// 2. Server responds: challenge(32) + ssd_nonce(32)
/// 3. Guest sends REGISTER (flags=REGISTER_RESPONSE): ECDSA signature
///    over (challenge || guest_id || ssd_nonce)
/// 4. Server verifies, returns 32-byte session token
///
/// All subsequent ops must include session token (FLAG_SESSION_TOKEN).

use std::collections::HashMap;

use crate::proto::*;
use rand::RngCore;

/// Per-connection session state.
pub struct SessionManager {
    /// Active session: (token, guest_id)
    session: Option<([u8; SESSION_TOKEN_LEN], String)>,
    /// Pending REGISTER challenge
    pending: Option<PendingChallenge>,
    /// Per-boot identity public keys: guest_id -> 65-byte uncompressed EC point
    identity_keys: HashMap<String, Vec<u8>>,
    /// Server start time for uptime reporting
    start_time: std::time::Instant,
}

struct PendingChallenge {
    guest_id: String,
    challenge: [u8; 32],
    ssd_nonce: [u8; 32],
}

impl SessionManager {
    pub fn new(start_time: std::time::Instant) -> Self {
        Self {
            session: None,
            pending: None,
            identity_keys: HashMap::new(),
            start_time,
        }
    }

    /// Server uptime in seconds.
    pub fn uptime_secs(&self) -> u32 {
        self.start_time.elapsed().as_secs() as u32
    }

    /// Generate a per-boot identity key pair for a guest.
    /// Returns the 32-byte private scalar (to send to guest).
    /// Stores the 65-byte uncompressed public key for REGISTER verification.
    pub fn provision_identity(&mut self, guest_id: &str) -> Vec<u8> {
        use p256::ecdsa::SigningKey;

        let sk = SigningKey::random(&mut rand::rngs::OsRng);
        let pk = sk.verifying_key().to_encoded_point(false);
        self.identity_keys
            .insert(guest_id.to_string(), pk.as_bytes().to_vec());
        sk.to_bytes().to_vec()
    }

    /// Look up provisioned identity public key for REGISTER verification.
    pub fn get_provisioned_pubkey(&self, guest_id: &str) -> Option<&[u8]> {
        self.identity_keys.get(guest_id).map(|v| v.as_slice())
    }

    /// Handle REGISTER phase 1: parse guest_id, generate challenge.
    /// Returns (challenge(32) + ssd_nonce(32)) as response payload.
    pub fn register_phase1(&mut self, payload: &[u8]) -> Result<(String, Vec<u8>), StatusCode> {
        // Payload: guest_id\0 + sw_version(4) + nonce(32)
        // Minimum: 1 byte id + 1 null + 4 sw_version + 32 nonce = 38
        if payload.len() < 38 {
            return Err(StatusCode::InvalidRequest);
        }

        // Find null terminator for guest_id
        let null_pos = payload
            .iter()
            .position(|&b| b == 0)
            .ok_or(StatusCode::InvalidRequest)?;
        if null_pos == 0 || null_pos > 127 {
            return Err(StatusCode::InvalidRequest);
        }

        let guest_id = String::from_utf8(payload[..null_pos].to_vec())
            .map_err(|_| StatusCode::InvalidRequest)?;

        // Generate challenge and nonce
        let mut challenge = [0u8; 32];
        let mut ssd_nonce = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut challenge);
        rand::rngs::OsRng.fill_bytes(&mut ssd_nonce);

        self.pending = Some(PendingChallenge {
            guest_id: guest_id.clone(),
            challenge,
            ssd_nonce,
        });

        let mut result = Vec::with_capacity(64);
        result.extend_from_slice(&challenge);
        result.extend_from_slice(&ssd_nonce);
        Ok((guest_id, result))
    }

    /// Handle REGISTER phase 2: verify signature, issue session token.
    /// `identity_pubkey` is the uncompressed EC point (65 bytes) for the guest.
    /// Returns 32-byte session token on success.
    pub fn register_phase2(
        &mut self,
        signature: &[u8],
        identity_pubkey: &[u8],
    ) -> Result<Vec<u8>, StatusCode> {
        let pending = self.pending.take().ok_or(StatusCode::InvalidRequest)?;

        // Build signed message: challenge || guest_id || ssd_nonce
        let mut message = Vec::with_capacity(32 + pending.guest_id.len() + 32);
        message.extend_from_slice(&pending.challenge);
        message.extend_from_slice(pending.guest_id.as_bytes());
        message.extend_from_slice(&pending.ssd_nonce);

        // Verify ECDSA-SHA256 signature using p256 crate
        use ecdsa::signature::Verifier;
        use p256::ecdsa::VerifyingKey;

        let vk = VerifyingKey::from_sec1_bytes(identity_pubkey)
            .map_err(|_| StatusCode::AccessDenied)?;
        let sig = ecdsa::der::Signature::<p256::NistP256>::from_bytes(signature)
            .map_err(|_| StatusCode::AccessDenied)?;

        vk.verify(&message, &sig)
            .map_err(|_| StatusCode::AccessDenied)?;

        // Issue session token
        let mut token = [0u8; SESSION_TOKEN_LEN];
        rand::rngs::OsRng.fill_bytes(&mut token);

        self.session = Some((token, pending.guest_id));

        Ok(token.to_vec())
    }

    /// Validate session token from request payload.
    /// Returns (guest_id, remaining_payload) on success.
    pub fn validate_token<'a>(&self, payload: &'a [u8]) -> Result<(&str, &'a [u8]), StatusCode> {
        if payload.len() < SESSION_TOKEN_LEN {
            return Err(StatusCode::NotRegistered);
        }

        let (Some((stored_token, guest_id)), token_bytes) = (
            self.session.as_ref(),
            &payload[..SESSION_TOKEN_LEN],
        ) else {
            return Err(StatusCode::NotRegistered);
        };

        // Constant-time comparison
        if !constant_time_eq(stored_token, token_bytes) {
            return Err(StatusCode::NotRegistered);
        }

        Ok((guest_id.as_str(), &payload[SESSION_TOKEN_LEN..]))
    }

    /// Get the pending guest_id (for looking up identity pubkey).
    pub fn pending_guest_id(&self) -> Option<&str> {
        self.pending.as_ref().map(|p| p.guest_id.as_str())
    }
}

/// Constant-time byte comparison to prevent timing attacks.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}
