/// ACL enforcement for vHSM operations.

use hsm::KeyInfo;

use crate::proto::{Op, StatusCode};

/// Check if the given guest is allowed to perform the given operation on the key.
pub fn check_access(key_info: &KeyInfo, guest_id: &str, op: Op) -> Result<(), StatusCode> {
    // Check allowed_guests (if present, guest must be in list)
    if let Some(ref guests) = key_info.allowed_guests {
        if !guests.iter().any(|g| g == guest_id) {
            tracing::debug!(
                key = %key_info.key_id,
                guest = guest_id,
                "ACL denied: guest not in allowed list"
            );
            return Err(StatusCode::AccessDenied);
        }
    }

    // Check allowed_ops (if present, op must be in list)
    if let Some(ref ops) = key_info.allowed_ops {
        if let Some(op_name) = op.acl_name() {
            if !ops.iter().any(|o| o == op_name) {
                tracing::debug!(
                    key = %key_info.key_id,
                    guest = guest_id,
                    op = op_name,
                    "ACL denied: operation not allowed"
                );
                return Err(StatusCode::AccessDenied);
            }
        }
    }

    Ok(())
}
