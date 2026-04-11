/// Binary frame encoding/decoding for the vHSM wire protocol (v2).
///
/// Request:  [3] magic + [1] version + [4] op + [4] session_id + [4] payload_len + [N] payload
/// Response: [3] magic + [1] version + [4] op + [4] session_id + [4] payload_len + [4] status + [N] payload

use std::io::{self, Read, Write};

use crate::proto::*;

/// Read a complete request from the stream.
pub fn read_request(r: &mut dyn Read) -> io::Result<Request> {
    let mut hdr = [0u8; REQUEST_HEADER_SIZE];
    read_exact(r, &mut hdr)?;

    // Validate magic
    if hdr[0..3] != VHSM_MAGIC {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "bad magic"));
    }
    // Validate version
    if hdr[3] != VHSM_VERSION {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("unsupported version: {}", hdr[3]),
        ));
    }

    let op = u32::from_le_bytes([hdr[4], hdr[5], hdr[6], hdr[7]]);
    let session_id = u32::from_le_bytes([hdr[8], hdr[9], hdr[10], hdr[11]]);
    let payload_len = u32::from_le_bytes([hdr[12], hdr[13], hdr[14], hdr[15]]) as usize;

    if payload_len > MAX_PAYLOAD {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "payload too large",
        ));
    }

    // Read payload
    let mut payload = vec![0u8; payload_len];
    if payload_len > 0 {
        read_exact(r, &mut payload)?;
    }

    Ok(Request {
        op,
        session_id,
        payload,
    })
}

/// Write a complete response to the stream.
pub fn write_response(w: &mut dyn Write, resp: &Response) -> io::Result<()> {
    let mut hdr = [0u8; RESPONSE_HEADER_SIZE];
    hdr[0..3].copy_from_slice(&VHSM_MAGIC);
    hdr[3] = VHSM_VERSION;
    hdr[4..8].copy_from_slice(&resp.op.to_le_bytes());
    hdr[8..12].copy_from_slice(&resp.session_id.to_le_bytes());
    hdr[12..16].copy_from_slice(&(resp.payload.len() as u32).to_le_bytes());
    hdr[16..20].copy_from_slice(&resp.status.to_le_bytes());

    w.write_all(&hdr)?;
    if !resp.payload.is_empty() {
        w.write_all(&resp.payload)?;
    }
    w.flush()
}

/// Read exactly `buf.len()` bytes, handling partial reads.
fn read_exact(r: &mut dyn Read, buf: &mut [u8]) -> io::Result<()> {
    let mut pos = 0;
    while pos < buf.len() {
        match r.read(&mut buf[pos..]) {
            Ok(0) => {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "connection closed",
                ))
            }
            Ok(n) => pos += n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_request_response() {
        // Build a request
        let req = Request {
            op: Op::Sign as u32,
            session_id: 42,
            payload: vec![1, 2, 3, 4],
        };

        // Encode to bytes
        let mut buf = Vec::new();
        buf.extend_from_slice(&VHSM_MAGIC);
        buf.push(VHSM_VERSION);
        buf.extend_from_slice(&req.op.to_le_bytes());
        buf.extend_from_slice(&req.session_id.to_le_bytes());
        buf.extend_from_slice(&(req.payload.len() as u32).to_le_bytes());
        buf.extend_from_slice(&req.payload);

        let parsed = read_request(&mut &buf[..]).unwrap();
        assert_eq!(parsed.op, Op::Sign as u32);
        assert_eq!(parsed.session_id, 42);
        assert_eq!(parsed.payload, vec![1, 2, 3, 4]);

        // Test response
        let resp = Response::ok(Op::Sign as u32, 42, vec![5, 6, 7]);
        let mut out = Vec::new();
        write_response(&mut out, &resp).unwrap();
        assert_eq!(out.len(), RESPONSE_HEADER_SIZE + 3);
        assert_eq!(&out[0..3], &VHSM_MAGIC);
        assert_eq!(
            u32::from_le_bytes([out[4], out[5], out[6], out[7]]),
            Op::Sign as u32
        );
    }
}
