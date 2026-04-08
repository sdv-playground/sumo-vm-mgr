/// Binary frame encoding/decoding for the vHSM wire protocol.

use std::io::{self, Read, Write};

use crate::proto::*;

/// Read a complete request from the stream.
pub fn read_request(r: &mut dyn Read) -> io::Result<Request> {
    let mut hdr = [0u8; REQUEST_HEADER_SIZE];
    read_exact(r, &mut hdr)?;

    // Validate magic
    if hdr[0..4] != VHSM_MAGIC {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "bad magic"));
    }
    // Validate version
    if hdr[4] != VHSM_VERSION {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("unsupported version: {}", hdr[4]),
        ));
    }

    let op = hdr[5];
    let flags = u16::from_le_bytes([hdr[6], hdr[7]]);
    let seq = u32::from_le_bytes([hdr[8], hdr[9], hdr[10], hdr[11]]);
    let key_id_len = u16::from_le_bytes([hdr[12], hdr[13]]) as usize;
    let payload_len = u32::from_le_bytes([hdr[14], hdr[15], hdr[16], hdr[17]]) as usize;

    if key_id_len > MAX_KEY_ID {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "key_id too long",
        ));
    }
    if payload_len > MAX_PAYLOAD {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "payload too large",
        ));
    }

    // Read key_id
    let mut key_id_buf = vec![0u8; key_id_len];
    if key_id_len > 0 {
        read_exact(r, &mut key_id_buf)?;
    }
    let key_id = String::from_utf8(key_id_buf)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "key_id not utf-8"))?;

    // Read payload
    let mut payload = vec![0u8; payload_len];
    if payload_len > 0 {
        read_exact(r, &mut payload)?;
    }

    Ok(Request {
        op,
        flags,
        seq,
        key_id,
        payload,
    })
}

/// Write a complete response to the stream.
pub fn write_response(w: &mut dyn Write, resp: &Response) -> io::Result<()> {
    let mut hdr = [0u8; RESPONSE_HEADER_SIZE];
    hdr[0..4].copy_from_slice(&VHSM_MAGIC);
    hdr[4] = VHSM_VERSION;
    hdr[5] = resp.op;
    // flags = 0
    hdr[6..8].copy_from_slice(&0u16.to_le_bytes());
    hdr[8..12].copy_from_slice(&resp.seq.to_le_bytes());
    hdr[12..16].copy_from_slice(&resp.status.to_le_bytes());
    hdr[16..20].copy_from_slice(&(resp.result.len() as u32).to_le_bytes());

    w.write_all(&hdr)?;
    if !resp.result.is_empty() {
        w.write_all(&resp.result)?;
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
            op: Op::Sign as u8,
            flags: FLAG_SESSION_TOKEN,
            seq: 42,
            key_id: "mykey".into(),
            payload: vec![1, 2, 3, 4],
        };

        // Encode to bytes
        let mut buf = Vec::new();
        buf.extend_from_slice(&VHSM_MAGIC);
        buf.push(VHSM_VERSION);
        buf.push(req.op);
        buf.extend_from_slice(&req.flags.to_le_bytes());
        buf.extend_from_slice(&req.seq.to_le_bytes());
        buf.extend_from_slice(&(req.key_id.len() as u16).to_le_bytes());
        buf.extend_from_slice(&(req.payload.len() as u32).to_le_bytes());
        buf.extend_from_slice(req.key_id.as_bytes());
        buf.extend_from_slice(&req.payload);

        let parsed = read_request(&mut &buf[..]).unwrap();
        assert_eq!(parsed.op, Op::Sign as u8);
        assert_eq!(parsed.flags, FLAG_SESSION_TOKEN);
        assert_eq!(parsed.seq, 42);
        assert_eq!(parsed.key_id, "mykey");
        assert_eq!(parsed.payload, vec![1, 2, 3, 4]);

        // Test response
        let resp = Response::ok(Op::Sign as u8, 42, vec![5, 6, 7]);
        let mut out = Vec::new();
        write_response(&mut out, &resp).unwrap();
        assert_eq!(out.len(), RESPONSE_HEADER_SIZE + 3);
        assert_eq!(&out[0..4], &VHSM_MAGIC);
        assert_eq!(out[5], Op::Sign as u8);
    }
}
