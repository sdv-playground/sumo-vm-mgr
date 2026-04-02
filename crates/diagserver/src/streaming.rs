//! Streaming SUIT envelope processor.
//!
//! Parses a SUIT envelope from a byte stream, validates the small header
//! (auth wrapper + manifest), then streams the "#firmware" payload through
//! decrypt → decompress → hash → write-to-disk without buffering the full payload.

use std::io::{self, Read, Write as IoWrite};
use std::path::Path;

use bytes::Bytes;
use futures::StreamExt;
use nv_store::types::BankSet;
use sha2::{Digest, Sha256};
use sumo_crypto::RustCryptoBackend;
use sumo_onboard::decryptor::StreamingDecryptor;
use tokio::io::{AsyncRead, AsyncReadExt};
use tokio_util::io::StreamReader;

use crate::manifest_provider::{ManifestProvider, ValidatedFirmware};

use sovd_core::{BackendError, PackageStream};

const ZSTD_MAGIC: [u8; 4] = [0x28, 0xB5, 0x2F, 0xFD];

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Process a SUIT envelope from a streaming source.
///
/// 1. Parse CBOR envelope header (auth + manifest, ~1KB)
/// 2. Validate signature, digest, anti-rollback
/// 3. Stream "#firmware" payload through decrypt → decompress → hash → file write
///
/// Returns (package_id_hint, validated_firmware) where image_data is empty
/// (firmware was written directly to disk).
pub async fn process_envelope_stream(
    stream: PackageStream,
    manifest_provider: &dyn ManifestProvider,
    min_security_ver: u32,
    images_dir: Option<&Path>,
    bank_set: BankSet,
) -> Result<ValidatedFirmware, BackendError> {
    // Convert PackageStream → AsyncRead
    let reader = StreamReader::new(
        stream.map(|r| r.map_err(|e| io::Error::new(io::ErrorKind::Other, e))),
    );
    tokio::pin!(reader);

    // Step 1: Parse CBOR envelope header, get payload stream
    let (header_bytes, payload_len) = parse_envelope_header(&mut reader).await?;

    // Step 2: Validate using header-only envelope (no payload)
    let validated = validate_header(manifest_provider, &header_bytes, min_security_ver, bank_set)?;

    // If no payload (CRL manifest), return early
    if payload_len == 0 {
        return Ok(validated);
    }

    // Step 3: Build the async→sync processing pipeline via tokio channel.
    // Using tokio::sync::mpsc so the async send doesn't block the tokio runtime
    // (std::sync::mpsc::sync_channel::send blocks the thread when full).
    let (tx, rx) = tokio::sync::mpsc::channel::<Bytes>(32);

    // Determine image path
    let image_path = images_dir.map(|dir| {
        let set_name = match bank_set {
            BankSet::Hypervisor => "hyp",
            BankSet::Os1 => "os1",
            BankSet::Os2 => "os2",
            BankSet::Hsm => "hsm",
            BankSet::Qtd => "qtd",
        };
        // Target bank is the inactive one — ota::install() will determine this.
        // For streaming, we write to a temp file and rename at install time.
        dir.join(format!("{set_name}-staged.img"))
    });

    // Clone what the blocking task needs
    let header_for_decrypt = header_bytes.clone();
    let image_path_clone = image_path.clone();

    // Extract the expected digest from the manifest for verification
    let envelope = sumo_codec::decode::decode_envelope(&header_bytes)
        .map_err(|_| BackendError::Internal("failed to re-parse envelope header".into()))?;
    let manifest = sumo_onboard::manifest::Manifest { envelope };
    let expected_image_digest = manifest
        .image_digest(0)
        .map(|d| d.0.bytes.clone())
        .ok_or_else(|| BackendError::Internal("manifest has no image digest".into()))?;

    let has_encryption = manifest.encryption_info(0).is_some();

    // Set up decryptor if needed
    let suit_trust_anchor = manifest_provider
        .trust_anchor()
        .ok_or_else(|| BackendError::Internal("no trust anchor for streaming".into()))?
        .to_vec();
    let suit_device_key = manifest_provider.device_key().map(|k| k.to_vec());

    // Spawn the sync processing pipeline in a blocking thread
    let process_handle = tokio::task::spawn_blocking(move || {
        process_payload_sync(
            rx,
            &header_for_decrypt,
            has_encryption,
            &suit_trust_anchor,
            suit_device_key.as_deref(),
            &expected_image_digest,
            image_path_clone.as_deref(),
        )
    });

    // Step 4: Stream payload bytes from async reader to sync channel
    let mut remaining = payload_len as usize;
    let mut buf = vec![0u8; 64 * 1024];

    while remaining > 0 {
        let to_read = buf.len().min(remaining);
        let n = reader.read(&mut buf[..to_read]).await.map_err(|e| {
            BackendError::Internal(format!("stream read error: {e}"))
        })?;
        if n == 0 {
            break;
        }
        remaining -= n;
        tx.send(Bytes::copy_from_slice(&buf[..n])).await.map_err(|_| {
            BackendError::Internal("payload processing thread died".into())
        })?;
    }
    drop(tx); // Signal EOF

    // Wait for processing to complete
    let (image_size, image_hash) = process_handle
        .await
        .map_err(|e| BackendError::Internal(format!("processing task panicked: {e}")))?
        .map_err(|e| BackendError::Internal(format!("payload processing failed: {e}")))?;

    tracing::info!(
        image_size,
        "streaming SUIT processing complete — firmware written to disk"
    );

    // Return validated firmware with empty image_data (already written to disk)
    Ok(ValidatedFirmware {
        bank_set: validated.bank_set,
        image_meta: validated.image_meta,
        image_data: Vec::new(), // Already written to disk
        version_display: validated.version_display,
        image_sha256: Some(image_hash),
        image_size: Some(image_size as u64),
    })
}

// ---------------------------------------------------------------------------
// CBOR envelope header parser
// ---------------------------------------------------------------------------

/// Parse the SUIT envelope CBOR header from an async reader.
///
/// Returns (header_bytes, payload_length).
///
/// SUIT envelope is a CBOR map:
///   { 2: bstr(auth), 3: bstr(manifest), "#firmware": bstr(payload) }
///
/// We buffer the small entries (auth ~200B, manifest ~500B) and return
/// the payload length so the caller can stream it.
async fn parse_envelope_header<R: AsyncRead + Unpin>(
    reader: &mut R,
) -> Result<(Vec<u8>, u64), BackendError> {
    // We'll buffer the entire header portion. The header is small (<8KB typically).
    // Strategy: read CBOR incrementally. First read the map header, then iterate entries.
    // For auth (key 2) and manifest (key 3): buffer the value.
    // For "#firmware": extract payload length, stop buffering.

    // Read the first byte to determine map type
    let initial = read_byte(reader).await?;
    let mut header_buf = vec![initial];

    let (major, additional) = (initial >> 5, initial & 0x1f);

    // Could be Tag(107, map) or just map
    let map_entry_count;
    if major == 6 {
        // Tag — read tag value, then the inner map
        let _tag_val = read_cbor_uint(reader, additional, &mut header_buf).await?;
        let map_byte = read_byte(reader).await?;
        header_buf.push(map_byte);
        let (m, a) = (map_byte >> 5, map_byte & 0x1f);
        if m != 5 {
            return Err(BackendError::Internal("expected CBOR map in envelope".into()));
        }
        map_entry_count = read_cbor_uint(reader, a, &mut header_buf).await?;
    } else if major == 5 {
        map_entry_count = read_cbor_uint(reader, additional, &mut header_buf).await?;
    } else {
        return Err(BackendError::Internal(format!(
            "expected CBOR map or tag, got major type {major}"
        )));
    }

    let mut payload_len: u64 = 0;

    for _ in 0..map_entry_count {
        // Read key
        let key_byte = read_byte(reader).await?;
        let (key_major, key_add) = (key_byte >> 5, key_byte & 0x1f);

        match key_major {
            0 => {
                // Positive integer key (2 = auth, 3 = manifest, etc.)
                header_buf.push(key_byte);
                let _key_val = read_cbor_uint(reader, key_add, &mut header_buf).await?;

                // Read and buffer the value (bstr)
                let val_byte = read_byte(reader).await?;
                header_buf.push(val_byte);
                let (val_major, val_add) = (val_byte >> 5, val_byte & 0x1f);
                let val_len = read_cbor_uint(reader, val_add, &mut header_buf).await?;

                if val_major == 2 {
                    // Byte string — read fully and buffer
                    let mut data = vec![0u8; val_len as usize];
                    reader.read_exact(&mut data).await.map_err(map_io)?;
                    header_buf.extend_from_slice(&data);
                } else {
                    // Skip other value types by reading raw bytes
                    // (severable members etc.)
                    let skip_len = val_len as usize;
                    let mut skip = vec![0u8; skip_len];
                    reader.read_exact(&mut skip).await.map_err(map_io)?;
                    header_buf.extend_from_slice(&skip);
                }
            }
            3 => {
                // Text string key — could be "#firmware"
                header_buf.push(key_byte);
                let key_len = read_cbor_uint(reader, key_add, &mut header_buf).await?;
                let mut key_str = vec![0u8; key_len as usize];
                reader.read_exact(&mut key_str).await.map_err(map_io)?;
                header_buf.extend_from_slice(&key_str);
                let key_name = String::from_utf8_lossy(&key_str);

                if key_name == "#firmware" {
                    // Read bstr header for payload length, but DON'T read the payload data
                    let val_byte = read_byte(reader).await?;
                    // Don't add to header_buf — we'll reconstruct without payload
                    let (val_major, val_add) = (val_byte >> 5, val_byte & 0x1f);
                    if val_major != 2 {
                        return Err(BackendError::Internal(
                            "expected byte string for #firmware payload".into(),
                        ));
                    }
                    let mut temp_buf = Vec::new();
                    payload_len = read_cbor_uint(reader, val_add, &mut temp_buf).await?;

                    // Don't add payload bstr header to header_buf — we build a
                    // header-only envelope for validation (without #firmware entry).
                    // Remove the "#firmware" key we just added.
                    // Actually, simpler: rebuild the header as a CBOR map without #firmware.
                    // We'll just truncate header_buf to remove the text key.
                    let key_header_len = 1 + temp_for_uint_len(key_len) + key_len as usize;
                    header_buf.truncate(header_buf.len() - key_header_len);

                    // We've consumed all non-payload entries at this point
                    // (SUIT puts #firmware last in the map)
                    break;
                } else {
                    // Other text key — buffer the value
                    let val_byte = read_byte(reader).await?;
                    header_buf.push(val_byte);
                    let (val_major, val_add) = (val_byte >> 5, val_byte & 0x1f);
                    let val_len = read_cbor_uint(reader, val_add, &mut header_buf).await?;

                    if val_major == 2 {
                        let mut data = vec![0u8; val_len as usize];
                        reader.read_exact(&mut data).await.map_err(map_io)?;
                        header_buf.extend_from_slice(&data);
                    }
                }
            }
            _ => {
                return Err(BackendError::Internal(format!(
                    "unexpected CBOR key major type {key_major} in envelope"
                )));
            }
        }
    }

    // Rebuild header as valid CBOR: reduce the map entry count by 1 (dropped #firmware)
    if payload_len > 0 {
        // We need to fix the map entry count in the header
        let header_bytes = rebuild_header_without_firmware(&header_buf, map_entry_count)?;
        Ok((header_bytes, payload_len))
    } else {
        Ok((header_buf, 0))
    }
}

/// Rebuild the CBOR header with a corrected map entry count (N-1, excluding #firmware).
fn rebuild_header_without_firmware(
    raw: &[u8],
    original_count: u64,
) -> Result<Vec<u8>, BackendError> {
    let new_count = original_count - 1;
    let mut result = Vec::with_capacity(raw.len());

    let mut pos = 0;
    let first = raw[pos];
    let (major, additional) = (first >> 5, first & 0x1f);
    pos += 1;

    if major == 6 {
        // Tag — copy tag header
        result.push(first);
        let (_tag_val, bytes_consumed) = decode_cbor_uint(additional, &raw[pos..]);
        result.extend_from_slice(&raw[pos..pos + bytes_consumed]);
        pos += bytes_consumed;

        // Now the map header
        let map_byte = raw[pos];
        pos += 1;
        let (_, map_add) = (map_byte >> 5, map_byte & 0x1f);
        let (_, map_bytes_consumed) = decode_cbor_uint(map_add, &raw[pos..]);
        pos += map_bytes_consumed;

        // Write new map header
        encode_cbor_uint(5, new_count, &mut result);
    } else if major == 5 {
        // Map — skip original count
        let (_, bytes_consumed) = decode_cbor_uint(additional, &raw[pos..]);
        pos += bytes_consumed;

        // Write new map header
        encode_cbor_uint(5, new_count, &mut result);
    } else {
        return Err(BackendError::Internal("unexpected header structure".into()));
    }

    // Copy remaining entries as-is
    result.extend_from_slice(&raw[pos..]);
    Ok(result)
}

// ---------------------------------------------------------------------------
// Sync payload processing pipeline
// ---------------------------------------------------------------------------

/// Process the firmware payload synchronously: decrypt → decompress → hash → write.
///
/// Runs in a blocking thread. Returns (total_image_size, image_sha256).
fn process_payload_sync(
    rx: tokio::sync::mpsc::Receiver<Bytes>,
    header_bytes: &[u8],
    has_encryption: bool,
    _trust_anchor: &[u8],
    device_key: Option<&[u8]>,
    expected_digest: &[u8],
    image_path: Option<&Path>,
) -> Result<(usize, [u8; 32]), String> {
    let crypto = RustCryptoBackend::new();

    let mut channel_reader = ChannelReader {
        rx,
        current: Bytes::new(),
    };

    if has_encryption {
        // Parse envelope to get manifest for decryptor setup
        let envelope = sumo_codec::decode::decode_envelope(header_bytes)
            .map_err(|e| format!("re-parse envelope: {e:?}"))?;
        let manifest = sumo_onboard::manifest::Manifest { envelope };

        // Get device key
        let dk_bytes = device_key.ok_or("encrypted payload but no device key")?;
        let dk = coset::CborSerializable::from_slice(dk_bytes)
            .map_err(|e| format!("invalid device key: {e:?}"))?;

        let decryptor = StreamingDecryptor::new(&manifest, 0, &dk, &crypto)
            .map_err(|e| format!("decryptor setup: {e:?}"))?;

        let mut decrypt_reader = DecryptReader::new(channel_reader, decryptor);

        // Read first chunk to detect zstd
        let mut first_buf = [0u8; 4];
        let first_n = read_exact_or_eof(&mut decrypt_reader, &mut first_buf)?;

        if first_n >= 4 && first_buf[..4] == ZSTD_MAGIC {
            // Encrypted + compressed: chain through ruzstd
            let prefixed = PrefixReader::new(&first_buf[..first_n], decrypt_reader);
            process_decompressed(prefixed, expected_digest, image_path)
        } else {
            // Encrypted, not compressed: hash + write directly
            let prefixed = PrefixReader::new(&first_buf[..first_n], decrypt_reader);
            process_plain(prefixed, expected_digest, image_path)
        }
    } else {
        // Unencrypted — read first bytes to check for zstd
        let mut first_buf = [0u8; 4];
        let first_n = read_exact_or_eof(&mut channel_reader, &mut first_buf)?;

        if first_n >= 4 && first_buf[..4] == ZSTD_MAGIC {
            let prefixed = PrefixReader::new(&first_buf[..first_n], channel_reader);
            process_decompressed(prefixed, expected_digest, image_path)
        } else {
            let prefixed = PrefixReader::new(&first_buf[..first_n], channel_reader);
            process_plain(prefixed, expected_digest, image_path)
        }
    }
}

/// Process a plain (uncompressed) stream: hash + write.
fn process_plain<R: Read>(
    mut reader: R,
    expected_digest: &[u8],
    image_path: Option<&Path>,
) -> Result<(usize, [u8; 32]), String> {
    let mut hasher = Sha256::new();
    let mut total = 0usize;
    let mut buf = vec![0u8; 64 * 1024];

    let mut file = image_path
        .map(|p| {
            std::fs::File::create(p)
                .map_err(|e| format!("create {}: {e}", p.display()))
        })
        .transpose()?;

    loop {
        let n = reader.read(&mut buf).map_err(|e| format!("read: {e}"))?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
        if let Some(ref mut f) = file {
            f.write_all(&buf[..n])
                .map_err(|e| format!("write: {e}"))?;
        }
        total += n;
    }

    let hash = verify_digest(hasher, expected_digest)?;
    Ok((total, hash))
}

/// Process a compressed stream: decompress → hash → write.
fn process_decompressed<R: Read>(
    reader: R,
    expected_digest: &[u8],
    image_path: Option<&Path>,
) -> Result<(usize, [u8; 32]), String> {
    let mut decoder = ruzstd::StreamingDecoder::new(reader)
        .map_err(|e| format!("zstd init: {e}"))?;

    let mut hasher = Sha256::new();
    let mut total = 0usize;
    let mut buf = vec![0u8; 64 * 1024];

    let mut file = image_path
        .map(|p| {
            std::fs::File::create(p)
                .map_err(|e| format!("create {}: {e}", p.display()))
        })
        .transpose()?;

    loop {
        let n = decoder.read(&mut buf).map_err(|e| format!("decompress: {e}"))?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
        if let Some(ref mut f) = file {
            f.write_all(&buf[..n])
                .map_err(|e| format!("write: {e}"))?;
        }
        total += n;
    }

    let hash = verify_digest(hasher, expected_digest)?;
    Ok((total, hash))
}

fn verify_digest(hasher: Sha256, expected: &[u8]) -> Result<[u8; 32], String> {
    let computed: [u8; 32] = hasher.finalize().into();
    if computed.as_slice() != expected {
        return Err("image digest mismatch".into());
    }
    Ok(computed)
}

// ---------------------------------------------------------------------------
// Validation using header-only envelope
// ---------------------------------------------------------------------------

fn validate_header(
    manifest_provider: &dyn ManifestProvider,
    header_bytes: &[u8],
    min_security_ver: u32,
    expected_bank_set: BankSet,
) -> Result<ValidatedFirmware, BackendError> {
    // Validate using the header-only envelope (no #firmware payload).
    // The validator checks auth + manifest — doesn't need the payload.
    let validated = manifest_provider
        .validate_header_only(header_bytes, min_security_ver)
        .map_err(|e| BackendError::InvalidRequest(format!("manifest validation: {e}")))?;

    if validated.bank_set != expected_bank_set {
        return Err(BackendError::InvalidRequest(format!(
            "manifest targets {:?}, but this is {:?}",
            validated.bank_set, expected_bank_set
        )));
    }

    Ok(validated)
}

// ---------------------------------------------------------------------------
// ChannelReader — sync Read over mpsc::Receiver<Bytes>
// ---------------------------------------------------------------------------

struct ChannelReader {
    rx: tokio::sync::mpsc::Receiver<Bytes>,
    current: Bytes,
}

impl Read for ChannelReader {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.current.is_empty() {
            // blocking_recv() is safe here — we run inside spawn_blocking
            match self.rx.blocking_recv() {
                Some(bytes) => self.current = bytes,
                None => return Ok(0), // channel closed = EOF
            }
        }
        let n = buf.len().min(self.current.len());
        buf[..n].copy_from_slice(&self.current[..n]);
        self.current = self.current.slice(n..);
        Ok(n)
    }
}

// ---------------------------------------------------------------------------
// DecryptReader — wraps StreamingDecryptor as std::io::Read
// ---------------------------------------------------------------------------

struct DecryptReader<R: Read> {
    inner: R,
    decryptor: StreamingDecryptor,
    out_buf: Vec<u8>,
    out_pos: usize,
    out_len: usize,
    finished: bool,
}

impl<R: Read> DecryptReader<R> {
    fn new(inner: R, decryptor: StreamingDecryptor) -> Self {
        Self {
            inner,
            decryptor,
            out_buf: vec![0u8; 4096 + 256], // CHUNK_SIZE + slack for GCM
            out_pos: 0,
            out_len: 0,
            finished: false,
        }
    }
}

impl<R: Read> Read for DecryptReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        // Drain buffered output first
        if self.out_pos < self.out_len {
            let n = buf.len().min(self.out_len - self.out_pos);
            buf[..n].copy_from_slice(&self.out_buf[self.out_pos..self.out_pos + n]);
            self.out_pos += n;
            return Ok(n);
        }

        if self.finished {
            return Ok(0);
        }

        // Read a chunk from inner and decrypt
        let mut in_buf = [0u8; 4096];
        let n = self.inner.read(&mut in_buf)?;

        if n == 0 {
            // EOF — finalize decryption (verify GCM tag)
            self.finished = true;
            let pt_len = self
                .decryptor
                .finalize(&mut self.out_buf)
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("{e:?}")))?;
            self.out_pos = 0;
            self.out_len = pt_len;

            if pt_len == 0 {
                return Ok(0);
            }
            let copy = buf.len().min(pt_len);
            buf[..copy].copy_from_slice(&self.out_buf[..copy]);
            self.out_pos = copy;
            return Ok(copy);
        }

        let pt_len = self
            .decryptor
            .update(&in_buf[..n], &mut self.out_buf)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("{e:?}")))?;

        if pt_len == 0 {
            // Decryptor buffering (e.g. GCM tag) — recurse to get more data
            return self.read(buf);
        }

        self.out_pos = 0;
        self.out_len = pt_len;

        let copy = buf.len().min(pt_len);
        buf[..copy].copy_from_slice(&self.out_buf[..copy]);
        self.out_pos = copy;
        Ok(copy)
    }
}

// ---------------------------------------------------------------------------
// PrefixReader — prepend already-read bytes to a reader
// ---------------------------------------------------------------------------

struct PrefixReader<R: Read> {
    prefix: Vec<u8>,
    prefix_pos: usize,
    inner: R,
}

impl<R: Read> PrefixReader<R> {
    fn new(prefix: &[u8], inner: R) -> Self {
        Self {
            prefix: prefix.to_vec(),
            prefix_pos: 0,
            inner,
        }
    }
}

impl<R: Read> Read for PrefixReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.prefix_pos < self.prefix.len() {
            let remaining = &self.prefix[self.prefix_pos..];
            let n = buf.len().min(remaining.len());
            buf[..n].copy_from_slice(&remaining[..n]);
            self.prefix_pos += n;
            Ok(n)
        } else {
            self.inner.read(buf)
        }
    }
}

// ---------------------------------------------------------------------------
// CBOR helpers
// ---------------------------------------------------------------------------

async fn read_byte<R: AsyncRead + Unpin>(reader: &mut R) -> Result<u8, BackendError> {
    let mut b = [0u8; 1];
    reader.read_exact(&mut b).await.map_err(map_io)?;
    Ok(b[0])
}

/// Read a CBOR unsigned integer given the additional info from the initial byte.
/// Appends raw bytes to `buf` for recording.
async fn read_cbor_uint<R: AsyncRead + Unpin>(
    reader: &mut R,
    additional: u8,
    buf: &mut Vec<u8>,
) -> Result<u64, BackendError> {
    match additional {
        0..=23 => Ok(additional as u64),
        24 => {
            let mut b = [0u8; 1];
            reader.read_exact(&mut b).await.map_err(map_io)?;
            buf.extend_from_slice(&b);
            Ok(b[0] as u64)
        }
        25 => {
            let mut b = [0u8; 2];
            reader.read_exact(&mut b).await.map_err(map_io)?;
            buf.extend_from_slice(&b);
            Ok(u16::from_be_bytes(b) as u64)
        }
        26 => {
            let mut b = [0u8; 4];
            reader.read_exact(&mut b).await.map_err(map_io)?;
            buf.extend_from_slice(&b);
            Ok(u32::from_be_bytes(b) as u64)
        }
        27 => {
            let mut b = [0u8; 8];
            reader.read_exact(&mut b).await.map_err(map_io)?;
            buf.extend_from_slice(&b);
            Ok(u64::from_be_bytes(b))
        }
        _ => Err(BackendError::Internal(format!(
            "unsupported CBOR additional info: {additional}"
        ))),
    }
}

/// Decode a CBOR uint from a byte slice (sync version for header rebuild).
fn decode_cbor_uint(additional: u8, data: &[u8]) -> (u64, usize) {
    match additional {
        0..=23 => (additional as u64, 0),
        24 => (data[0] as u64, 1),
        25 => (u16::from_be_bytes([data[0], data[1]]) as u64, 2),
        26 => (
            u32::from_be_bytes([data[0], data[1], data[2], data[3]]) as u64,
            4,
        ),
        27 => (
            u64::from_be_bytes([
                data[0], data[1], data[2], data[3], data[4], data[5], data[6], data[7],
            ]),
            8,
        ),
        _ => (0, 0),
    }
}

/// Encode a CBOR major type + uint value.
fn encode_cbor_uint(major: u8, value: u64, buf: &mut Vec<u8>) {
    let mt = major << 5;
    if value < 24 {
        buf.push(mt | value as u8);
    } else if value <= u8::MAX as u64 {
        buf.push(mt | 24);
        buf.push(value as u8);
    } else if value <= u16::MAX as u64 {
        buf.push(mt | 25);
        buf.extend_from_slice(&(value as u16).to_be_bytes());
    } else if value <= u32::MAX as u64 {
        buf.push(mt | 26);
        buf.extend_from_slice(&(value as u32).to_be_bytes());
    } else {
        buf.push(mt | 27);
        buf.extend_from_slice(&value.to_be_bytes());
    }
}

/// Calculate how many extra bytes a CBOR uint needs (for tracking buffer positions).
fn temp_for_uint_len(value: u64) -> usize {
    if value < 24 {
        0
    } else if value <= u8::MAX as u64 {
        1
    } else if value <= u16::MAX as u64 {
        2
    } else if value <= u32::MAX as u64 {
        4
    } else {
        8
    }
}

fn read_exact_or_eof<R: Read>(reader: &mut R, buf: &mut [u8]) -> Result<usize, String> {
    let mut total = 0;
    while total < buf.len() {
        match reader.read(&mut buf[total..]) {
            Ok(0) => break,
            Ok(n) => total += n,
            Err(e) => return Err(format!("read: {e}")),
        }
    }
    Ok(total)
}

fn map_io(e: io::Error) -> BackendError {
    BackendError::Internal(format!("I/O error: {e}"))
}
