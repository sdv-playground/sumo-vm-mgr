# vm-mgr

Platform-agnostic VM lifecycle manager for automotive ECUs. Handles A/B bank switching, boot decisions, OTA software updates with SUIT manifest validation, encrypted firmware, and SOVD-compatible diagnostics.

## Quick Start

```bash
cargo build
cargo test                      # 105+ tests

# Generate SUIT signing keys + encrypted firmware + CRL manifests
cargo run --example build

# Start SOVD server (port 4000) with security helper (port 9100)
./example/run.sh

# Or fresh start (wipes NV store)
./example/run.sh --fresh
```

Then connect [SOVD Explorer](https://github.com/sdv-playground/SOVD-explorer) to `http://localhost:4000`.

**SOVD Explorer settings:** Helper URL `http://localhost:9100`, token `dev-secret-123`.

## Architecture

```
┌──────────────────────────────────────────────┐
│ vm-mgr                                        │
│                                               │
│  nv-store        NV data: boot state, FW meta,│
│  (lib)           factory, runtime DIDs, DTCs   │
│                                               │
│  vm-boot         Boot decisions, trial count,  │
│  (lib+bin)       hash verify, QEMU/QNX backend │
│                                               │
│  vm-diagserver   SUIT validation, OTA engine,  │
│  (lib+bins)      DID resolution, VmBackend     │
│       │                                        │
│       ├── sovd-core (DiagnosticBackend trait)  │
│       ├── sovd-api  (HTTP routing)            │
│       ├── sumo-onboard (SUIT validation)      │
│       └── sumo-processor (command sequences)  │
└──────────────────────────────────────────────┘
```

### Crates

| Crate | Binaries | Purpose |
|-------|----------|---------|
| `nv-store` | — | Sector-rotated NV storage with CRC-32 integrity |
| `vm-boot` | `vm-boot`, `vm-runner` | Boot decisions, trial counting, auto-rollback, backend trait |
| `vm-diagserver` | `vm-diagserver`, `vm-sovd` | SUIT+SOVD: manifest validation, OTA engine, DID resolution, REST server |

## SUIT Manifest Integration

Firmware updates use [RFC 9124 SUIT](https://datatracker.ietf.org/doc/draft-ietf-suit-manifest/) manifests via [sumo-rs](https://github.com/tr-sdv-sandbox/sumo-rs):

- **Signed envelopes** — COSE_Sign1 signature verification
- **Encrypted firmware** — AES-128-GCM + ECDH-ES+A128KW per-device key wrapping
- **Compressed payloads** — zstd compression before encryption
- **Security version** — custom parameter (-257), separate from sequence_number
- **CRL manifests** — policy-only (no firmware), raises anti-rollback floor
- **SUIT command sequences** — manifests declare the update flow (install, validate, invoke)
- **Content-addressable firmware** — manifests ~500 bytes, firmware stored by SHA-256

### Security Version Model

Separates build ordering from anti-rollback policy:

```
v1.0.0 (seq=1, secver=1) ←→ v1.1.0 (seq=2, secver=1)   # A/B fleet testing
v1.2.0 (seq=3, secver=2)                                   # security-critical fix
CRL manifest (secver=2, no payload, 228 bytes)              # blocks secver < 2
```

### Example Firmware

```bash
cargo run --example build
```

Generates in `example/output/`:

| File | Description |
|------|-------------|
| `os1-v1.0.0.suit` | Encrypted firmware (secver=1) |
| `os1-v1.1.0.suit` | Encrypted firmware (secver=1) |
| `os1-v1.2.0.suit` | Encrypted firmware (secver=1) |
| `os1-v1.3.0.suit` | Encrypted firmware (secver=1) |
| `os1-v1.2.0-secver2-full.suit` | Re-signed with secver=2 |
| `os1-crl-secver2.suit` | CRL: blocks secver < 2 (228 bytes) |
| `firmware/*.bin` | Content-addressable binaries (by SHA-256) |

## SOVD Server

Uses [sovd-core](https://github.com/sdv-playground/SOVDd) `DiagnosticBackend` trait — wire-format compatible with [sovd-client](https://github.com/sdv-playground/SOVDd) and [SOVD Explorer](https://github.com/sdv-playground/SOVD-explorer).

### Components

| Component | Bank Set | Description |
|-----------|----------|-------------|
| `hyp` | Hypervisor | Hypervisor A/B bank set |
| `os1` | OS1 | Primary OS VM |
| `os2` | OS2 | Secondary OS VM |

### Endpoints

Standard SOVD REST API including:

```
GET/PUT  /vehicle/v1/components/{id}/modes/session    # Programming session
GET/PUT  /vehicle/v1/components/{id}/modes/security    # Seed/key security unlock
POST     /vehicle/v1/components/{id}/files             # Upload firmware
POST     /vehicle/v1/components/{id}/files/{id}/verify # Verify package
POST     /vehicle/v1/components/{id}/flash/transfer    # Start flash
GET      /vehicle/v1/components/{id}/flash/activation  # Activation state
POST     /vehicle/v1/components/{id}/flash/commit      # Commit trial
POST     /vehicle/v1/components/{id}/flash/rollback    # Rollback trial
POST     /vehicle/v1/components/{id}/reset             # ECU reset
```

Plus data (DIDs), faults (DTCs), and all standard SOVD resource types.

### Session & Security

Flash operations require programming session + security unlock:

1. `PUT /modes/session {"value": "programming"}`
2. `PUT /modes/security {"value": "level1_requestseed"}` → seed
3. `PUT /modes/security {"value": "level1", "key": "..."}` → unlocked
4. Upload + flash + commit

`SecurityProvider` trait is pluggable — `TestSecurityProvider` (XOR 0xFF) for development, production HSM for deployment. Uses [SOVD Security Helper](https://github.com/skarlsson/SOVD-security-helper) for key derivation.

## Key Concepts

- **Three A/B bank sets**: Hypervisor, OS1, OS2 — independent state machines
- **Trial boot**: Up to 10 reboots before auto-rollback to previous bank
- **Copy-on-update**: Runtime DIDs/DTCs cloned to target bank before OTA write
- **NV persistence**: Boot state, security floor survive power cycles (sector-rotated, CRC-protected)
- **Backend trait**: `QemuBackend` for dev/test, `QnxBackend` stub for production

## NV Store Layout

```
Boot State     — active bank, committed flag, boot count (per bank set)
Factory        — serial number, VIN, HW numbers (write-once)
FW Meta A/B    — firmware version, SHA-256, security version, UDS DIDs
Runtime A/B    — writable DIDs, DTCs (cloned on update)
```

## Flash Flow

```
Session → Programming → Security Unlock → Upload SUIT Envelope
  → Validate (signature + digest + security_version)
  → Install (decrypt + decompress + write to target bank)
  → Reset → Trial (activated, not committed)
  → Health check → Commit (permanent) or Rollback
```

For CRL manifests: Upload → Apply floor → Done (no flash/reset/commit).

## Related Projects

| Project | Description |
|---------|-------------|
| [sumo-rs](https://github.com/tr-sdv-sandbox/sumo-rs) | SUIT manifest library (Rust) |
| [sumo-sovd](https://github.com/sdv-playground/sumo-sovd) | Campaign orchestrator over SOVD |
| [sumo-campaign-viewer](https://github.com/sdv-playground/sumo-campaign-viewer) | Campaign visualization tool |
| [SOVDd](https://github.com/sdv-playground/SOVDd) | SOVD diagnostic server |
| [SOVD Explorer](https://github.com/sdv-playground/SOVD-explorer) | Diagnostic GUI |
| [SUMO specs](https://github.com/tr-sdv-sandbox/sumo) | Specifications and feature mapping |
