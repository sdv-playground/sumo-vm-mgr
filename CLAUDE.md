# CLAUDE.md — vm-mgr

## Project Overview

Platform-agnostic VM lifecycle manager. Handles A/B bank switching, boot
decisions, OTA updates with SUIT manifest validation, encrypted firmware,
and SOVD-compatible diagnostics for hypervisor-managed VMs.

Developed and tested on Linux (file-backed storage + QEMU), deployable on
any hypervisor (QNX qvm, Xen, etc.) via the backend trait.

### Architecture

Three Rust crates in a workspace:

- **nv-store** (lib): NV data types, sector-rotated storage, CRC integrity,
  block device abstraction. Platform-independent.
- **vm-boot** (lib+bin): Boot-time logic. Reads NV boot state, verifies image
  hashes, handles trial boot counting and auto-rollback. Backend trait for
  VM launch (QEMU for dev, QNX qvm for production).
- **vm-diagserver** (lib+bins): SUIT manifest validation (sumo-onboard),
  encrypted firmware pipeline, OTA engine (install/commit/rollback),
  DID resolution, VmBackend implementing sovd-core DiagnosticBackend.

### Key Dependencies

- **sovd-core / sovd-api** (from SOVDd): DiagnosticBackend trait + HTTP routing.
  Ensures wire-format compatibility with sovd-client and SOVD Explorer.
- **sumo-onboard / sumo-crypto / sumo-codec** (from sumo-rs): SUIT manifest
  validation, streaming decryption (AES-GCM + ECDH-ES+A128KW), decompression.
- **sumo-processor**: SUIT command sequence interpreter.

### Key Concepts

- Three A/B bank sets: hypervisor, OS1, OS2 (independent state machines)
- NV store: raw partition, sector rotation, CRC-32, monotonic write_seq
- Trial boot: up to 10 reboots before auto-rollback
- Copy-on-update: clone Runtime DIDs to target bank before OTA write
- Security version (custom param -257): separate from sequence_number,
  enables A/B fleet testing. Floor raised only on commit.
- CRL manifests: policy-only, no firmware, raises anti-rollback floor
- Encrypted firmware: AES-128-GCM + ECDH-ES+A128KW per-device
- Session/security: programming session + seed/key unlock before flash
- SecurityProvider trait: pluggable key validation (TestSecurityProvider for dev)
- ManifestProvider trait: pluggable manifest validation (SuitProvider default)

### Key Files

```
crates/diagserver/src/
  backend.rs              — VmBackend: DiagnosticBackend implementation
  suit_provider.rs        — SUIT envelope validation + orchestrator integration
  manifest_provider.rs    — ManifestProvider trait
  ota.rs                  — OTA engine: install, commit, rollback
  did.rs                  — UDS DID resolution (F187-F19E + custom)
  sovd/security.rs        — SecurityProvider trait + TestSecurityProvider

example/
  build.rs                — Generate keys, encrypted firmware, CRL manifests
  run.sh                  — Start SOVD server + security helper
  factory/                — Factory provisioning YAML manifests
  config/secrets.toml     — Security helper ECU secrets
```

### Specs

- `specs/disk-layout.md` — GPT partition table
- `specs/nv-store-format.md` — NV partition internal layout
- `specs/bank-state-machine.md` — Update lifecycle state machine

## Build & Test

```bash
cargo build
cargo test              # 105+ tests
cargo run --example build   # Generate SUIT artifacts
./example/run.sh --fresh    # Start server
```

## Workflow

Plan mode for non-trivial tasks, subagents for research.
Use sovd-core enums — never hand-build JSON response strings.
NV committed flag is source of truth after power cycle.
