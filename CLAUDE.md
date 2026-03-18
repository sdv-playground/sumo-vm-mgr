# CLAUDE.md — vm-mgr

## Project Overview

Platform-agnostic VM lifecycle manager. Handles A/B bank switching, boot
decisions, OTA updates, and automotive diagnostics (SOVD/DoIP/UDS DIDs)
for hypervisor-managed VMs.

Developed and tested on Linux (file-backed storage + QEMU), deployable on
any hypervisor (QNX qvm, Xen, etc.) via the backend trait.

### Architecture

Three Rust crates in a workspace:

- **nv-store** (lib): NV data types, sector-rotated storage, CRC integrity,
  block device abstraction. Platform-independent.
- **vm-boot** (lib+bin): Boot-time logic. Reads NV boot state, verifies image
  hashes, handles trial boot counting and auto-rollback. Backend trait for
  VM launch (QEMU for dev, QNX qvm for production).
- **vm-diagserver** (bin): Diagnostic server. UDS/SOVD interface, DID
  resolution, OTA download/verify/write, commit/rollback commands.

### Key Concepts

- Three A/B bank sets: hypervisor, OS1, OS2 (independent state machines)
- NV store: raw partition, sector rotation, CRC-32, monotonic write_seq
- Trial boot: up to 10 reboots before auto-rollback
- Copy-on-update: clone Runtime DIDs to target bank before OTA write
- Anti-rollback: min_security_ver floor raised on commit

### Specs

- `specs/disk-layout.md` — GPT partition table
- `specs/nv-store-format.md` — NV partition internal layout
- `specs/bank-state-machine.md` — Update lifecycle state machine

## Build & Test

```bash
cargo build
cargo test
```

## Workflow

Plan mode for non-trivial tasks, subagents for research, lessons in
tasks/lessons.md, verify before done.
