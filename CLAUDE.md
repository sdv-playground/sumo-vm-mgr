# CLAUDE.md — sumo-vm-mgr

## Project Overview

Platform-agnostic machine manager. Handles A/B bank switching, boot
decisions, OTA updates with SUIT manifest validation, encrypted firmware,
and SOVD-compatible diagnostics.

Developed and tested on Linux (file-backed storage + QEMU). The `machine-mgr`
trait layer + per-crate `BlockDevice` / `SharedMemory` / `HsmCryptoProvider`
traits let the same business logic run on QNX once the concrete impls exist.

On QNX, `supernova-machine-manager` collapses `vm-service` + `vm-mgr` +
`host-os-mgr` into one binary.

### Architecture

Cargo workspace with 10 crates. Bottom-up:

- **nv-store** (lib): sector-rotated NV regions (boot state, factory,
  FW meta, runtime DIDs) with CRC-32 and monotonic `write_seq`, over a
  pluggable `BlockDevice`. Platform-independent.
- **secstore** (lib): encrypted key-metadata persistence with pluggable
  `SecstoreEncryptor` + `SecstoreBackend`. File backend + dev "encryptor"
  today; HSE-backed in production.
- **vm-boot** (lib+bin): boot-time logic. Reads NV boot state, verifies
  image hashes, handles trial boot counting and auto-rollback. Runs at
  startup for ALL bank sets (host-os, vm1, vm2, hsm).
- **hsm** (lib): HSM management trait (`HsmProvider`, `HsmCryptoProvider`).
  `SimHsm` (dev/test: vhsm-ssd + file keystore) works; `QnxHsm` is a stub
  waiting for HSE integration.
- **vhsm-ssd** (lib+bin): host-side daemon terminating the v2 handle-based
  vHSM wire protocol from guest `/dev/vhsm`. Transports: vsock (Linux/QEMU)
  and QNX-native shm/IPC.
- **vm-devices** (lib): virtual CAN, health, and time simulators running
  on shared memory. Abstracts transport (ivshmem vs QNX native shm) and
  clock (real-time vs simulation-stepping vs gPTP-corrected).
- **vm-service** (lib+bin): QEMU / `qvm` lifecycle, per-bank VM config,
  ivshmem-server management, QMP integration, IPC to diagnostics.
- **machine-mgr** (lib): platform-agnostic `Machine` / `Component` trait
  layer. See `crates/machine-mgr/src/lib.rs` for the hierarchy.
- **host-os-mgr** (lib): Host OS component — IFS activation (dev: mount +
  atomic copy, prod: raw partition write), A/B boot commit/rollback, reboot
  coordination. Implements `machine_mgr::Component`.
- **vm-mgr** (lib+bins: `vm-sovd`): SUIT validation, encrypted firmware
  streaming pipeline, OTA engine (install/commit/rollback), DID resolution,
  and the SOVD wire adapter. `VmBackend` is the per-component state machine;
  `ComponentDiagBackend` routes SOVD calls through `machine-mgr::Component`.

### Separation of Concerns

```
vm-boot        — WHEN to boot which bank (runs once at startup, all bank sets)
vm-service     — HOW to start/stop VMs (QEMU QMP, qvm lifecycle, ivshmem)
vm-mgr         — WHAT to flash and verify (OTA engine, SUIT, SOVD wire)
host-os-mgr    — Host-specific: IFS write, partition swap, reboot
machine-mgr    — Abstract trait layer connecting them all
```

### Key Dependencies

- **sovd-core / sovd-api** (from SOVDd): `DiagnosticBackend` trait + HTTP
  routing. Keeps wire-format compatibility with `sovd-client` and SOVD
  Explorer.
- **sumo-onboard / sumo-crypto / sumo-codec** (from sumo-rs): SUIT manifest
  validation, streaming decryption (AES-GCM + ECDH-ES+A128KW), decompression.
- **sumo-processor**: SUIT command-sequence interpreter.

### Key Concepts

- Four bank sets: host-os (IFS + rootfs, updated atomically), vm1, vm2
  (A/B banked), hsm (single-bank, no rollback)
- Two-process architecture: `vm-service` (QEMU/qvm lifecycle) + `vm-sovd`
  (diagnostics/OTA). Supernova merges them into one binary.
- Per-bank VM config: `vm-config.yaml` in bank directories, delivered
  alongside firmware via OTA, rolls back with firmware
- NV store: sector rotation, CRC-32, monotonic `write_seq`
- Trial boot: up to 10 reboots before auto-rollback
- Copy-on-update: clone runtime DIDs to target bank before OTA write
- Security version (SUIT custom param -257): separate from `sequence_number`,
  enables A/B fleet testing. Floor raised only on commit.
- CRL manifests: policy-only, no firmware, raises anti-rollback floor
- Encrypted firmware: AES-128-GCM + ECDH-ES+A128KW per-device
- Multi-payload SUIT: host-os carries `#ifs` + `#rootfs`; VMs carry
  `#kernel` + `#firmware` + `#config` — compressed and encrypted per-ECU
- Session/security: programming session + seed/key unlock before flash
- `SecurityProvider` trait: pluggable key validation (`TestSecurityProvider`
  for dev)
- `ManifestProvider` trait: pluggable manifest validation (`SuitProvider`
  default)

### Key Files

```
crates/vm-mgr/src/
  backend.rs              — VmBackend: per-component state machine
  component_adapter.rs    — VmBackendComponent: exposes VmBackend via Component
  diag_backend.rs         — ComponentDiagBackend: routes SOVD → Component
  suit_provider.rs        — SUIT envelope validation
  manifest_provider.rs    — ManifestProvider trait
  ota.rs                  — OTA engine: install, commit, rollback
  streaming.rs            — upload pipeline (decrypt + decompress + hash)
  did.rs                  — UDS DID resolution (F187-F19E + custom)
  sovd/security.rs        — SecurityProvider trait + TestSecurityProvider

crates/host-os-mgr/src/
  component.rs            — HostOsComponent: machine_mgr::Component impl
  ifs/dev.rs              — DevIfsActivator (mount + atomic copy)
  ifs/partition.rs        — PartitionIfsActivator (raw block write)

crates/machine-mgr/src/
  component.rs            — Component trait (async, ~35 methods)
  machine.rs              — Machine + MachineRegistry (composition)
  types.rs                — Capabilities, RuntimeState, FlashId, ...

crates/hsm/src/
  crypto.rs               — SimHsm HsmCryptoProvider (RustCrypto)
  sim.rs                  — SimHsm lifecycle (spawns vhsm-ssd + file keys)
  payload.rs              — HsmKeystore CBOR schema
  qnx.rs                  — QnxHsm stub

crates/vhsm-ssd/src/
  proto.rs + codec.rs     — wire format (v2, handle-based)
  handle_table.rs         — dynamic handle allocator (0x0100+)
  policy.rs               — per-CID ACL
  handler.rs              — op dispatch → HsmCryptoProvider
  transport.rs            — vsock / QNX shm

example/
  build.rs                — Generate keys, encrypted firmware, CRL manifests
  run.sh                  — Start SOVD server + security helper
  factory/                — Factory provisioning YAML manifests
  config/secrets.toml     — Security helper ECU secrets
```

### Specs

- `specs/disk-layout.md`      — GPT partition table
- `specs/nv-store-format.md`  — NV partition internal layout
- `specs/bank-state-machine.md` — Update lifecycle state machine
- `docs/simulation-stepping.md` — deterministic time for CI / hardware-in-loop
- `ARCHITECTURE.md`           — full subsystem walkthrough

## Build & Test

```bash
cargo build
cargo test              # 425+ tests
cargo run --example build   # Generate SUIT artifacts
./example/run.sh --fresh    # Start server
```

## Workflow

Plan mode for non-trivial tasks, subagents for research.
Use sovd-core enums — never hand-build JSON response strings.
NV committed flag is source of truth after power cycle.
