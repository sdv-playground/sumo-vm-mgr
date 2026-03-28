# vm-mgr

Platform-agnostic VM lifecycle manager for automotive ECUs. Handles A/B bank switching, boot decisions, OTA software updates, and UDS DID resolution. Includes a SOVD REST server for remote diagnostics.

Reference implementation — designed to be forked and adapted with proprietary manifests and transport layers.

## Crates

| Crate | Binary | Purpose |
|-------|--------|---------|
| `nv-store` | — | Sector-rotated NV storage with CRC-32 integrity |
| `vm-boot` | `vm-boot` | Boot decisions: trial boot, auto-rollback, image hash verification |
| `vm-boot` | `vm-runner` | Boot loop orchestrator (process_boot → start VM → wait → repeat) |
| `vm-diagserver` | `vm-diagserver` | CLI tool: OTA install/commit/rollback, UDS DID resolution (F187–F199) |
| `vm-diagserver` | `vm-sovd` | SOVD REST server exposing bank sets as SOVD components |

`vm-boot` produces two binaries: `vm-boot` handles a single boot decision (pick bank, verify hash, increment trial counter), while `vm-runner` wraps it in a loop that launches the VM via the backend trait and restarts on exit.

`vm-diagserver` produces two binaries: `vm-diagserver` is the CLI for direct NV store access, while `vm-sovd` is an HTTP server exposing the same data via SOVD-compatible REST endpoints.

## Prerequisites

- Rust toolchain (stable)
- QEMU (for the dev/test backend)

## Quick Start

```bash
cargo build
cargo test   # 101 tests

# Run the boot loop + SOVD server
./example/run.sh --profile example/profiles/os1-minimal.toml --images /path/to/output

# From another terminal — SOVD REST API
curl http://localhost:8080/vehicle/v1/components
curl http://localhost:8080/vehicle/v1/components/os1/data
curl http://localhost:8080/vehicle/v1/components/os1/flash/activation

# Or use the CLI directly
./target/debug/vm-diagserver /tmp/vm-mgr-nv.bin status os1
```

`run.sh` starts both `vm-runner` (boot loop) and `vm-sovd` (SOVD server) sharing the same NV store.

| Flag | Default | Description |
|------|---------|-------------|
| `--profile <path>` | *(required)* | VM profile TOML file |
| `--images <dir>` | *(required)* | Directory with bank images |
| `--sim-dir <dir>` | — | Directory with simulator binaries |
| `--nv <path>` | `/tmp/vm-mgr-nv.bin` | NV store file path |

| Env var | Default | Description |
|---------|---------|-------------|
| `VM_MGR_NV` | `/tmp/vm-mgr-nv.bin` | NV store file path |
| `VM_MGR_SOVD_ADDR` | `0.0.0.0:8080` | SOVD server bind address |

## SOVD Server

`vm-sovd` exposes the three A/B bank sets as SOVD-compatible components:

| Component | Bank Set | Description |
|-----------|----------|-------------|
| `hyp` | Hypervisor | Hypervisor A/B bank set |
| `os1` | OS1 | Primary OS VM A/B bank set |
| `os2` | OS2 | Secondary OS VM A/B bank set |

### Endpoints

```
GET  /health
GET  /vehicle/v1/components
GET  /vehicle/v1/components/{id}
GET  /vehicle/v1/components/{id}/data
GET  /vehicle/v1/components/{id}/data/{param}
PUT  /vehicle/v1/components/{id}/data/{param}
GET  /vehicle/v1/components/{id}/faults
DELETE /vehicle/v1/components/{id}/faults
GET  /vehicle/v1/components/{id}/flash/activation
POST /vehicle/v1/components/{id}/flash/commit
POST /vehicle/v1/components/{id}/flash/rollback
```

Parameters can be addressed by name (`fw_version`, `vin`, `active_bank`) or hex DID (`F189`, `F190`, `FD00`). Runtime DIDs are writable via PUT.

The server can be used standalone or proxied through SOVDd via its `sovd-proxy` crate. SOVD Explorer can connect to it directly.

### Standalone usage

```bash
./target/debug/vm-sovd /tmp/vm-mgr-nv.bin
./target/debug/vm-sovd /tmp/vm-mgr-nv.bin 127.0.0.1:9090
```

## Profiles

VM profiles are TOML files in `example/profiles/` that define QEMU parameters (RAM, CPUs, kernel, devices). Two are included:

- `os1-minimal.toml` — minimal QEMU config with network only
- `os1-dev.toml` — full dev config with additional devices

## Key Concepts

- **Three A/B bank sets**: Hypervisor, OS1, OS2 — independent state machines
- **Trial boot**: Up to 10 reboots before auto-rollback to previous bank
- **Copy-on-update**: Runtime DIDs/DTCs cloned to target bank before OTA write
- **Anti-rollback**: `min_security_ver` floor raised on commit, blocks downgrades
- **Backend trait**: `QemuBackend` for dev/test, `QnxBackend` stub for production

## NV Store Layout

```
Boot State     — active bank, committed flag, boot count (per bank set)
Factory        — serial number, VIN, HW numbers (write-once)
FW Meta A/B    — firmware version, SHA-256, security version, UDS SW DIDs
Runtime A/B    — writable DIDs, DTCs (cloned on update)
App            — cert revocation, timestamps, shared config
```

## Diagnostics

The diagserver library implements UDS DID resolution with priority:

1. **Runtime** (writable DIDs, per-bank)
2. **FW Meta** (firmware identity, per-bank)
3. **Factory** (hardware identity, shared)
4. **Dynamic** (computed: active bank, boot count, security versions)

Standard DIDs: F187 (spare part), F188 (ECU SW number), F189 (FW version), F18A–F199.

## Specs

Detailed design documents live in `specs/`:

- `disk-layout.md` — GPT partition table
- `nv-store-format.md` — NV partition internal layout
- `bank-state-machine.md` — Update lifecycle state machine

## Related Projects

- **[SOVDd](https://github.com/sdv-playground/SOVDd)** — SOVD diagnostic server. Translates ASAM SOVD REST API into UDS commands over SocketCAN/DoIP. Multi-ECU gateway, flash/OTA lifecycle, SSE streaming, CLI tool.
- **[SOVD Explorer](https://github.com/sdv-playground/SOVD-explorer)** — Tauri 2 desktop GUI for automotive ECU diagnostics via the SOVD protocol. Parameter read/write, fault display, firmware flashing with two-phase commit, and OIDC-secured security access.

## License

MIT — see `LICENSE` (TODO: add LICENSE file).
