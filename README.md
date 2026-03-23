# vm-mgr

Platform-agnostic VM lifecycle manager with automotive diagnostics. Handles A/B bank switching, boot decisions, OTA software updates, and UDS/SOVD diagnostic interface.

Reference implementation — designed to be forked and adapted with proprietary manifests and transport layers.

## Crates

| Crate | Binary | Purpose |
|-------|--------|---------|
| `nv-store` | — | Sector-rotated NV storage with CRC-32 integrity |
| `boot` | `vm-boot` | Boot decisions: trial boot, auto-rollback, image hash verification |
| `boot` | `vm-runner` | Boot loop orchestrator (process_boot → start VM → wait → repeat) |
| `diagserver` | `vm-diagserver` | OTA install/commit/rollback, UDS DID resolution (F187-F199) |

## Quick Start

```bash
cargo build
cargo test   # 77 tests

# Run the boot loop with a VM profile
./scripts/run.sh --profile profiles/os1-minimal.toml --images /path/to/output

# From another terminal, send diag commands
./target/debug/vm-diagserver /tmp/vm-mgr-nv.bin status os1
./target/debug/vm-diagserver /tmp/vm-mgr-nv.bin install os1 image.bin v2.0 1
./target/debug/vm-diagserver /tmp/vm-mgr-nv.bin commit os1
```

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

The diagserver implements UDS DID resolution with priority:

1. **Runtime** (writable DIDs, per-bank)
2. **FW Meta** (firmware identity, per-bank)
3. **Factory** (hardware identity, shared)
4. **Dynamic** (computed: active bank, boot count, security versions)

Standard DIDs: F187 (spare part), F188 (ECU SW number), F189 (FW version), F18A-F199.

## Binary Sizes

Release build, stripped: **~1.8 MB total** (vm-boot 440K + vm-diagserver 431K + vm-runner 958K).

## Related Projects

- **[SOVDd](https://github.com/sdv-playground/SOVDd)** — SOVD diagnostic server. Translates ASAM SOVD REST API into UDS commands over SocketCAN/DoIP. Multi-ECU gateway, flash/OTA lifecycle, SSE streaming, CLI tool.
- **[SOVD Explorer](https://github.com/sdv-playground/SOVD-explorer)** — Tauri 2 desktop GUI for automotive ECU diagnostics via the SOVD protocol. Parameter read/write, fault display, firmware flashing with two-phase commit, and OIDC-secured security access.

## License

MIT
