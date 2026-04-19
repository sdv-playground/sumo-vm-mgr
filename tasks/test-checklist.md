# Test checklist — run before pushing

Quick steps come first; expensive ones last. Stop at the first failure
and fix it before continuing — later steps assume earlier ones pass.

Current baseline (PR 3f + abort_install + wrapper-http tests):
- 108 hypervisor-mgr tests
- 11 machine-mgr tests
- vm-sovd binary builds clean in release

## 1. Format check on changed files (~1 sec)

```bash
rustfmt --edition 2021 --check \
  crates/machine-mgr/src/*.rs \
  crates/hypervisor-mgr/src/{component_adapter,component_adapter_tests,diag_backend,diag_backend_tests,wrapper_http_tests,sovd_main}.rs
```

Pre-existing format diffs in unrelated files (`boot/src/config.rs`,
`example/build_hsm_keys.rs`, …) make `cargo fmt --all -- --check` noisy.
Scope to what we own.

To fix: re-run without `--check`.

## 2. Workspace build (~5 sec warm)

```bash
cargo build --workspace
```

Catches missing-import / borrow-checker regressions across all crates.

## 3. Workspace tests (~10 sec warm)

```bash
cargo test --workspace
```

Watch the hypervisor-mgr count: should be **≥ 108**. If it drops, a test
got accidentally cfg'd out or removed.

## 4. Clippy spot-check on changed crates (~30 sec warm)

```bash
cargo clippy -p hypervisor-mgr -p machine-mgr --tests --no-deps 2>&1 \
  | grep -E "src/(diag_backend|component_adapter|sovd_main|wrapper_http_tests|machine|types|component|error)\.rs"
```

We don't gate on `-D warnings` — the existing codebase has unrelated
clippy noise that would dominate. Just eyeball for **new** warnings in the
files we own. Acceptable existing patterns: `field_reassign_with_default`
in test setup (matches existing tests.rs style); `needless_update` on
`..ComponentConfig::default()` in the components table.

## 5. Release binary smoke (~5 sec warm)

```bash
cargo build --release -p hypervisor-mgr
ls -la target/release/vm-sovd target/release/vm-diagserver
```

Confirms the production binaries link with all wiring in place. Release
mode catches some issues debug doesn't.

## 6. Wrapper-level HTTP smoke (~1 sec — included in step 3)

`wrapper_http_tests.rs` exercises SOVD HTTP through `ComponentDiagBackend`
(the wiring `vm-sovd` actually uses), not raw `VmBackend` like
`sovd_tests.rs`. **Add a test here whenever a wrapper bug is found that
unit tests didn't catch** — the wrapper layer is where translation
mismatches live.

Run alone:

```bash
cargo test -p hypervisor-mgr wrapper_http
```

## 7. Sibling-repo build (skip — siblings consume binaries, not Cargo deps)

`grep -rl "hypervisor-mgr\|machine-mgr"` across `cvc-vm-linux`,
`cvc-vm-qnx`, `qemu-qnx-host` shows only `qemu-qnx-host/scripts/build.sh`
references our crate names. No sibling imports our types via Cargo, so
cross-repo `cargo check` adds no signal. Re-evaluate if a sibling starts
depending on `machine-mgr` directly.

## 8. End-to-end OTA (manual, before any release)

```bash
cd ~/dev/sumo-workspace/examples/campaign
./start-ecus.sh --fresh   # terminal A
./run-campaigns.sh        # terminal B
```

Heavyweight: needs vcan kernel modules, ivshmem-server, built guest
images. Catches issues that wrapper_http tests can't (real OTA flow,
encrypted firmware, multi-component campaigns).

For QNX host equivalent (when functional):

```bash
cd ~/dev/sumo-workspace/examples/qnx-host
./start-host.sh --fresh
```
