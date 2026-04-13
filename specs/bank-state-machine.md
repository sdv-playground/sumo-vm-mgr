# Bank State Machine Specification

## Overview

Each A/B bank set (hypervisor, vm1, vm2) has an independent state machine
managing its update lifecycle. The HSM component uses a single bank (no A/B,
no rollback). The state machine ensures atomic updates with automatic rollback
on failure.

## States

```
                    ┌──────────────────────────────┐
                    │         COMMITTED             │
                    │  active_bank = X              │
                    │  committed = true             │
                    │  boot_count = 0               │
                    └──────────┬───────────────────┘
                               │
                         OTA complete
                     (write to inactive bank,
                      copy-on-update runtime,
                      write FW Meta,
                      swap active_bank)
                               │
                               ▼
                    ┌──────────────────────────────┐
                    │           TRIAL               │
              ┌────▶│  active_bank = Y (new)        │◀────┐
              │     │  committed = false            │     │
              │     │  boot_count = N               │     │
              │     └───┬───────────┬──────────┬───┘     │
              │         │           │          │          │
            reboot      │       COMMIT     ROLLBACK      │
         boot_count++   │       command    command        │
              │         │           │          │          │
              │         │           ▼          ▼          │
              │         │    COMMITTED    COMMITTED       │
              │         │    (bank Y)    (bank X, old)    │
              │         │                                 │
              │         │  boot_count > MAX_TRIAL_BOOTS   │
              │         └─────────────────────────────────┘
              │                auto-rollback
              └─── (boot_count <= MAX_TRIAL_BOOTS)
```

## Boot Flow (vm-boot)

On every boot, the boot manager executes:

```
1. Read NV Boot State
2. For each A/B bank set (hypervisor, vm1, vm2):
   a. If committed == true:
      - Boot from active_bank (normal path)
   b. If committed == false (trial mode):
      - Increment boot_count
      - If boot_count > MAX_TRIAL_BOOTS (10):
        - Swap active_bank to other bank
        - Set committed = true, boot_count = 0
        - Log: "auto-rollback after {MAX_TRIAL_BOOTS} trial boots"
      - Else:
        - Write updated boot_count to NV
        - Boot from active_bank (trial continues)
3. Verify image hash (SHA-256 from NV FW Meta) for each active bank
4. If hash verification fails:
   - If trial: immediate rollback (don't count, just swap)
   - If committed: FATAL — both banks may be corrupted
5. Start hypervisor from hypervisor active bank
6. Start VMs from vm1/vm2 active banks
```

## OTA Update Flow (vm-diagserver)

```
1. Receive OTA image for a bank set (e.g., vm1)
2. Preconditions:
   - Current bank set must be COMMITTED (reject if trial)
   - Image security_version >= min_security_ver (anti-rollback)
3. Determine target: inactive bank (active_bank.other())
4. Copy-on-update: clone active Runtime DIDs/DTCs → target Runtime
5. Write image to target partition (vm1-a or vm1-b)
6. Verify written image (read-back SHA-256)
7. Write NV FW Meta for target bank:
   - SW DIDs from image header
   - image_sha256 from verification
   - Preserve min_security_ver from active bank
8. Update NV Boot State:
   - active_bank = target
   - committed = false
   - boot_count = 0
9. Report success — system must reboot to activate

On next boot, bootmgr enters TRIAL state for this bank set.
```

## Commit (from orchestrator or diagnostic command)

```
1. Precondition: bank set is in TRIAL state (committed == false)
2. Set committed = true
3. Set boot_count = 0
4. If fw_secver > min_security_ver:
   - Raise min_security_ver = fw_secver (prevents downgrade)
5. Write NV Boot State + NV FW Meta
```

## Explicit Rollback (from orchestrator or diagnostic command)

```
1. Precondition: bank set is in TRIAL state
2. Swap active_bank to previous bank
3. Set committed = true (rolling back to known-good)
4. Set boot_count = 0
5. Write NV Boot State
```

## Auto-Rollback

Triggered when `boot_count > MAX_TRIAL_BOOTS` (10). This means:
- The system has rebooted 10 times in trial mode
- No orchestrator has sent COMMIT
- Something is likely wrong with the new image

The boot manager automatically:
1. Swaps active_bank back to the previous bank
2. Sets committed = true
3. Resets boot_count = 0
4. Logs the rollback event

### Why 10 boots?

Automotive key-off/key-on cycles are normal during the update window. The
orchestrator may need multiple boot cycles to:
- Verify all services start correctly
- Run integration tests
- Wait for the vehicle to stabilize after key cycles

A threshold of 10 gives ample room for normal operation while still catching
fundamentally broken updates.

## Independence

Each A/B bank set has its own state machine. Updating vm1 does not affect vm2
or the hypervisor. They can be:
- Updated independently
- At different states (one committed, another in trial)
- Committed/rolled back independently

This allows staged rollouts: update vm1, verify, commit, then update vm2.

The HSM component uses a single bank and does not participate in A/B switching
or trial boot. HSM updates are applied directly without rollback support.

## DID Resolution (read path)

When a diagnostic client reads a UDS DID, the diagnostic server resolves it:

```
1. Runtime DIDs (writable, per-bank):
   → Read from active bank's NV Runtime
   → If found, return

2. FW Meta DIDs (SW identity, per-bank):
   → Read from active bank's NV FW Meta
   → F187, F188, F189, F194, F195, F197, F198, F199, F19E

3. Factory DIDs (hardware identity, shared):
   → Read from NV Factory
   → F18A, F18B, F18C, F190, F191, F192, F193

4. Dynamic DIDs (computed):
   → Active bank indicator (A/B)
   → Committed status
   → Boot count
   → Security version info
```

## Anti-Rollback

Each bank's NV FW Meta contains:
- `fw_secver`: the security version of the installed image
- `min_security_ver`: the minimum acceptable security version (floor)

Rules:
- OTA download rejected if image `security_version < min_security_ver`
- On COMMIT: if `fw_secver > min_security_ver`, raise the floor
- The floor is **never lowered** — prevents installing old vulnerable images
- Both banks share the same floor (copied from active to target during OTA)
