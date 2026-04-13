# Example: SUIT Firmware Envelopes

Generate demo artifacts (signing keys + signed SUIT envelopes with 1MB dummy firmware):

```bash
cargo run --example build
```

This creates:

| File | Component | Sequence | Use case |
|------|-----------|----------|----------|
| `output/vm1-v1.suit` | vm1 | 1 | Initial flash |
| `output/vm1-v2.suit` | vm1 | 2 | Upgrade |
| `output/vm2-v1.suit` | vm2 | 1 | Initial flash |
| `output/vm2-v2.suit` | vm2 | 2 | Upgrade |

## Quick start

```bash
# Start SOVD server (generates keys on first run):
./example/run.sh

# Or fresh start:
./example/run.sh --fresh
```

Then open SOVD Explorer and connect to `http://localhost:4000`.

## Simulate upgrade flow

1. Upload `vm1-v1.suit` via the Software tab → verify → transfer → commit
2. Upload `vm1-v2.suit` → verify → transfer → commit (upgrade)
3. Try uploading `vm1-v1.suit` again → should be rejected (anti-rollback)

Same flow works for vm2 independently.
