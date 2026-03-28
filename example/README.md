# Example: SUIT Firmware Envelopes

Generate demo artifacts (signing keys + signed SUIT envelopes with 1MB dummy firmware):

```bash
cargo run --example build
```

This creates:

| File | Component | Sequence | Use case |
|------|-----------|----------|----------|
| `output/os1-v1.suit` | os1 | 1 | Initial flash |
| `output/os1-v2.suit` | os1 | 2 | Upgrade |
| `output/os2-v1.suit` | os2 | 1 | Initial flash |
| `output/os2-v2.suit` | os2 | 2 | Upgrade |

## Quick start

```bash
# Start SOVD server (generates keys on first run):
./scripts/run.sh

# Or fresh start:
./scripts/run.sh --fresh
```

Then open SOVD Explorer and connect to `http://localhost:4000`.

## Simulate upgrade flow

1. Upload `os1-v1.suit` via the Software tab → verify → transfer → commit
2. Upload `os1-v2.suit` → verify → transfer → commit (upgrade)
3. Try uploading `os1-v1.suit` again → should be rejected (anti-rollback)

Same flow works for os2 independently.
