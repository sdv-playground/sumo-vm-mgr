# Example: SUIT Firmware Envelope

Generate demo artifacts (signing keys + signed SUIT envelope with 1MB dummy firmware):

```bash
cargo run --example build
```

Start the SOVD server with the generated trust anchor:

```bash
cargo run --bin vm-sovd -- /tmp/vm-mgr-nv.bin example/keys/signing.pub
```

Upload, verify, transfer, and commit:

```bash
# Upload SUIT envelope
curl -X POST http://localhost:8080/vehicle/v1/components/os1/files \
  -H 'Content-Type: application/octet-stream' \
  --data-binary @example/output/os1.suit

# Verify
curl -X POST http://localhost:8080/vehicle/v1/components/os1/files/1/verify

# Flash
curl -X POST http://localhost:8080/vehicle/v1/components/os1/flash/transfer \
  -H 'Content-Type: application/json' -d '{"file_id": "1"}'

# Commit
curl -X POST http://localhost:8080/vehicle/v1/components/os1/flash/commit
```
