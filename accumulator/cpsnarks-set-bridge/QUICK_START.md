# Quick Start: Testing the Bridge

## Quick Test (2 minutes)

### Terminal 1: Start the Bridge
```bash
cd accumulator/cpsnarks-set-bridge
cargo run --release
```

### Terminal 2: Send a Test Request
```bash
cd accumulator/cpsnarks-set-bridge

# Test 1: Setup
echo '{"type":"setup","security_level":128}' > bridge_request.json
sleep 3
cat bridge_response.json

# Test 2: Prove (after setup completes)
echo '{"type":"prove","security_level":128,"element":"12702637924034044211","randomness":"5"}' > bridge_request.json
sleep 10
cat bridge_response.json
```

## What to Expect

1. **Setup Response**: Should contain `setup_data` with cryptographic parameters
2. **Prove Response**: Should contain `proof_data` with a complete proof
3. **Status**: Should be `"success"` for valid requests

## Troubleshooting

- **No response?** Make sure bridge is running in Terminal 1
- **Error status?** Check the `error` field in the response
- **Stuck?** Remove lock files: `rm -f *.lock`

For detailed testing instructions, see [TESTING.md](TESTING.md).



