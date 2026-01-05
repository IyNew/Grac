# Testing the File-Based Bridge

This document explains how to test the file-based bridge.

## Prerequisites

- Rust toolchain installed
- `jq` (optional, for pretty JSON output): `brew install jq` or `apt-get install jq`

## Method 1: Manual Testing

### Step 1: Start the Bridge

In one terminal, start the bridge:

```bash
cd accumulator/cpsnarks-set-bridge
cargo run --release
```

You should see:
```
Starting cpsnarks-set file-based bridge
Watching for requests in: bridge_request.json
Writing responses to: bridge_response.json
Press Ctrl+C to stop
```

### Step 2: Test Setup Request

In another terminal, create a setup request:

```bash
cd accumulator/cpsnarks-set-bridge
cat > bridge_request.json << 'EOF'
{
  "type": "setup",
  "security_level": 128
}
EOF
```

The bridge will process it and create `bridge_response.json`. Check the response:

```bash
cat bridge_response.json | jq '.'  # or just: cat bridge_response.json
```

Expected response:
```json
{
  "status": "success",
  "setup_data": {
    "security_level": 128,
    "hash_to_prime_bits": 254,
    "field_size_bits": 255,
    "integer_commitment_g": "...",
    "integer_commitment_h": "...",
    "pedersen_commitment_g": {
      "x": "...",
      "y": "..."
    },
    "pedersen_commitment_h": {
      "x": "...",
      "y": "..."
    }
  }
}
```

### Step 3: Test Prove Request

Create a prove request:

```bash
cat > bridge_request.json << 'EOF'
{
  "type": "prove",
  "security_level": 128,
  "element": "12702637924034044211",
  "randomness": "5"
}
EOF
```

Wait a few seconds, then check the response:

```bash
cat bridge_response.json | jq '.'
```

Expected response:
```json
{
  "status": "success",
  "proof_data": {
    "accumulator_value": "...",
    "integer_commitment": "...",
    "pedersen_commitment": {
      "x": "...",
      "y": "..."
    },
    "coprime_proof": { ... },
    "modeq_proof": { ... },
    "hash_to_prime_proof": { ... }
  },
  "proving_time_ms": 1234
}
```

## Method 2: Using the Test Script

A test script is provided for automated testing:

```bash
cd accumulator/cpsnarks-set-bridge
chmod +x test_bridge.sh
./test_bridge.sh
```

**Note**: The script requires you to start the bridge manually in another terminal first.

## Method 3: Integration Test from Go

You can test the bridge from Go code. Here's an example:

```go
package main

import (
    "encoding/json"
    "fmt"
    "os"
    "time"
)

type BridgeRequest struct {
    Type          string `json:"type"`
    SecurityLevel  uint16 `json:"security_level,omitempty"`
    Element        string `json:"element,omitempty"`
    Randomness     string `json:"randomness,omitempty"`
}

type BridgeResponse struct {
    Status    string      `json:"status"`
    Error     *string     `json:"error,omitempty"`
    SetupData interface{} `json:"setup_data,omitempty"`
    ProofData interface{} `json:"proof_data,omitempty"`
}

func callBridge(request BridgeRequest) (*BridgeResponse, error) {
    // Write request
    reqData, err := json.Marshal(request)
    if err != nil {
        return nil, err
    }
    
    if err := os.WriteFile("bridge_request.json", reqData, 0644); err != nil {
        return nil, err
    }
    
    // Wait for processing (check for lock file disappearance)
    maxWait := 30 * time.Second
    start := time.Now()
    for time.Since(start) < maxWait {
        if _, err := os.Stat("bridge_request.lock"); os.IsNotExist(err) {
            // Lock file gone, check for response
            if _, err := os.Stat("bridge_response.json"); err == nil {
                break
            }
        }
        time.Sleep(100 * time.Millisecond)
    }
    
    // Read response
    respData, err := os.ReadFile("bridge_response.json")
    if err != nil {
        return nil, err
    }
    
    var response BridgeResponse
    if err := json.Unmarshal(respData, &response); err != nil {
        return nil, err
    }
    
    return &response, nil
}

func main() {
    // Test setup
    setupReq := BridgeRequest{
        Type:         "setup",
        SecurityLevel: 128,
    }
    
    resp, err := callBridge(setupReq)
    if err != nil {
        fmt.Printf("Error: %v\n", err)
        return
    }
    
    fmt.Printf("Status: %s\n", resp.Status)
    if resp.Error != nil {
        fmt.Printf("Error: %s\n", *resp.Error)
    }
}
```

## Troubleshooting

### Bridge not processing requests

1. Check that the bridge is running: `ps aux | grep cpsnarks-set-bridge`
2. Check that `bridge_request.json` exists and is valid JSON
3. Check for lock files - if they exist, the bridge might be stuck
4. Check bridge logs for errors

### Response file not created

1. Ensure the bridge is running
2. Check that the request file is valid JSON
3. Look for error messages in the bridge output
4. Verify file permissions

### Lock files not being removed

If lock files persist, manually remove them:
```bash
rm -f bridge_request.lock bridge_response.lock
```

## Expected Behavior

1. **Request Processing**: Bridge should process requests within 1-2 seconds for setup, 5-30 seconds for prove
2. **File Cleanup**: Request file should be deleted after processing
3. **Lock Files**: Lock files should be created and removed automatically
4. **Response Format**: Responses should be valid JSON with a `status` field

## Performance Benchmarks

Typical processing times:
- **Setup**: 1-5 seconds
- **Prove**: 5-30 seconds (depends on security level and element size)
- **Verify**: 1-5 seconds

These times are included in the response as `proving_time_ms` or `verification_time_ms`.



