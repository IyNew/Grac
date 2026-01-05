# CPSNARKs Set Bridge - File-Based Communication

This bridge provides file-based communication between Go (gnark) and Rust (cpsnarks-set) implementations.

## Overview

The bridge has been converted from an HTTP API-based system to a file-based communication system. Instead of making HTTP requests, the bridge reads requests from a JSON file and writes responses to another JSON file.

## How It Works

1. **Request File**: `bridge_request.json` - Write your request here
2. **Response File**: `bridge_response.json` - Read the response from here
3. **Lock Files**: `.lock` files prevent concurrent access

## Usage

### Starting the Bridge

```bash
cd accumulator/cpsnarks-set-bridge
cargo run --release
```

The bridge will continuously watch for `bridge_request.json` in the current directory.

### Making Requests

#### Setup Request

Create `bridge_request.json`:

```json
{
  "type": "setup",
  "security_level": 128
}
```

The bridge will process it and write the response to `bridge_response.json`:

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

#### Prove Request

Create `bridge_request.json`:

```json
{
  "type": "prove",
  "security_level": 128,
  "element": "12702637924034044211",
  "randomness": "5"
}
```

The bridge will generate a proof and write it to `bridge_response.json`.

#### Verify Request

Create `bridge_request.json`:

```json
{
  "type": "verify",
  "proof_data": {
    "accumulator_value": "...",
    "integer_commitment": "...",
    "pedersen_commitment": {
      "x": "...",
      "y": "..."
    },
    "coprime_proof": {
      "alpha1": "...",
      "s_e": "...",
      "s_r": "...",
      "challenge": "..."
    },
    "modeq_proof": {
      "alpha1": {"x": "...", "y": "..."},
      "alpha2": {"x": "...", "y": "..."},
      "s_e": "...",
      "s_r": "...",
      "s_r_q": "...",
      "challenge": "..."
    },
    "hash_to_prime_proof": {
      "bit_decomposition": [],
      "challenge": "...",
      "original_element": "...",
      "hashed_prime": "...",
      "range_bits": 0
    }
  }
}
```

## File-Based Protocol

1. Write your request to `bridge_request.json`
2. Wait for the bridge to process (check for `bridge_request.lock` to see if it's processing)
3. Read the response from `bridge_response.json`
4. The request file will be automatically deleted after processing

## Lock Files

- `bridge_request.lock` - Indicates the bridge is processing a request
- `bridge_response.lock` - Indicates the bridge is writing a response

These are automatically created and removed by the bridge.

## Integration with Go

From Go code, you can:

1. Write a JSON request to `bridge_request.json`
2. Poll for `bridge_request.lock` to disappear
3. Read `bridge_response.json` for the result

Example Go code:

```go
import (
    "encoding/json"
    "os"
    "time"
)

func callBridge(request BridgeRequest) (*BridgeResponse, error) {
    // Write request
    reqData, _ := json.Marshal(request)
    os.WriteFile("bridge_request.json", reqData, 0644)
    
    // Wait for processing
    for {
        if _, err := os.Stat("bridge_request.lock"); os.IsNotExist(err) {
            break
        }
        time.Sleep(100 * time.Millisecond)
    }
    
    // Read response
    respData, _ := os.ReadFile("bridge_response.json")
    var response BridgeResponse
    json.Unmarshal(respData, &response)
    return &response, nil
}
```

## Benefits of File-Based Communication

1. **No Network Dependencies**: No need to manage HTTP servers or ports
2. **Simpler Integration**: Just read/write JSON files
3. **Easier Debugging**: Can inspect request/response files directly
4. **Process Isolation**: Bridge runs as a separate process
5. **Cross-Language**: Works with any language that can read/write files



