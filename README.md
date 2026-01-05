# Gr2AC zkSNARK Implementation

This project implements the zkSNARK component of the Gr2AC (Group-based Anonymous Credential) system, enabling anonymous authentication through zero-knowledge proofs. The system proves possession of attributes without revealing user identity by converting cryptographic operations into zkSNARK proofs using Groth16.

## Overview

The Gr2AC zkSNARK system provides:
- **Zero-Knowledge Authentication**: Prove attribute possession without revealing identity
- **Efficient Verification**: Constant-time verification suitable for high-throughput scenarios
- **Cryptographic Security**: Built on proven zkSNARK technology with Groth16
- **Modular Design**: Clean separation between cryptographic operations and business logic
- **Multi-Language Support**: Go (Gnark) and Rust (Arkworks) implementations with file-based bridge

## Architecture

### Core Components

1. **ZK Circuits** (`circuits/`): Circuits implementing the `Reach()` algorithm constraints
2. **Cryptographic Primitives** (`crypto/`): ZK-friendly hash functions and symmetric encryption
3. **Proof System** (`zk/`): Groth16 proving/verifying system setup and operations
4. **Integration Layer** (`integration/`): Service interface for external applications
5. **Accumulator Implementations** (`accumulator/`): PoC accumulator proofs

```

## Quick Start

### Prerequisites

- Go 1.23 or higher
- Rust 1.70 or higher (for cpsnarks-set-bridge)
- Git

### Installation

1. Clone the repository:
```bash
git clone <repository-url>
cd grac-enhanced
```

2. Install dependencies:
```bash
make deps
```

### Build and Test

```bash
# Build the entire project
make build

# Run tests
make test

# Run benchmarks
make bench

# Run the demo application
make demo

# Clean build artifacts
make clean
```

## Accumulator Components

### gnark-accumulator (Go)

The Go implementation provides accumulator circuits for membership and non-membership proofs:

```bash
cd accumulator/gnark-accumulator

# Run circuit tests
go test ./internal/circuit -v

# Run benchmarks
go test ./cmd/bench -bench=. -benchmem

# Run combined circuit tests
go test ./internal/circuit -run TestCombined
```

**Features:**
- Membership proof verification
- Non-membership proof verification
- Combined circuit supporting both proof types
- Batch processing support

### cpsnarks-set-bridge (Rust)

The bridge provides file-based communication between Go (Gnark) and Rust (Arkworks) implementations:

```bash
cd accumulator/cpsnarks-set-bridge

# Build and start the bridge server
cargo run --release

# Quick test (see QUICK_START.md)
echo '{"type":"setup","security_level":128}' > bridge_request.json
```

**File-Based Protocol:**
- Write requests to `bridge_request.json`
- Read responses from `bridge_response.json`
- Lock files prevent concurrent access

## Basic Usage

### Core Credential Service

```go
package main

import (
    "context"
    "fmt"
    "github.com/research/gr2ac-poc/integration"
)

func main() {
    ctx := context.Background()

    // Create credential service
    service, err := integration.NewCredentialService()
    if err != nil {
        panic(err)
    }

    // Generate proof
    accumulatorState := "acc_state_123"
    attributeID := "student@university.edu"
    witnessData := map[string]interface{}{
        "secretKey":         "your_secret_key",
        "index":             "12345",
        "controlP":          "computed_control_p",
        "controlNext":       "computed_control_next",
        "membershipWitness": "membership_witness_data",
    }

    proof, err := service.GenerateCredential(ctx, accumulatorState, attributeID, witnessData)
    if err != nil {
        panic(err)
    }

    // Verify proof
    valid, err := service.VerifyCredential(ctx, proof, accumulatorState, attributeID)
    if err != nil {
        panic(err)
    }

    fmt.Printf("Proof valid: %v\n", valid)
}
```

## Core Concepts

### Basic Credential Circuit

The core circuit proves the relation:
```
(accCT, TAttID) | H(sk|idx) = CT.P; Enc(sk, AttID) = CT.Next; H(CT) in accCT
```

Where:
- `accCT` is the accumulator state of control transactions
- `TAttID` is the target attribute ID
- `sk` is the user's secret key
- `idx` is an index value
- `CT` is the control transaction
- `H(CT) in accCT` proves membership in the accumulator

### Public Inputs
- `AccumulatorState`: The current state of the control transaction accumulator
- `AttributeID`: The attribute being claimed

### Private Inputs (Witness)
- `SecretKey`: User's secret key
- `Index`: Index value for the credential
- `ControlP`: Control transaction P value
- `ControlNext`: Control transaction Next value
- `MembershipWitness`: Proof of membership in accumulator


## References

- [Groth16: On the Size of Pairing-based Non-interactive Arguments](https://eprint.iacr.org/2016/260)
- [MiMC: Efficient and Provably Secure Hash Function](https://eprint.iacr.org/2016/492)
- [zkSNARKs: Zero-Knowledge Succinct Non-Interactive Arguments of Knowledge](https://github.com/zcash/zcash/issues/2230)
- [Gnark: Fast, Generic, and Modular zkSNARK Frameworks](https://github.com/Consensys/gnark)
- [Arkworks: Rust libraries for zkSNARK programming](https://github.com/arkworks-rs)