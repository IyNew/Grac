# Combined Membership and Non-Membership Circuit

This directory contains a combined circuit implementation that verifies both membership and non-membership proofs in a single circuit.

## Files Created

1. **`internal/circuit/combined.go`** - The combined circuit implementation
2. **`internal/circuit/combined_test.go`** - Test code for the combined circuit
3. **`cmd/bench/combined_bench_test.go`** - Benchmark tests for the combined circuit
4. **`cmd/bench/combined_main.go`** - Main entry point for running benchmarks

## Circuit Structure

The `CombinedCircuit` includes:
- **Membership Circuit**: Verifies that an element is a member of the accumulator
- **Non-Membership Circuit**: Verifies that an element is not a member of the accumulator

Both circuits are verified simultaneously in a single proof.

## Running Tests

### Unit Tests

Run the unit tests to verify the circuit works correctly:

```bash
cd accumulator/gnark-accumulator
go test ./internal/circuit -v -run TestCombinedCircuit
```

Run all combined circuit tests:

```bash
go test ./internal/circuit -v -run TestCombined
```

### Full Test Suite

```bash
go test ./internal/circuit -v
```

## Running Benchmarks

### Using Go's Benchmark Tool

Run all benchmarks:

```bash
cd accumulator/gnark-accumulator
go test ./cmd/bench -bench=BenchmarkCombined -benchmem
```

Run specific benchmarks:

```bash
# Setup benchmark
go test ./cmd/bench -bench=BenchmarkCombinedCircuitSetup -benchmem

# Compile benchmark
go test ./cmd/bench -bench=BenchmarkCombinedCircuitCompile -benchmem

# Prove benchmark
go test ./cmd/bench -bench=BenchmarkCombinedCircuitProve -benchmem

# Verify benchmark
go test ./cmd/bench -bench=BenchmarkCombinedCircuitVerify -benchmem

# Full cycle benchmark
go test ./cmd/bench -bench=BenchmarkCombinedCircuitFullCycle -benchmem
```

### Using the Benchmark Main Program

You can also use the main program to run benchmarks:

```bash
cd accumulator/gnark-accumulator/cmd/bench
go run combined_main.go combined_bench_test.go -iterations=10 -verbose
```

## Benchmark Output

The benchmarks will provide:
- **Setup Time**: Time to generate proving and verification keys
- **Compile Time**: Time to compile the circuit
- **Prove Time**: Time to generate a proof
- **Verify Time**: Time to verify a proof
- **Full Cycle Time**: Combined prove + verify time

## Circuit Parameters

The combined circuit uses the following default parameters:
- **Hash-to-Prime Bits**: 254
- **Field Size Bits**: 255
- **Security Level**: 128 bits
- **Curve**: BN254

## Example Output

```
=== Combined Circuit Benchmark ===

Benchmarking Setup...
Average Setup Time: 2.5s

Benchmarking Prove...
Average Prove Time: 1.2s

Benchmarking Verify...
Average Verify Time: 15ms

=== Summary ===
Setup: 2.5s
Prove: 1.2s
Verify: 15ms
```

## Notes

- The combined circuit verifies both membership and non-membership proofs in a single circuit
- This allows for more efficient batch verification when both types of proofs are needed
- The circuit size is approximately the sum of the individual membership and non-membership circuits
- Proof generation time will be higher than individual circuits due to the increased constraint count


