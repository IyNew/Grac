package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"math/big"
	"os"
	"time"

	"github.com/grac-enhanced/accumulator/gnark-accumulator/internal/circuit"
	"github.com/grac-enhanced/accumulator/gnark-accumulator/internal/prove"
	"github.com/grac-enhanced/accumulator/gnark-accumulator/internal/setup"
	"github.com/grac-enhanced/accumulator/gnark-accumulator/internal/verify"
	"github.com/grac-enhanced/accumulator/gnark-accumulator/pkg/types"
)

var (
	iterationsFlag     = flag.Int("iterations", 100, "Number of iterations for benchmarking")
	proveIterations   = flag.Int("prove-iterations", 50, "Number of proving iterations")
	verifyIterations  = flag.Int("verify-iterations", 500, "Number of verification iterations")
	securityLevel    = flag.Int("security-level", 128, "Security level for setup")
	hashToPrimeBits  = flag.Int("hash-to-prime-bits", 254, "Number of bits for hash-to-prime")
	fieldSizeBits    = flag.Int("field-size-bits", 255, "Field size bits")
	backend          = flag.String("backend", "plonk", "ZK-SNARK backend (plonk, groth16)")
	setupFile       = flag.String("setup-file", "", "File to save/load setup")
	outputFile      = flag.String("output", "", "File to save benchmark results")
	compareRust     = flag.Bool("compare-rust", false, "Compare with Rust benchmark results")
	verbose         = flag.Bool("verbose", false, "Verbose output")
	simple          = flag.Bool("simple", true, "Use simplified implementation")
)

func main() {
	flag.Parse()

	if *verbose {
		log.SetFlags(log.LstdFlags | log.Lshortfile)
	}

	fmt.Printf("=== Simple Non-Membership Verification Benchmark ===\n")
	fmt.Printf("Backend: %s\n", *backend)
	fmt.Printf("Security Level: %d bits\n", *securityLevel)
	fmt.Printf("Hash-to-Prime Bits: %d\n", *hashToPrimeBits)
	fmt.Printf("Field Size Bits: %d\n", *fieldSizeBits)
	fmt.Printf("Proving Iterations: %d\n", *proveIterations)
	fmt.Printf("Verification Iterations: %d\n", *verifyIterations)
	fmt.Printf("Simple Implementation: %t\n", *simple)
	fmt.Println()

	// Run benchmark
	results, err := runSimpleBenchmark()
	if err != nil {
		log.Fatalf("Benchmark failed: %v", err)
	}

	// Output results
	if *outputFile != "" {
		if err := saveResults(results, *outputFile); err != nil {
			log.Fatalf("Failed to save results: %v", err)
		}
		fmt.Printf("Results saved to: %s\n", *outputFile)
	} else {
		printSimpleResults(results)
	}

	// Compare with Rust if requested
	if *compareRust {
		compareWithRust(results)
	}
}

func runSimpleBenchmark() (*types.BenchmarkResults, error) {
	fmt.Printf("Setting up simple non-membership verification circuit...\n")

	// Setup circuit
	setupStart := time.Now()
	simpleSetup, err := setup.SetupSimpleCircuit()
	if err != nil {
		return nil, fmt.Errorf("setup failed: %w", err)
	}
	setupTime := time.Since(setupStart)

	fmt.Printf("Circuit setup completed in: %v\n", setupTime)
	fmt.Printf("Setup contains:\n")
	fmt.Printf("  - Security Level: %d bits\n", simpleSetup.SecurityLevel)
	fmt.Printf("  - Hash-to-Prime Bits: %d\n", simpleSetup.HashToPrimeBits)
	fmt.Printf("  - Field Size Bits: %d\n", simpleSetup.FieldSizeBits)
	fmt.Println()

	// Create prover and verifier
	prover := prove.NewSimpleProver(simpleSetup)
	verifier := verify.NewSimpleVerifier(simpleSetup)

	// Generate test data
	fmt.Printf("Generating test data...\n")
	testAssignments := generateTestAssignments(*proveIterations)
	fmt.Printf("Generated %d test assignments\n", len(testAssignments))
	fmt.Println()

	// Benchmark proof generation
	fmt.Printf("Benchmarking proof generation (%d iterations)...\n", *proveIterations)
	proofBenchmark, err := prover.BenchmarkSimpleProofGeneration(*proveIterations)
	if err != nil {
		return nil, fmt.Errorf("proof benchmark failed: %w", err)
	}

	fmt.Printf("Proof Generation Results:\n")
	fmt.Printf("  - Success Rate: %.2f%% (%d/%d)\n",
		proofBenchmark.SuccessRate*100,
		proofBenchmark.SuccessfulProofs,
		proofBenchmark.Iterations)
	fmt.Printf("  - Average Time: %.2f ms\n", proofBenchmark.AverageTimeMs)
	fmt.Printf("  - Min Time: %.2f ms\n", proofBenchmark.MinTimeMs)
	fmt.Printf("  - Max Time: %.2f ms\n", proofBenchmark.MaxTimeMs)
	fmt.Printf("  - Total Time: %.2f ms\n", proofBenchmark.TotalTimeMs)
	fmt.Printf("  - Average Proof Size: %d bytes\n", proofBenchmark.AverageProofSize)
	fmt.Println()

	// Benchmark proof verification
	fmt.Printf("Benchmarking proof verification (%d iterations)...\n", *verifyIterations)
	verificationBenchmark, err := verifier.BenchmarkSimpleProofVerification(*verifyIterations)
	if err != nil {
		return nil, fmt.Errorf("verification benchmark failed: %w", err)
	}

	fmt.Printf("Proof Verification Results:\n")
	fmt.Printf("  - Success Rate: %.2f%% (%d/%d)\n",
		verificationBenchmark.SuccessRate*100,
		verificationBenchmark.SuccessfulVerifications,
		verificationBenchmark.Iterations)
	fmt.Printf("  - Average Time: %.2f ms\n", verificationBenchmark.AverageTimeMs)
	fmt.Printf("  - Min Time: %.2f ms\n", verificationBenchmark.MinTimeMs)
	fmt.Printf("  - Max Time: %.2f ms\n", verificationBenchmark.MaxTimeMs)
	fmt.Printf("  - Total Time: %.2f ms\n", verificationBenchmark.TotalTimeMs)
	fmt.Println()

	// Create benchmark results
	results := &types.BenchmarkResults{
		Config: types.BenchmarkConfig{
			ProveIterations:  *proveIterations,
			VerifyIterations: *verifyIterations,
			SecurityLevel:    *securityLevel,
			HashToPrimeBits:  *hashToPrimeBits,
			FieldSizeBits:    *fieldSizeBits,
			GenerateRandom:   false,
			NumRandomCases:   len(testAssignments),
			Simple:          *simple,
		},
		ProvingResults:     *proofBenchmark,
		VerificationResults: *verificationBenchmark,
		CircuitStats:      circuit.GetCircuitStats(),
		SetupTime:         setupTime,
		CreatedAt:         simpleSetup.CreatedAt,
	}

	return results, nil
}

func generateTestAssignments(numCases int) []*circuit.SimpleAssignment {
	assignments := make([]*circuit.SimpleAssignment, numCases)

	for i := 0; i < numCases; i++ {
		assignment := circuit.CreateMockAssignment()
		assignments[i] = assignment

		if *verbose && i < 5 {
			fmt.Printf("Test assignment %d:\n", i)
			fmt.Printf("  Element: %s\n", assignment.Element.String())
			fmt.Printf("  Randomness: %s\n", assignment.Randomness.String())
			fmt.Printf("  Coprime Alpha1: %s\n", assignment.CoprimeAlpha1.String())
		}
	}

	return assignments
}

func saveResults(results *types.BenchmarkResults, filename string) error {
	data, err := json.MarshalIndent(results, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal results: %w", err)
	}

	return os.WriteFile(filename, data, 0644)
}

func printSimpleResults(results *types.BenchmarkResults) {
	fmt.Printf("\n=== Simple Benchmark Summary ===\n")
	fmt.Printf("Configuration:\n")
	fmt.Printf("  Backend: %s\n", results.Config.Backend)
	fmt.Printf("  Security Level: %d bits\n", results.Config.SecurityLevel)
	fmt.Printf("  Hash-to-Prime Bits: %d\n", results.Config.HashToPrimeBits)
	fmt.Printf("  Field Size Bits: %d\n", results.Config.FieldSizeBits)
	fmt.Printf("  Prove Iterations: %d\n", results.Config.ProveIterations)
	fmt.Printf("  Verify Iterations: %d\n", results.Config.VerifyIterations)
	fmt.Printf("  Simple Implementation: %t\n", results.Config.Simple)
	fmt.Println()

	fmt.Printf("Circuit Statistics:\n")
	fmt.Printf("  Number of Constraints: %d\n", results.CircuitStats.NumConstraints)
	fmt.Printf("  Number of Variables: %d\n", results.CircuitStats.NumVariables)
	fmt.Printf("  Proof Size: %d bytes\n", results.CircuitStats.ProofSizeBytes)
	fmt.Printf("  Verification Key Size: %d bytes\n", results.CircuitStats.VerificationKeySizeBytes)
	fmt.Printf("  Setup Time: %v\n", results.SetupTime)
	fmt.Println()

	fmt.Printf("Performance Results:\n")
	fmt.Printf("  Proof Generation:\n")
	fmt.Printf("    Average: %.2f ms\n", results.ProvingResults.AverageTimeMs)
	fmt.Printf("    Min: %.2f ms\n", results.ProvingResults.MinTimeMs)
	fmt.Printf("    Max: %.2f ms\n", results.ProvingResults.MaxTimeMs)
	fmt.Printf("    Success Rate: %.2f%%\n", results.ProvingResults.SuccessRate*100)
	fmt.Println()

	fmt.Printf("  Proof Verification:\n")
	fmt.Printf("    Average: %.2f ms\n", results.VerificationResults.AverageTimeMs)
	fmt.Printf("    Min: %.2f ms\n", results.VerificationResults.MinTimeMs)
	fmt.Printf("    Max: %.2f ms\n", results.VerificationResults.MaxTimeMs)
	fmt.Printf("    Success Rate: %.2f%%\n", results.VerificationResults.SuccessRate*100)
	fmt.Println()
}

func compareWithRust(results *types.BenchmarkResults) {
	fmt.Printf("=== Comparison with Rust Implementation ===\n")

	// These values are taken from the original Rust benchmark
	// and would need to be updated with actual measured values
	rustProvingTime := 10.0   // Placeholder - would be measured from Rust
	rustVerificationTime := 2.0 // Placeholder - would be measured from Rust

	goProvingSpeedup := rustProvingTime / results.ProvingResults.AverageTimeMs
	goVerificationSpeedup := rustVerificationTime / results.VerificationResults.AverageTimeMs

	fmt.Printf("Rust Implementation (Estimated):\n")
	fmt.Printf("  Proof Generation: %.2f ms\n", rustProvingTime)
	fmt.Printf("  Verification: %.2f ms\n", rustVerificationTime)
	fmt.Println()

	fmt.Printf("Go Implementation:\n")
	fmt.Printf("  Proof Generation: %.2f ms\n", results.ProvingResults.AverageTimeMs)
	fmt.Printf("  Verification: %.2f ms\n", results.VerificationResults.AverageTimeMs)
	fmt.Println()

	fmt.Printf("Performance Comparison:\n")
	fmt.Printf("  Proving Speedup: %.2fx %s\n",
		goProvingSpeedup,
		speedupDescription(goProvingSpeedup))
	fmt.Printf("  Verification Speedup: %.2fx %s\n",
		goVerificationSpeedup,
		speedupDescription(goVerificationSpeedup))
	fmt.Println()
}

func speedupDescription(speedup float64) string {
	if speedup > 1.5 {
		return "Go is significantly faster"
	} else if speedup > 1.1 {
		return "Go is moderately faster"
	} else if speedup > 0.9 {
		return "Comparable performance"
	} else if speedup > 0.7 {
		return "Go is moderately slower"
	} else {
		return "Go is significantly slower"
	}
}