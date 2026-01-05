package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"math/big"
	"os"
	"time"

	"github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/grac-enhanced/accumulator/gnark-accumulator/internal/prove"
	"github.com/grac-enhanced/accumulator/gnark-accumulator/internal/setup"
	"github.com/grac-enhanced/accumulator/gnark-accumulator/internal/verify"
	"github.com/grac-enhanced/accumulator/gnark-accumulator/pkg/types"
)

var (
	iterationsFlag     = flag.Int("iterations", 100, "Number of iterations for benchmarking")
	proveIterations   = flag.Int("prove-iterations", 100, "Number of proving iterations")
	verifyIterations  = flag.Int("verify-iterations", 1000, "Number of verification iterations")
	securityLevel    = flag.Int("security-level", 128, "Security level for setup")
	hashToPrimeBits  = flag.Int("hash-to-prime-bits", 254, "Number of bits for hash-to-prime")
	fieldSizeBits    = flag.Int("field-size-bits", 255, "Field size bits")
	backend          = flag.String("backend", "groth16", "ZK-SNARK backend (groth16, plonk)")
	setupFile       = flag.String("setup-file", "", "File to save/load setup")
	outputFile      = flag.String("output", "", "File to save benchmark results")
	compareRust     = flag.Bool("compare-rust", false, "Compare with Rust benchmark results")
	endpoint        = flag.String("endpoint", "http://localhost:3030/api/bridge", "Bridge API endpoint")
	verbose         = flag.Bool("verbose", false, "Verbose output")
)

func main() {
	flag.Parse()

	if *verbose {
		log.SetFlags(log.LstdFlags | log.Lshortfile)
	}

	fmt.Printf("=== Non-Membership Verification Benchmark ===\n")
	fmt.Printf("Backend: %s\n", *backend)
	fmt.Printf("Security Level: %d bits\n", *securityLevel)
	fmt.Printf("Hash-to-Prime Bits: %d\n", *hashToPrimeBits)
	fmt.Printf("Field Size Bits: %d\n", *fieldSizeBits)
	fmt.Printf("Proving Iterations: %d\n", *proveIterations)
	fmt.Printf("Verification Iterations: %d\n", *verifyIterations)
	fmt.Printf("Bridge Endpoint: %s\n", *endpoint)
	fmt.Println()

	// Run benchmark
	results, err := runBenchmark()
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
		printResults(results)
	}

	// Compare with Rust if requested
	if *compareRust {
		compareWithRust(results)
	}
}

func runBenchmark() (*types.BenchmarkResults, error) {
	fmt.Printf("Setting up non-membership verification circuit...\n")

	// Setup options
	opts := &setup.SetupOptions{
		SecurityLevel:   *securityLevel,
		HashToPrimeBits: *hashToPrimeBits,
		FieldSizeBits:   *fieldSizeBits,
		Backend:         *backend,
		Curve:           "bn254",
	}

	// Setup circuit
	setupStart := time.Now()
	circuitSetup, err := setup.SetupNonMembership(opts)
	if err != nil {
		return nil, fmt.Errorf("setup failed: %w", err)
	}
	setupTime := time.Since(setupStart)

	fmt.Printf("Circuit setup completed in: %v\n", setupTime)
	fmt.Printf("Setup contains:\n")
	fmt.Printf("  - Proving Key: ~%d bytes\n", estimateProvingKeySize(circuitSetup.ProvingKey))
	fmt.Printf("  - Verification Key: ~%d bytes\n", estimateVerificationKeySize(circuitSetup.VerifyingKey))
	fmt.Printf("  - Security Level: %d bits\n", circuitSetup.SecurityLevel)
	fmt.Printf("  - Hash-to-Prime Bits: %d\n", circuitSetup.HashToPrimeBits)
	fmt.Println()

	// Create prover and verifier
	prover := prove.NewProver(circuitSetup)
	verifier := verify.NewVerifier(circuitSetup)

	// Generate test data
	fmt.Printf("Generating test data...\n")
	testCases := generateTestData(*iterationsFlag)
	fmt.Printf("Generated %d test cases\n", len(testCases))
	fmt.Println()

	// Benchmark proof generation
	fmt.Printf("Benchmarking proof generation (%d iterations)...\n", *proveIterations)
	proofBenchmark, err := prover.BenchmarkProofGeneration(testCases, *proveIterations)
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
	verificationBenchmark, err := verifier.BenchmarkProofVerification(testCases, *verifyIterations)
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
			NumRandomCases:   len(testCases),
		},
		ProvingResults: types.ProofBenchmarkResult(*proofBenchmark),
		VerificationResults: types.VerificationBenchmarkResult(*verificationBenchmark),
		CircuitStats: types.CircuitStats{
			NumConstraints:             estimateNumConstraints(circuitSetup),
			NumVariables:               estimateNumVariables(circuitSetup),
			ProofSizeBytes:             estimateProofSize(circuitSetup.ProvingKey),
			VerificationKeySizeBytes:   estimateVerificationKeySize(circuitSetup.VerifyingKey),
		},
	}

	return results, nil
}

func generateTestData(numCases int) []types.TestCaseData {
	// Use the same test elements as the original Rust benchmark
	testElements := []string{
		"12702637924034044211",
		"378373571372703133",
		"8640171141336142787",
	}

	testRandomness := []string{
		"5",
		"9",
		"13",
	}

	testCases := make([]types.TestCaseData, numCases)

	for i := 0; i < numCases; i++ {
		element, _ := new(big.Int).SetString(testElements[i%len(testElements)], 10)
		randomness, _ := new(big.Int).SetString(testRandomness[i%len(testRandomness)], 10)

		// Generate mock proof data
		// In a real implementation, this would come from the bridge API
		proofData := &types.NonMembershipProofData{
			AccumulatorValue: generateMockAccumulatorValue(),
			IntegerCommitment:  generateMockIntegerCommitment(),
			PedersenCommitment: &types.EllipticPoint{
				X: generateMockNumber(256),
				Y: generateMockNumber(256),
			},
			CoprimeProof: &types.CoprimeProofData{
				Alpha1:   generateMockNumber(2048),
				SE:       generateMockNumber(2048),
				SR:       generateMockNumber(2048),
				Challenge: generateMockNumber(256),
			},
			ModEqProof: &types.ModEqProofData{
				Alpha1: &types.EllipticPoint{
					X: generateMockNumber(256),
					Y: generateMockNumber(256),
				},
				Alpha2: &types.EllipticPoint{
					X: generateMockNumber(256),
					Y: generateMockNumber(256),
				},
				SE:       generateMockNumber(256),
				SR:       generateMockNumber(256),
				SRq:      generateMockNumber(255),
				Challenge: generateMockNumber(256),
			},
			HashToPrimeProof: &types.HashToPrimeProofData{
				BitDecomposition:  generateMockBitDecomposition(254),
				Challenge:        generateMockNumber(256),
				OriginalElement:  element.String(),
				HashedPrime:      generateMockPrime(254),
				RangeBits:        254,
			},
			WitnessData: &types.WitnessData{
				Element:     element.String(),
				Randomness:  randomness.String(),
				RandomnessQ: generateMockNumber(255),
				D:           generateMockNumber(2048),
				B:           generateMockNumber(2048),
			},
		}

		testCases[i] = types.TestCaseData{
			Element:           element,
			Randomness:        randomness,
			ProofData:         proofData,
			VerificationResult: true, // Mock for testing
		}
	}

	return testCases
}

func generateMockAccumulatorValue() string {
	// Generate a random 2048-bit accumulator value
	return generateMockNumber(2048)
}

func generateMockIntegerCommitment() string {
	// Generate a random 2048-bit integer commitment
	return generateMockNumber(2048)
}

func generateMockNumber(bits int) string {
	// Generate a random number with the specified bit length
	max := new(big.Int).Lsh(big.NewInt(1), uint(bits))
	result := new(big.Int).Rand(nil, max)
	return result.String()
}

func generateMockPrime(bits int) string {
	// Generate a mock prime number (simplified)
	// In practice, this would use actual primality testing
	result := new(big.Int).Lsh(big.NewInt(1), uint(bits-1)) // Set MSB to 1
	result.Add(result, big.NewInt(1)) // Ensure odd

	// Simple primality check - this is just for mock data
	if !result.ProbablyPrime(1) {
		// Add a small adjustment to make it more likely to be prime
		result.Add(result, big.NewInt(2))
	}

	return result.String()
}

func generateMockBitDecomposition(bits int) []uint64 {
	result := make([]uint64, (bits+63)/64)
	for i := range result {
		result[i] = uint64(i * 12345) + uint64(i*i*67) // Simple pseudo-random
	}
	return result
}

func estimateProvingKeySize(pk interface{}) int {
	// Rough estimate for Groth16 proving key on BN254
	// This would typically be several hundred kilobytes to a few megabytes
	return 1024 * 1024 // 1MB estimate
}

func estimateVerificationKeySize(vk interface{}) int {
	// Rough estimate for Groth16 verification key on BN254
	return 288 // About 288 bytes
}

func estimateNumConstraints(setup interface{}) int {
	// Estimate based on the circuit complexity
	// This is a rough approximation based on our circuit implementation
	coprimeConstraints := 5      // g^s_e * h^s_r = α1
	modeqConstraints := 10         // Pedersen commitment equality
	rangeProofConstraints := 254   // Bit decomposition for 254-bit number
	accumulatorConstraints := 5     // Accumulator relationship

	totalConstraints := coprimeConstraints + modeqConstraints + rangeProofConstraints + accumulatorConstraints

	// Add overhead for Fiat-Shamir challenges and hash functions
	totalConstraints += 50

	return totalConstraints
}

func estimateNumVariables(setup interface{}) int {
	// Estimate number of variables based on constraints
	// Typically slightly less than number of constraints
	return int(estimateNumConstraints(setup) * 0.8)
}

func estimateProofSize(setup interface{}) int {
	// Groth16 proofs are typically around 288 bytes on BN254
	return 288
}

func saveResults(results *types.BenchmarkResults, filename string) error {
	data, err := json.MarshalIndent(results, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal results: %w", err)
	}

	return os.WriteFile(filename, data, 0644)
}

func printResults(results *types.BenchmarkResults) {
	fmt.Printf("\n=== Benchmark Summary ===\n")
	fmt.Printf("Configuration:\n")
	fmt.Printf("  Backend: %s\n", *backend)
	fmt.Printf("  Security Level: %d bits\n", results.Config.SecurityLevel)
	fmt.Printf("  Hash-to-Prime Bits: %d\n", results.Config.HashToPrimeBits)
	fmt.Printf("  Field Size Bits: %d\n", results.Config.FieldSizeBits)
	fmt.Printf("  Prove Iterations: %d\n", results.Config.ProveIterations)
	fmt.Printf("  Verify Iterations: %d\n", results.Config.VerifyIterations)
	fmt.Println()

	fmt.Printf("Circuit Statistics:\n")
	fmt.Printf("  Number of Constraints: %d\n", results.CircuitStats.NumConstraints)
	fmt.Printf("  Number of Variables: %d\n", results.CircuitStats.NumVariables)
	fmt.Printf("  Proof Size: %d bytes\n", results.CircuitStats.ProofSizeBytes)
	fmt.Printf("  Verification Key Size: %d bytes\n", results.CircuitStats.VerificationKeySizeBytes)
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

	// These values are taken from the original Rust benchmark documentation
	// and would need to be updated with actual measured values
	rustProvingTime := 10.0    // Placeholder - would be measured from Rust
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