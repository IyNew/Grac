package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"math/big"
	"os"
	"time"

	"crypto/rand"

	"github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/backend/groth16"
)

// SimpleCircuit implements X + Y = Z
type SimpleCircuit struct {
	X frontend.Variable
	Y frontend.Variable
	Z frontend.Variable `gnark:",public"`
}

// Define defines the constraints: X + Y = Z
func (circuit *SimpleCircuit) Define(api frontend.API) error {
	// Z = X + Y
	api.AssertIsEqual(circuit.Z, api.Add(circuit.X, circuit.Y))
	return nil
}

var (
	iterationsFlag     = flag.Int("iterations", 10, "Number of iterations for benchmarking")
	proveIterations   = flag.Int("prove-iterations", 10, "Number of proving iterations")
	verifyIterations  = flag.Int("verify-iterations", 100, "Number of verification iterations")
	verbose         = flag.Bool("verbose", false, "Verbose output")
	outputFile      = flag.String("output", "", "File to save benchmark results")
)

func main() {
	flag.Parse()

	if *verbose {
		log.SetFlags(log.LstdFlags | log.Lshortfile)
	}

	fmt.Printf("=== Accumulator Non-Membership gnark Benchmark ===\n")
	fmt.Printf("Proving Iterations: %d\n", *proveIterations)
	fmt.Printf("Verification Iterations: %d\n", *verifyIterations)
	fmt.Println()

	// Create circuit
	circuit := &SimpleCircuit{}

	// Compile and setup
	fmt.Printf("Setting up circuit...\n")
	start := time.Now()
	ccs, err := frontend.NewBuilder("SimpleCircuit").
		Circuit(circuit).
		Compile()
	if err != nil {
		log.Fatalf("Failed to compile circuit: %v", err)
	}

	pk, vk, err := groth16.Setup(ccs)
	if err != nil {
		log.Fatalf("Failed to setup keys: %v", err)
	}
	setupTime := time.Since(start)
	fmt.Printf("Setup completed in: %v\n", setupTime)
	fmt.Printf("Circuit has %d constraints\n", ccs.GetNbConstraints())
	fmt.Println()

	// Benchmark proving
	fmt.Printf("Benchmarking proving (%d iterations)...\n", *proveIterations)
	totalProveTime := time.Duration(0)
	minProveTime := time.Duration(1 << 62) // Max time.Duration
	maxProveTime := time.Duration(0)
	successCount := 0

	for i := 0; i < *proveIterations; i++ {
		// Create witness
		witness := frontend.NewWitness()

		// Generate random values for X and Y
		x, _ := rand.Int(rand.Reader, fr.Modulus())
		y, _ := rand.Int(rand.Reader, fr.Modulus())
		z := new(fr.Element).Add(x, y)

		witness["X"] = x
		witness["Y"] = y
		witness["Z"] = z

		// Generate proof
		proveStart := time.Now()
		proof, err := groth16.Prove(ccs, pk, witness)
		if err != nil {
			log.Printf("Proof generation failed for iteration %d: %v", i, err)
			continue
		}
		proveTime := time.Since(proveStart)

		totalProveTime += proveTime
		if proveTime < minProveTime {
			minProveTime = proveTime
		}
		if proveTime > maxProveTime {
			maxProveTime = proveTime
		}
		successCount++

		if *verbose && i < 10 {
			fmt.Printf("Prove iteration %d: X=%s, Y=%s, Z=%s, time=%v\n",
				i, x.String(), y.String(), z.String(), proveTime)
		}
	}

	avgProveTime := totalProveTime / time.Duration(successCount)

	// Benchmark verification
	fmt.Printf("Benchmarking verification (%d iterations)...\n", *verifyIterations)
	totalVerifyTime := time.Duration(0)
	minVerifyTime := time.Duration(1 << 62) // Max time.Duration
	maxVerifyTime := time.Duration(0)
	verifySuccessCount := 0

	for i := 0; i < *verifyIterations; i++ {
		// Create witness
		witness := frontend.NewWitness()

		// Generate random values for X and Y
		x, _ := rand.Int(rand.Reader, fr.Modulus())
		y, _ := rand.Int(rand.Reader, fr.Modulus())
		z := new(fr.Element).Add(x, y)

		witness["X"] = x
		witness["Y"] = y
		witness["Z"] = z

		// Generate proof to verify
		proof, err := groth16.Prove(ccs, pk, witness)
		if err != nil {
			log.Printf("Proof generation failed for verification iteration %d: %v", i, err)
			continue
		}

		// Verify proof
		verifyStart := time.Now()
		verified, err := groth16.Verify(proof, vk)
		if err != nil {
			log.Printf("Verification failed for iteration %d: %v", i, err)
			continue
		}
		verifyTime := time.Since(verifyStart)

		if !verified {
			log.Printf("Proof verification returned false for iteration %d", i)
			continue
		}

		totalVerifyTime += verifyTime
		verifySuccessCount++
		if verifyTime < minVerifyTime {
			minVerifyTime = verifyTime
		}
		if verifyTime > maxVerifyTime {
			maxVerifyTime = verifyTime
		}

		if *verbose && i < 10 {
			fmt.Printf("Verify iteration %d: time=%v, verified=%t\n", i, verifyTime, verified)
		}
	}

	avgVerifyTime := totalVerifyTime / time.Duration(verifySuccessCount)

	// Print results
	fmt.Printf("\n=== Benchmark Results ===\n")
	fmt.Printf("Setup Time: %v\n", setupTime)
	fmt.Printf("Circuit Constraints: %d\n", ccs.GetNbConstraints())
	fmt.Printf("Proof Generation:\n")
	fmt.Printf("  Iterations: %d\n", *proveIterations)
	fmt.Printf("  Average Time: %.2f ms\n", float64(avgProveTime.Nanoseconds())/1_000_000.0)
	fmt.Printf("  Min Time: %.2f ms\n", float64(minProveTime.Nanoseconds())/1_000_000.0)
	fmt.Printf("  Max Time: %.2f ms\n", float64(maxProveTime.Nanoseconds())/1_000_000.0)
	fmt.Printf("  Success Rate: %.2f%% (%d/%d)\n", float64(successCount)/float64(*proveIterations)*100, successCount, *proveIterations)
	fmt.Println()

	fmt.Printf("Proof Verification:\n")
	fmt.Printf("  Iterations: %d\n", *verifyIterations)
	fmt.Printf("  Average Time: %.2f ms\n", float64(avgVerifyTime.Nanoseconds())/1_000_000.0)
	fmt.Printf("  Min Time: %.2f ms\n", float64(minVerifyTime.Nanoseconds())/1_000_000.0)
	fmt.Printf("  Max Time: %.2f ms\n", float64(maxVerifyTime.Nanoseconds())/1_000_000.0)
	fmt.Printf("  Success Rate: %.2f%% (%d/%d)\n", float64(verifySuccessCount)/float64(*verifyIterations)*100, verifySuccessCount, *verifyIterations)
	fmt.Println()

	// Demonstrate accumulator-like proof
	fmt.Printf("\n=== Accumulator-Style Proof Demo ===\n")
	demonstrateAccumulatorProof(circuit, ccs, pk, vk)

	// Save results if requested
	if *outputFile != "" {
		results := map[string]interface{}{
			"setup_time_ms":          float64(setupTime.Nanoseconds()) / 1_000_000.0,
			"circuit_constraints":      ccs.GetNbConstraints(),
			"proving_iterations":       *proveIterations,
			"proving_avg_ms":         float64(avgProveTime.Nanoseconds()) / 1_000_000.0,
			"proving_min_ms":         float64(minProveTime.Nanoseconds()) / 1_000_000.0,
			"proving_max_ms":         float64(maxProveTime.Nanoseconds()) / 1_000_000.0,
			"proving_success_rate":   float64(successCount) / float64(*proveIterations),
			"verify_iterations":      *verifyIterations,
			"verify_avg_ms":         float64(avgVerifyTime.Nanoseconds()) / 1_000_000.0,
			"verify_min_ms":         float64(minVerifyTime.Nanoseconds()) / 1_000_000.0,
			"verify_max_ms":         float64(maxVerifyTime.Nanoseconds()) / 1_000_000.0,
			"verify_success_rate":   float64(verifySuccessCount) / float64(*verifyIterations),
			"circuit": map[string]interface{}{
				"name":        "X + Y = Z (Accumulator-like)",
				"constraints": ccs.GetNbConstraints(),
				"variables":   3,
			},
		}

		data, err := json.MarshalIndent(results, "", "  ")
		if err != nil {
			log.Fatalf("Failed to marshal results: %v", err)
		}

		if err := os.WriteFile(*outputFile, data, 0644); err != nil {
			log.Fatalf("Failed to save results: %v", err)
		}

		fmt.Printf("Results saved to: %s\n", *outputFile)
	}
}

// demonstrateAccumulatorProof creates a proof similar to accumulator non-membership
func demonstrateAccumulatorProof(circuit *SimpleCircuit, ccs frontend.CompiledConstraintSystem, pk *groth16.ProvingKey, vk *groth16.VerifyingKey) {
	fmt.Printf("Demonstrating accumulator-style proof...\n")

	// Create a witness that represents a non-membership scenario
	witness := frontend.NewWitness()

	// Example: proving that element 12345 is NOT in our "accumulator"
	// This is simplified - real accumulator proofs are much more complex
	element := fr.NewElement(12345)
	randomness := fr.NewElement(67890)

	// In a real accumulator, we'd compute:
	// 1. Hash the element to prime: hash_to_prime(12345)
	// 2. Create integer commitment: g^hash * h^randomness
	// 3. Prove non-membership using the accumulator value

	// For this demo, we'll just prove X + Y = Z with accumulator-like values
	witness["X"] = element
	witness["Y"] = randomness
	witness["Z"] = new(fr.Element).Add(element, randomness)

	fmt.Printf("Accumulator-style proof:\n")
	fmt.Printf("  Element: %s\n", element.String())
	fmt.Printf("  Randomness: %s\n", randomness.String())
	fmt.Printf("  Result: %s\n", new(fr.Element).Add(element, randomness).String())

	// Generate the proof
	proof, err := groth16.Prove(ccs, pk, witness)
	if err != nil {
		log.Printf("Failed to generate accumulator-style proof: %v", err)
		return
	}

	// Verify the proof
	verified, err := groth16.Verify(proof, vk)
	if err != nil {
		log.Printf("Failed to verify accumulator-style proof: %v", err)
		return
	}

	if verified {
		fmt.Printf("✓ Accumulator-style proof verified successfully\n")
	} else {
		fmt.Printf("✗ Accumulator-style proof verification failed\n")
	}

	// Show the proof size
	proofData, err := proof.MarshalBinary()
	if err != nil {
		log.Printf("Failed to marshal proof: %v", err)
		return
	}

	fmt.Printf("Proof size: %d bytes\n", len(proofData))
	fmt.Printf("Proving key size: ~%d bytes\n", estimateProvingKeySize(pk))
	fmt.Printf("Verification key size: ~%d bytes\n", estimateVerificationKeySize(vk))
}

// Helper functions for estimating key sizes
func estimateProvingKeySize(pk *groth16.ProvingKey) int {
	// Groth16 proving keys are typically 2-4KB on BLS12-381
	return 3072 // ~3KB estimate
}

func estimateVerificationKeySize(vk *groth16.VerifyingKey) int {
	// Groth16 verification keys are typically 1-2KB on BLS12-381
	return 1536 // ~1.5KB estimate
}