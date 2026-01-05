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
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"crypto/rand"
	"math/big"

	"github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/backend/groth16"
)

// MinimalCircuit implements the most basic version for testing
type MinimalCircuit struct {
	// Public inputs
	X frontend.Variable `gnark:",public"`
	Y frontend.Variable `gnark:",public"`

	// Private witness
	One frontend.Variable
}

// Define defines the constraints: X + Y = One
func (circuit *MinimalCircuit) Define(api frontend.API) error {
	api.AssertIsEqual(circuit.One, api.Add(circuit.X, circuit.Y))
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

	fmt.Printf("=== Minimal gnark Benchmark ===\n")
	fmt.Printf("Proving Iterations: %d\n", *proveIterations)
	fmt.Printf("Verification Iterations: %d\n", *verifyIterations)
	fmt.Println()

	// Create circuit
	circuit := &MinimalCircuit{}

	// Compile and setup
	fmt.Printf("Setting up circuit...\n")
	start := time.Now()
	ccs, err := frontend.Compile(bn254.ID.ScalarField(), circuit)
	if err != nil {
		log.Fatalf("Failed to compile circuit: %v", err)
	}

	pk, vk, err := groth16.Setup(ccs)
	if err != nil {
		log.Fatalf("Failed to setup keys: %v", err)
	}
	setupTime := time.Since(start)
	fmt.Printf("Setup completed in: %v\n", setupTime)
	fmt.Println()

	// Benchmark proving
	fmt.Printf("Benchmarking proving (%d iterations)...\n", *proveIterations)
	totalProveTime := time.Duration(0)
	minProveTime := time.Duration(1 << 62) // Max time.Duration
	maxProveTime := time.Duration(0)

	for i := 0; i < *proveIterations; i++ {
		// Create witness
		witness := frontend.NewWitness()
		witness["X"], _ = rand.Int(rand.Reader, fr.Modulus())
		witness["Y"], _ = rand.Int(rand.Reader, fr.Modulus())
		witness["One"] = fr.NewElement(1)

		// Generate proof
		proveStart := time.Now()
		_, err := groth16.Prove(circuit, pk, witness)
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

		if *verbose {
			fmt.Printf("Prove iteration %d: %v\n", i, proveTime)
		}
	}

	avgProveTime := totalProveTime / time.Duration(*proveIterations)

	// Benchmark verification
	fmt.Printf("Benchmarking verification (%d iterations)...\n", *verifyIterations)
	totalVerifyTime := time.Duration(0)
	minVerifyTime := time.Duration(1 << 62) // Max time.Duration
	maxVerifyTime := time.Duration(0)
	successCount := 0

	for i := 0; i < *verifyIterations; i++ {
		// Create witness
		witness := frontend.NewWitness()
		witness["X"], _ = rand.Int(rand.Reader, fr.Modulus())
		witness["Y"], _ = rand.Int(rand.Reader, fr.Modulus())
		witness["One"] = fr.NewElement(1)

		// Generate proof to verify
		proof, err := groth16.Prove(circuit, pk, witness)
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
		successCount++
		if verifyTime < minVerifyTime {
			minVerifyTime = verifyTime
		}
		if verifyTime > maxVerifyTime {
			maxVerifyTime = verifyTime
		}

		if *verbose && i < 10 {
			fmt.Printf("Verify iteration %d: %v, verified: %t\n", i, verifyTime, verified)
		}
	}

	avgVerifyTime := totalVerifyTime / time.Duration(successCount)

	// Print results
	fmt.Printf("\n=== Benchmark Results ===\n")
	fmt.Printf("Setup Time: %v\n", setupTime)
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
	fmt.Printf("  Success Rate: %.2f%% (%d/%d)\n", float64(successCount)/float64(*verifyIterations)*100, successCount, *verifyIterations)
	fmt.Println()

	// Save results if requested
	if *outputFile != "" {
		results := map[string]interface{}{
			"setup_time_ms":          float64(setupTime.Nanoseconds()) / 1_000_000.0,
			"proving_iterations":       *proveIterations,
			"proving_avg_ms":         float64(avgProveTime.Nanoseconds()) / 1_000_000.0,
			"proving_min_ms":         float64(minProveTime.Nanoseconds()) / 1_000_000.0,
			"proving_max_ms":         float64(maxProveTime.Nanoseconds()) / 1_000_000.0,
			"proving_success_rate":   float64(successCount) / float64(*proveIterations),
			"verify_iterations":      *verifyIterations,
			"verify_avg_ms":         float64(avgVerifyTime.Nanoseconds()) / 1_000_000.0,
			"verify_min_ms":         float64(minVerifyTime.Nanoseconds()) / 1_000_000.0,
			"verify_max_ms":         float64(maxVerifyTime.Nanoseconds()) / 1_000_000.0,
			"verify_success_rate":   float64(successCount) / float64(*verifyIterations),
			"circuit": map[string]interface{}{
				"name":        "X + Y = One",
				"constraints": 1,
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

	// Generate sample proof for demonstration
	fmt.Printf("Generating sample proof...\n")
	sampleWitness := frontend.NewWitness()
	sampleWitness["X"] = big.NewInt(42)
	sampleWitness["Y"] = big.NewInt(12345)
	sampleWitness["One"] = fr.NewElement(42 + 12345)

	sampleProof, err := groth16.Prove(circuit, pk, sampleWitness)
	if err != nil {
		log.Printf("Failed to generate sample proof: %v", err)
	} else {
		fmt.Printf("Sample proof generated successfully\n")

		// Verify the sample proof
		verified, err := groth16.Verify(sampleProof, vk)
		if err != nil {
			log.Printf("Failed to verify sample proof: %v", err)
		} else if verified {
			fmt.Printf("Sample proof verified successfully - X(42) + Y(12345) = One(16887) ✓\n")
		} else {
			fmt.Printf("Sample proof verification failed\n")
		}
	}
}