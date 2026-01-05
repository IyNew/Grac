package prove

import (
	"crypto/rand"
	"math/big"
	"time"

	"github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/recursion/plonk"
	"github.com/grac-enhanced/accumulator/gnark-accumulator/internal/circuit"
	"github.com/grac-enhanced/accumulator/gnark-accumulator/internal/setup"
	"github.com/grac-enhanced/accumulator/gnark-accumulator/pkg/types"
)

// SimpleProver handles simplified proving process
type SimpleProver struct {
	setup *setup.SimpleSetup
}

// NewSimpleProver creates a new simple prover
func NewSimpleProver(setup *setup.SimpleSetup) *SimpleProver {
	return &SimpleProver{
		setup: setup,
	}
}

// ProveSimpleNonMembership generates a simplified zero-knowledge proof
func (p *SimpleProver) ProveSimpleNonMembership(assignment *circuit.SimpleAssignment) (*plonk.Proof, error) {
	startTime := time.Now()

	// Create witness
	witness := circuit.NewSimpleWitness(assignment)
	if witness == nil {
		return nil, frontend.ErrNoWitnessAssigned
	}

	// Generate proof
	proof, err := plonk.Prove(p.setup.ProvingKey, witness)
	if err != nil {
		return nil, err
	}

	proofTime := time.Since(startTime)
	return proof, nil
}

// CreateMockAssignment creates test assignment for benchmarking
func CreateMockAssignment() *circuit.SimpleAssignment {
	// Generate mock data similar to Rust benchmark
	element, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 254))
	randomness, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 255))

	// Generate mock public inputs
	accumulatorValue, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 2048))
	integerCommitment, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 2048))
	pedersenCommitmentX, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 255))
	pedersenCommitmentY, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 255))

	// Generate mock proof components
	coprimeAlpha1, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 2048))
	modeqAlpha1X, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 255))
	modeqAlpha1Y, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 255))
	hashToPrimeChallenge, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 256))

	// Generate mock witness values
	coprimeSE, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 254))
	coprimeSR, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 2048))
	modeqSE, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 254))
	modeqSR, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 255))

	return &circuit.SimpleAssignment{
		// Public inputs
		AccumulatorValue:  accumulatorValue,
		IntegerCommitment:  integerCommitment,
		PedersenCommitmentX: pedersenCommitmentX,
		PedersenCommitmentY: pedersenCommitmentY,

		// Proof components
		CoprimeAlpha1:      coprimeAlpha1,
		ModEqAlpha1X:       modeqAlpha1X,
		ModEqAlpha1Y:       modeqAlpha1Y,
		HashToPrimeChallenge: hashToPrimeChallenge,

		// Private witness
		Element:      element,
		Randomness:   randomness,
		CoprimeSE:    coprimeSE,
		CoprimeSR:    coprimeSR,
		ModEqSE:      modeqSE,
		ModEqSR:      modeqSR,
	}
}

// BenchmarkSimpleProofGeneration benchmarks simplified proof generation
func (p *SimpleProver) BenchmarkSimpleProofGeneration(iterations int) (*types.ProofBenchmarkResult, error) {
	if iterations <= 0 {
		iterations = 100
	}

	successCount := 0
	totalTime := time.Duration(0)
	minTime := time.Duration(1<<63 - 1) // Max time.Duration
	maxTime := time.Duration(0)
	proofSizes := make([]int, 0, iterations)

	for i := 0; i < iterations; i++ {
		assignment := CreateMockAssignment()
		start := time.Now()

		proof, err := p.ProveSimpleNonMembership(assignment)
		if err != nil {
			continue
		}
		duration := time.Since(start)

		successCount++
		totalTime += duration

		if duration < minTime {
			minTime = duration
		}
		if duration > maxTime {
			maxTime = duration
		}

		// Estimate proof size
		proofSize := p.estimateProofSize(proof)
		proofSizes = append(proofSizes, proofSize)

		if i < 5 || i%20 == 0 {
			fmt.Printf("Iteration %d: %v, proof size: %d bytes\n", i, duration, proofSize)
		}
	}

	if successCount == 0 {
		return nil, frontend.ErrNoWitnessAssigned
	}

	averageTime := totalTime / time.Duration(successCount)

	// Calculate statistics
	avgProofSize := 0
	if len(proofSizes) > 0 {
		for _, size := range proofSizes {
			avgProofSize += size
		}
		avgProofSize /= len(proofSizes)
	}

	return &types.ProofBenchmarkResult{
		Iterations:       iterations,
		SuccessfulProofs: successCount,
		SuccessRate:      float64(successCount) / float64(iterations),
		AverageTimeMs:    float64(averageTime.Nanoseconds()) / 1_000_000.0,
		MinTimeMs:        float64(minTime.Nanoseconds()) / 1_000_000.0,
		MaxTimeMs:        float64(maxTime.Nanoseconds()) / 1_000_000.0,
		TotalTimeMs:      float64(totalTime.Nanoseconds()) / 1_000_000.0,
		AverageProofSize: avgProofSize,
	}, nil
}

// estimateProofSize estimates the size of a PLONK proof
func (p *SimpleProver) estimateProofSize(proof *plonk.Proof) int {
	if proof == nil {
		return 0
	}

	// PLONK proofs are typically around 1-2KB on BLS12-381
	// This is a rough estimate
	return 1500 // 1.5KB estimate
}