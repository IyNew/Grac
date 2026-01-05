package verify

import (
	"time"

	"github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/recursion/plonk"
	"github.com/grac-enhanced/accumulator/gnark-accumulator/internal/circuit"
	"github.com/grac-enhanced/accumulator/gnark-accumulator/internal/setup"
	"github.com/grac-enhanced/accumulator/gnark-accumulator/pkg/types"
)

// SimpleVerifier handles simplified verification process
type SimpleVerifier struct {
	setup *setup.SimpleSetup
}

// NewSimpleVerifier creates a new simple verifier
func NewSimpleVerifier(setup *setup.SimpleSetup) *SimpleVerifier {
	return &SimpleVerifier{
		setup: setup,
	}
}

// VerifySimpleNonMembership verifies a simplified non-membership proof
func (v *SimpleVerifier) VerifySimpleNonMembership(
	proof *plonk.Proof,
	publicInputs *circuit.SimpleAssignment,
) (bool, error) {
	startTime := time.Now()

	// Create witness from public inputs only (private witness not needed for verification)
	witness := v.createPublicWitness(publicInputs)
	if witness == nil {
		return false, frontend.ErrNoWitnessAssigned
	}

	// Verify proof
	verified, err := plonk.Verify(v.setup.VerifyingKey, witness)
	if err != nil {
		return false, err
	}

	verificationTime := time.Since(startTime)
	fmt.Printf("Proof verification took: %v\n", verificationTime)

	return verified, nil
}

// createPublicWitness creates witness from public inputs only
func (v *SimpleVerifier) createPublicInputsWitness(publicInputs *circuit.SimpleAssignment) (frontend.Witness, error) {
	witness := frontend.NewWitness()

	// Assign only public inputs (private witness not needed for verification)
	if publicInputs.AccumulatorValue != nil {
		witness["accumulator_value"] = publicInputs.AccumulatorValue
	}
	if publicInputs.IntegerCommitment != nil {
		witness["integer_commitment"] = publicInputs.IntegerCommitment
	}
	if publicInputs.PedersenCommitmentX != nil {
		witness["pedersen_commitment_x"] = publicInputs.PedersenCommitmentX
	}
	if publicInputs.PedersenCommitmentY != nil {
		witness["pedersen_commitment_y"] = publicInputs.PedersenCommitmentY
	}

	// Assign proof components
	if publicInputs.CoprimeAlpha1 != nil {
		witness["coprime_alpha1"] = publicInputs.CoprimeAlpha1
	}
	if publicInputs.ModEqAlpha1X != nil {
		witness["modeq_alpha1_x"] = publicInputs.ModEqAlpha1X
	}
	if publicInputs.ModEqAlpha1Y != nil {
		witness["modeq_alpha1_y"] = publicInputs.ModEqAlpha1Y
	}
	if publicInputs.HashToPrimeChallenge != nil {
		witness["hash_to_prime_challenge"] = publicInputs.HashToPrimeChallenge
	}

	return witness, nil
}

// BenchmarkSimpleProofVerification benchmarks simplified proof verification
func (v *SimpleVerifier) BenchmarkSimpleProofVerification(iterations int) (*types.VerificationBenchmarkResult, error) {
	if iterations <= 0 {
		iterations = 1000
	}

	successCount := 0
	totalTime := time.Duration(0)
	minTime := time.Duration(1<<63 - 1) // Max time.Duration
	maxTime := time.Duration(0)

	for i := 0; i < iterations; i++ {
		assignment := circuit.CreateMockAssignment()
		start := time.Now()

		// First generate a proof to verify
		prover := circuit.NewSimpleNonMembershipCircuit()
		witness := circuit.NewSimpleWitness(assignment)

		ccs, err := frontend.Compile(bn254.ID.ScalarField(), prover)
		if err != nil {
			return nil, err
		}

		pk, vk, err := plonk.Setup(ccs)
		if err != nil {
			return nil, err
		}

		proof, err := plonk.Prove(pk, witness)
		if err != nil {
			continue
		}

		verified, err := plonk.Verify(vk, witness)
		if err != nil {
			continue
		}

		duration := time.Since(start)

		if !verified {
			fmt.Printf("Proof verification failed for iteration %d\n", i)
			continue
		}

		successCount++
		totalTime += duration

		if duration < minTime {
			minTime = duration
		}
		if duration > maxTime {
			maxTime = duration
		}

		if i < 5 || i%100 == 0 {
			fmt.Printf("Iteration %d: %v, verified: %t\n", i, duration, verified)
		}
	}

	if successCount == 0 {
		return nil, frontend.ErrNoWitnessAssigned
	}

	averageTime := totalTime / time.Duration(successCount)

	return &types.VerificationBenchmarkResult{
		Iterations:             iterations,
		SuccessfulVerifications: successCount,
		SuccessRate:            float64(successCount) / float64(iterations),
		AverageTimeMs:          float64(averageTime.Nanoseconds()) / 1_000_000.0,
		MinTimeMs:              float64(minTime.Nanoseconds()) / 1_000_000.0,
		MaxTimeMs:              float64(maxTime.Nanoseconds()) / 1_000_000.0,
		TotalTimeMs:            float64(totalTime.Nanoseconds()) / 1_000_000.0,
	}, nil
}

// GetVerificationMetrics returns metrics about the simple verification setup
func (v *SimpleVerifier) GetVerificationMetrics() types.VerificationMetrics {
	return types.VerificationMetrics{
		SecurityLevel:     v.setup.SecurityLevel,
		HashToPrimeBits:   v.setup.HashToPrimeBits,
		FieldSizeBits:     v.setup.FieldSizeBits,
		CurveName:        "bn254",
		Backend:          "plonk",
		VerificationKeySize: v.estimateVerificationKeySize(v.setup.VerifyingKey),
		SetupTime:        v.setup.SetupTime,
		CreatedAt:        v.setup.CreatedAt,
	}
}

// estimateVerificationKeySize estimates the size of verification key in bytes
func (v *SimpleVerifier) estimateVerificationKeySize(vk *plonk.VerifyingKey) int {
	if vk == nil {
		return 0
	}

	// PLONK verification keys are typically several kilobytes
	// This is a rough estimate for BLS12-381
	return 2048 // ~2KB estimate
}