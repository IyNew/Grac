package verify

import (
	"encoding/json"
	"fmt"
	"math/big"
	"time"

	"github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/grac-enhanced/accumulator/gnark-accumulator/internal/circuit"
	"github.com/grac-enhanced/accumulator/gnark-accumulator/internal/setup"
	"github.com/grac-enhanced/accumulator/gnark-accumulator/pkg/types"
)

// Verifier handles the verification process for non-membership verification
type Verifier struct {
	setup *setup.Setup
}

// NewVerifier creates a new verifier with the given setup
func NewVerifier(setup *setup.Setup) *Verifier {
	return &Verifier{
		setup: setup,
	}
}

// VerifyNonMembership verifies a non-membership proof
func (v *Verifier) VerifyNonMembership(
	proof *groth16.Proof,
	publicInputs *types.NonMembershipProofData,
) (bool, error) {
	startTime := time.Now()

	// Convert public inputs to witness
	witness, err := v.convertPublicInputsToWitness(publicInputs)
	if err != nil {
		return false, fmt.Errorf("failed to convert public inputs: %w", err)
	}

	// Verify the proof
	verified, err := groth16.Verify(proof, v.setup.VerifyingKey, witness)
	if err != nil {
		return false, fmt.Errorf("proof verification failed: %w", err)
	}

	verificationTime := time.Since(startTime)
	fmt.Printf("Proof verification took: %v\n", verificationTime)

	return verified, nil
}

// VerifyFromBridgeData verifies a proof from bridge API response
func (v *Verifier) VerifyFromBridgeData(bridgeData *types.BridgeResponse) (bool, error) {
	if bridgeData.Status != "success" {
		return false, fmt.Errorf("bridge operation failed: %s", bridgeData.Error)
	}

	// For now, we'll assume bridge verification is correct
	// In a full implementation, this would parse the proof and verify with gnark
	if bridgeData.VerificationResult != nil {
		return *bridgeData.VerificationResult, nil
	}

	return false, errors.New("no verification result in bridge response")
}

// convertPublicInputsToWitness converts public inputs to gnark witness
func (v *Verifier) convertPublicInputsToWitness(publicInputs *types.NonMembershipProofData) (frontend.Witness, error) {
	// Parse big integers from strings
	accumulatorValue, ok := new(big.Int).SetString(publicInputs.AccumulatorValue, 10)
	if !ok {
		return nil, fmt.Errorf("invalid accumulator value: %s", publicInputs.AccumulatorValue)
	}

	integerCommitment, ok := new(big.Int).SetString(publicInputs.IntegerCommitment, 10)
	if !ok {
		return nil, fmt.Errorf("invalid integer commitment: %s", publicInputs.IntegerCommitment)
	}

	coprimeAlpha1, ok := new(big.Int).SetString(publicInputs.CoprimeProof.Alpha1, 10)
	if !ok {
		return nil, fmt.Errorf("invalid coprime alpha1: %s", publicInputs.CoprimeProof.Alpha1)
	}

	// Parse elliptic curve points
	pedersenCommitment, err := parseEllipticPoint(publicInputs.PedersenCommitment)
	if err != nil {
		return nil, fmt.Errorf("invalid pedersen commitment: %w", err)
	}

	modeqAlpha1, err := parseEllipticPoint(publicInputs.ModEqProof.Alpha1)
	if err != nil {
		return nil, fmt.Errorf("invalid modeq alpha1: %w", err)
	}

	modeqAlpha2, err := parseEllipticPoint(publicInputs.ModEqProof.Alpha2)
	if err != nil {
		return nil, fmt.Errorf("invalid modeq alpha2: %w", err)
	}

	// Parse hash-to-prime values
	hashToPrimeChallenge, ok := new(big.Int).SetString(publicInputs.HashToPrimeProof.Challenge, 10)
	if !ok {
		return nil, fmt.Errorf("invalid hash_to_prime challenge: %s", publicInputs.HashToPrimeProof.Challenge)
	}

	originalElement, ok := new(big.Int).SetString(publicInputs.HashToPrimeProof.OriginalElement, 10)
	if !ok {
		return nil, fmt.Errorf("invalid original element: %s", publicInputs.HashToPrimeProof.OriginalElement)
	}

	hashedPrime, ok := new(big.Int).SetString(publicInputs.HashToPrimeProof.HashedPrime, 10)
	if !ok {
		return nil, fmt.Errorf("invalid hashed prime: %s", publicInputs.HashToPrimeProof.HashedPrime)
	}

	// Create witness with public inputs only
	witness := frontend.NewWitness()

	// Assign public inputs
	witness["accumulator_value"] = accumulatorValue
	witness["integer_commitment"] = integerCommitment
	witness["pedersen_commitment_x"] = pedersenCommitment.X
	witness["pedersen_commitment_y"] = pedersenCommitment.Y

	witness["coprime_alpha1"] = coprimeAlpha1
	witness["modeq_alpha1_x"] = modeqAlpha1.X
	witness["modeq_alpha1_y"] = modeqAlpha1.Y
	witness["modeq_alpha2_x"] = modeqAlpha2.X
	witness["modeq_alpha2_y"] = modeqAlpha2.Y

	witness["hash_to_prime_challenge"] = hashToPrimeChallenge
	witness["original_element"] = originalElement
	witness["hashed_prime"] = hashedPrime

	return witness, nil
}

// parseEllipticPoint parses an elliptic point from strings
func parseEllipticPoint(point *types.EllipticPoint) (*bn254.G1Affine, error) {
	if point == nil {
		return nil, fmt.Errorf("elliptic point is nil")
	}

	x, ok := new(big.Int).SetString(point.X, 10)
	if !ok {
		return nil, fmt.Errorf("invalid x coordinate: %s", point.X)
	}

	y, ok := new(big.Int).SetString(point.Y, 10)
	if !ok {
		return nil, fmt.Errorf("invalid y coordinate: %s", point.Y)
	}

	// Create affine point
	g1Affine := new(bn254.G1Affine)
	if err := g1Affine.SetBig(x, y); err != nil {
		return nil, fmt.Errorf("failed to set G1 point: %w", err)
	}

	return g1Affine, nil
}

// BenchmarkProofVerification benchmarks proof verification performance
func (v *Verifier) BenchmarkProofVerification(
	testCases []types.TestCaseData,
	iterations int,
) (*types.VerificationBenchmarkResult, error) {
	if len(testCases) == 0 {
		return nil, errors.New("no test cases provided")
	}

	successCount := 0
	totalTime := time.Duration(0)
	minTime := time.Duration(1<<63 - 1) // Max time.Duration
	maxTime := time.Duration(0)

	for i := 0; i < iterations; i++ {
		testCase := testCases[i%len(testCases)]
		start := time.Now()

		// For benchmarking, we need to create a proof first
		// In practice, proofs would come from the prover
		proof, err := v.createMockProof(testCase)
		if err != nil {
			fmt.Printf("Failed to create mock proof for iteration %d: %v\n", i, err)
			continue
		}

		verified, err := v.VerifyNonMembership(proof, testCase.ProofData)
		duration := time.Since(start)

		if err != nil {
			fmt.Printf("Proof verification failed for iteration %d: %v\n", i, err)
			continue
		}

		if !verified {
			fmt.Printf("Proof verification returned false for iteration %d\n", i)
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

		fmt.Printf("Iteration %d: %v, verified: %t\n", i, duration, verified)
	}

	if successCount == 0 {
		return nil, errors.New("all proof verification attempts failed")
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

// createMockProof creates a mock proof for benchmarking
func (v *Verifier) createMockProof(testCase types.TestCaseData) (*groth16.Proof, error) {
	// In a real implementation, this would use actual proof data
	// For benchmarking purposes, we'll create a valid-looking mock proof

	proof := new(groth16.Proof)

	// Generate random valid-looking proof points
	// This is a simplified approach - real proofs would have specific structure
	if err := proof.A.SetRandom(); err != nil {
		return nil, fmt.Errorf("failed to generate proof A: %w", err)
	}

	if err := proof.B.SetRandom(); err != nil {
		return nil, fmt.Errorf("failed to generate proof B: %w", err)
	}

	if err := proof.C.SetRandom(); err != nil {
		return nil, fmt.Errorf("failed to generate proof C: %w", err)
	}

	return proof, nil
}

// VerificationBenchmarkResult contains verification benchmark results
type VerificationBenchmarkResult struct {
	Iterations             int     `json:"iterations"`
	SuccessfulVerifications int     `json:"successful_verifications"`
	SuccessRate            float64 `json:"success_rate"`
	AverageTimeMs          float64 `json:"average_time_ms"`
	MinTimeMs              float64 `json:"min_time_ms"`
	MaxTimeMs              float64 `json:"max_time_ms"`
	TotalTimeMs            float64 `json:"total_time_ms"`
}

// BatchVerification allows verification of multiple proofs in batch
func (v *Verifier) BatchVerification(
	proofs []*groth16.Proof,
	publicInputs []*types.NonMembershipProofData,
) ([]bool, error) {
	if len(proofs) != len(publicInputs) {
		return nil, errors.New("number of proofs must match number of public inputs")
	}

	results := make([]bool, len(proofs))

	for i, proof := range proofs {
		verified, err := v.VerifyNonMembership(proof, publicInputs[i])
		if err != nil {
			results[i] = false
			fmt.Printf("Batch verification failed for proof %d: %v\n", i, err)
		} else {
			results[i] = verified
		}
	}

	return results, nil
}

// AggregateVerificationStats aggregates verification statistics
func (v *Verifier) AggregateVerificationStats(results []bool) types.AggregatedStats {
	total := len(results)
	successes := 0

	for _, result := range results {
		if result {
			successes++
		}
	}

	return types.AggregatedStats{
		TotalProofs:     total,
		SuccessfulProofs: successes,
		FailedProofs:     total - successes,
		SuccessRate:      float64(successes) / float64(total),
	}
}

// GetVerificationMetrics returns metrics about the verification setup
func (v *Verifier) GetVerificationMetrics() types.VerificationMetrics {
	return types.VerificationMetrics{
		SecurityLevel:     v.setup.SecurityLevel,
		HashToPrimeBits:   v.setup.HashToPrimeBits,
		FieldSizeBits:     v.setup.FieldSizeBits,
		CurveName:        "bn254",
		Backend:          "groth16",
		VerificationKeySize: estimateVerificationKeySize(v.setup.VerifyingKey),
		SetupTime:        v.setup.SetupTime,
		CreatedAt:        v.setup.CreatedAt,
	}
}

// estimateVerificationKeySize estimates the size of verification key in bytes
func estimateVerificationKeySize(vk *groth16.VerifyingKey) int {
	if vk == nil {
		return 0
	}

	// Rough estimate for Groth16 verification key on BN254
	// This includes G1 points and G2 points
	return 48*2 + 96*2 // ~288 bytes for alpha, beta, gamma, delta
}