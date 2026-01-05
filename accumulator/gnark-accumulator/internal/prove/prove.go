package prove

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
	"math/big"
	"time"

	"github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/bits"
	"github.com/grac-enhanced/accumulator/gnark-accumulator/internal/circuit"
	"github.com/grac-enhanced/accumulator/gnark-accumulator/internal/setup"
	"github.com/grac-enhanced/accumulator/gnark-accumulator/pkg/types"
)

// Prover handles the proving process for non-membership verification
type Prover struct {
	setup *setup.Setup
}

// NewProver creates a new prover with the given setup
func NewProver(setup *setup.Setup) *Prover {
	return &Prover{
		setup: setup,
	}
}

// ProveNonMembership generates a zero-knowledge proof for non-membership verification
func (p *Prover) ProveNonMembership(proofData *types.NonMembershipProofData) (*groth16.Proof, error) {
	startTime := time.Now()

	// Convert proof data to circuit assignment
	assignment, err := p.convertToCircuitAssignment(proofData)
	if err != nil {
		return nil, fmt.Errorf("failed to convert proof data: %w", err)
	}

	// Create witness
	witness, err := circuit.NewWitness(
		circuit.NewNonMembershipCircuit(
			p.setup.HashToPrimeBits,
			p.setup.FieldSizeBits,
			p.setup.IntegerCommitmentG,
			p.setup.IntegerCommitmentH,
			p.setup.PedersenCommitmentG,
			p.setup.PedersenCommitmentH,
		),
		assignment,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create witness: %w", err)
	}

	// Generate proof
	proof, err := groth16.Prove(p.setup.ProvingKey, witness)
	if err != nil {
		return nil, fmt.Errorf("failed to generate proof: %w", err)
	}

	proofTime := time.Since(startTime)
	fmt.Printf("Proof generation took: %v\n", proofTime)

	return proof, nil
}

// convertToCircuitAssignment converts proof data to circuit assignment
func (p *Prover) convertToCircuitAssignment(proofData *types.NonMembershipProofData) (*circuit.CircuitAssignment, error) {
	// Parse big integers from strings
	accumulatorValue, ok := new(big.Int).SetString(proofData.AccumulatorValue, 10)
	if !ok {
		return nil, fmt.Errorf("invalid accumulator value: %s", proofData.AccumulatorValue)
	}

	integerCommitment, ok := new(big.Int).SetString(proofData.IntegerCommitment, 10)
	if !ok {
		return nil, fmt.Errorf("invalid integer commitment: %s", proofData.IntegerCommitment)
	}

	coprimeAlpha1, ok := new(big.Int).SetString(proofData.CoprimeProof.Alpha1, 10)
	if !ok {
		return nil, fmt.Errorf("invalid coprime alpha1: %s", proofData.CoprimeProof.Alpha1)
	}

	// Parse elliptic curve points
	pedersenCommitment, err := parseEllipticPoint(proofData.PedersenCommitment)
	if err != nil {
		return nil, fmt.Errorf("invalid pedersen commitment: %w", err)
	}

	modeqAlpha1, err := parseEllipticPoint(proofData.ModEqProof.Alpha1)
	if err != nil {
		return nil, fmt.Errorf("invalid modeq alpha1: %w", err)
	}

	modeqAlpha2, err := parseEllipticPoint(proofData.ModEqProof.Alpha2)
	if err != nil {
		return nil, fmt.Errorf("invalid modeq alpha2: %w", err)
	}

	// Parse witness values
	element, ok := new(big.Int).SetString(proofData.WitnessData.Element, 10)
	if !ok {
		return nil, fmt.Errorf("invalid element: %s", proofData.WitnessData.Element)
	}

	randomness, ok := new(big.Int).SetString(proofData.WitnessData.Randomness, 10)
	if !ok {
		return nil, fmt.Errorf("invalid randomness: %s", proofData.WitnessData.Randomness)
	}

	randomnessQ, ok := new(big.Int).SetString(proofData.WitnessData.RandomnessQ, 10)
	if !ok {
		return nil, fmt.Errorf("invalid randomness_q: %s", proofData.WitnessData.RandomnessQ)
	}

	// Parse proof response values
	coprimeSE, ok := new(big.Int).SetString(proofData.CoprimeProof.SE, 10)
	if !ok {
		return nil, fmt.Errorf("invalid coprime s_e: %s", proofData.CoprimeProof.SE)
	}

	coprimeSR, ok := new(big.Int).SetString(proofData.CoprimeProof.SR, 10)
	if !ok {
		return nil, fmt.Errorf("invalid coprime s_r: %s", proofData.CoprimeProof.SR)
	}

	coprimeChallenge, ok := new(big.Int).SetString(proofData.CoprimeProof.Challenge, 10)
	if !ok {
		return nil, fmt.Errorf("invalid coprime challenge: %s", proofData.CoprimeProof.Challenge)
	}

	modeqSE, ok := new(big.Int).SetString(proofData.ModEqProof.SE, 10)
	if !ok {
		return nil, fmt.Errorf("invalid modeq s_e: %s", proofData.ModEqProof.SE)
	}

	modeqSR, ok := new(big.Int).SetString(proofData.ModEqProof.SR, 10)
	if !ok {
		return nil, fmt.Errorf("invalid modeq s_r: %s", proofData.ModEqProof.SR)
	}

	modeqSRQ, ok := new(big.Int).SetString(proofData.ModEqProof.SRq, 10)
	if !ok {
		return nil, fmt.Errorf("invalid modeq s_r_q: %s", proofData.ModEqProof.SRq)
	}

	modeqChallenge, ok := new(big.Int).SetString(proofData.ModEqProof.Challenge, 10)
	if !ok {
		return nil, fmt.Errorf("invalid modeq challenge: %s", proofData.ModEqProof.Challenge)
	}

	// Parse hash-to-prime values
	hashToPrimeChallenge, ok := new(big.Int).SetString(proofData.HashToPrimeProof.Challenge, 10)
	if !ok {
		return nil, fmt.Errorf("invalid hash_to_prime challenge: %s", proofData.HashToPrimeProof.Challenge)
	}

	originalElement, ok := new(big.Int).SetString(proofData.HashToPrimeProof.OriginalElement, 10)
	if !ok {
		return nil, fmt.Errorf("invalid original element: %s", proofData.HashToPrimeProof.OriginalElement)
	}

	hashedPrime, ok := new(big.Int).SetString(proofData.HashToPrimeProof.HashedPrime, 10)
	if !ok {
		return nil, fmt.Errorf("invalid hashed prime: %s", proofData.HashToPrimeProof.HashedPrime)
	}

	// Create bit decomposition for range proof
	bitDecomposition := make([]frontend.Variable, proofData.HashToPrimeProof.RangeBits)
	for i, bit := range proofData.HashToPrimeProof.BitDecomposition {
		bitDecomposition[i] = frontend.Variable(bit)
	}

	// Create circuit assignment
	assignment := &circuit.CircuitAssignment{
		// Public inputs
		AccumulatorValue:  accumulatorValue,
		IntegerCommitment:  integerCommitment,
		PedersenCommitment: *pedersenCommitment,

		// Proof components
		CoprimeAlpha1:     coprimeAlpha1,
		ModEqAlpha1:       *modeqAlpha1,
		ModEqAlpha2:       *modeqAlpha2,

		HashToPrimeChallenge: hashToPrimeChallenge,
		OriginalElement:     originalElement,
		HashedPrime:         hashedPrime,

		// Private witness
		Element:      element,
		Randomness:   randomness,
		RandomnessQ:  randomnessQ,

		// Coprime witness
		CoprimeSE:    coprimeSE,
		CoprimeSR:    coprimeSR,
		CoprimeChallenge: coprimeChallenge,

		// ModEq witness
		ModEqSE:      modeqSE,
		ModEqSR:      modeqSR,
		ModEqSRQ:     modeqSRQ,
		ModEqChallenge: modeqChallenge,

		// Range proof witness
		BitDecomposition: bitDecomposition,
	}

	return assignment, nil
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

// ProveFromBridgeData generates proof from bridge API response
func (p *Prover) ProveFromBridgeData(bridgeData *types.BridgeResponse) (*groth16.Proof, error) {
	if bridgeData.Status != "success" {
		return nil, fmt.Errorf("bridge operation failed: %s", bridgeData.Error)
	}

	if bridgeData.ProofData == nil {
		return nil, errors.New("no proof data in bridge response")
	}

	return p.ProveNonMembership(bridgeData.ProofData)
}

// BenchmarkProofGeneration benchmarks proof generation performance
func (p *Prover) BenchmarkProofGeneration(
	testCases []types.TestCaseData,
	iterations int,
) (*types.ProofBenchmarkResult, error) {
	if len(testCases) == 0 {
		return nil, errors.New("no test cases provided")
	}

	successCount := 0
	totalTime := time.Duration(0)
	minTime := time.Duration(1<<63 - 1) // Max time.Duration
	maxTime := time.Duration(0)
	proofSizes := make([]int, 0, iterations)

	for i := 0; i < iterations; i++ {
		testCase := testCases[i%len(testCases)]
		start := time.Now()

		proof, err := p.ProveNonMembership(testCase.ProofData)
		duration := time.Since(start)

		if err != nil {
			fmt.Printf("Proof generation failed for iteration %d: %v\n", i, err)
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

		// Get proof size (this would depend on the actual proof structure)
		proofSize := estimateProofSize(proof)
		proofSizes = append(proofSizes, proofSize)

		fmt.Printf("Iteration %d: %v, proof size: %d bytes\n", i, duration, proofSize)
	}

	if successCount == 0 {
		return nil, errors.New("all proof generation attempts failed")
	}

	averageTime := totalTime / time.Duration(successCount)

	// Calculate statistics
	avgProofSize := 0
	for _, size := range proofSizes {
		avgProofSize += size
	}
	avgProofSize /= len(proofSizes)

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

// estimateProofSize estimates the size of a proof in bytes
func estimateProofSize(proof *groth16.Proof) int {
	if proof == nil {
		return 0
	}

	// This is a rough estimate - actual size depends on the curve and proof format
	// Groth16 proofs on BN254 are approximately 288 bytes
	return 288
}

// ProofBenchmarkResult contains proof generation benchmark results
type ProofBenchmarkResult struct {
	Iterations       int     `json:"iterations"`
	SuccessfulProofs int     `json:"successful_proofs"`
	SuccessRate      float64 `json:"success_rate"`
	AverageTimeMs    float64 `json:"average_time_ms"`
	MinTimeMs        float64 `json:"min_time_ms"`
	MaxTimeMs        float64 `json:"max_time_ms"`
	TotalTimeMs      float64 `json:"total_time_ms"`
	AverageProofSize int     `json:"average_proof_size"`
}

// CreateTestProofData creates test proof data for benchmarking
func CreateTestProofData(numCases int) []types.TestCaseData {
	testCases := make([]types.TestCaseData, numCases)

	// Use the same test elements as the Rust benchmark
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

	for i := 0; i < numCases; i++ {
		element, _ := new(big.Int).SetString(testElements[i%len(testElements)], 10)
		randomness, _ := new(big.Int).SetString(testRandomness[i%len(testRandomness)], 10)

		// Create mock proof data for testing
		// In a real implementation, this would come from the bridge API
		testCases[i] = types.TestCaseData{
			Element:    element,
			Randomness: randomness,
			ProofData: &types.NonMembershipProofData{
				AccumulatorValue: "123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890",
				IntegerCommitment:  "98765432109876543210987654321098765432109876543210987654321098765432109876543210987654321098765432109876543210",
				// Fill in other mock data...
			},
		}
	}

	return testCases
}