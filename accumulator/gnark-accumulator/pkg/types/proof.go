package types

import (
	"math/big"
)

// NonMembershipProofData represents the data structure for non-membership proofs
// that comes from the Rust implementation
type NonMembershipProofData struct {
	// Public inputs from accumulator
	AccumulatorValue *big.Int `json:"accumulator_value"`
	IntegerCommitment  *big.Int `json:"integer_commitment"`

	// Pedersen commitment (elliptic curve point)
	PedersenCommitment *EllipticPoint `json:"pedersen_commitment"`

	// Coprime proof components
	CoprimeProof *CoprimeProofData `json:"coprime_proof"`

	// ModEq proof components
	ModEqProof *ModEqProofData `json:"modeq_proof"`

	// Hash-to-prime proof components
	HashToPrimeProof *HashToPrimeProofData `json:"hash_to_prime_proof"`

	// Security parameters
	SecurityLevel     int    `json:"security_level"`
	HashToPrimeBits    int    `json:"hash_to_prime_bits"`
	FieldSizeBits      int    `json:"field_size_bits"`
}

// EllipticPoint represents a point on an elliptic curve
type EllipticPoint struct {
	X *big.Int `json:"x"`
	Y *big.Int `json:"y"`
}

// CoprimeProofData contains the proof that an element is coprime to the accumulator
type CoprimeProofData struct {
	// Message from first round of sigma protocol
	Alpha1 *big.Int `json:"alpha1"`

	// Response values from second round
	SE *big.Int `json:"s_e"`
	SR *big.Int `json:"s_r"`

	// Challenge value
	Challenge *big.Int `json:"challenge"`
}

// ModEqProofData contains the proof of modular equality between commitments
type ModEqProofData struct {
	// Pedersen commitment responses
	Alpha1 *EllipticPoint `json:"alpha1"`
	Alpha2 *EllipticPoint `json:"alpha2"`

	// Response values
	SE   *big.Int `json:"s_e"`
	SR   *big.Int `json:"s_r"`
	SRq  *big.Int `json:"s_r_q"`

	// Challenge
	Challenge *big.Int `json:"challenge"`
}

// HashToPrimeProofData contains the range proof for hash-to-prime
type HashToPrimeProofData struct {
	// Bit decomposition for range proof
	BitDecomposition []uint64 `json:"bit_decomposition"`

	// Challenge from Fiat-Shamir
	Challenge *big.Int `json:"challenge"`

	// Original element and hashed prime
	OriginalElement *big.Int `json:"original_element"`
	HashedPrime     *big.Int `json:"hashed_prime"`

	// Number of bits in the range proof
	RangeBits int `json:"range_bits"`
}

// WitnessData contains the private witness information
type WitnessData struct {
	// Original element being proven
	Element *big.Int `json:"element"`

	// Randomness values
	Randomness     *big.Int `json:"randomness"`     // For integer commitment
	RandomnessQ    *big.Int `json:"randomness_q"`  // For Pedersen commitment

	// Coprime witness values
	D *big.Int `json:"d"`
	B *big.Int `json:"b"`
}

// BenchmarkData contains all data needed for benchmarking
type BenchmarkData struct {
	// Setup parameters
	SetupData *SetupData `json:"setup_data"`

	// Test case data
	TestCases []TestCaseData `json:"test_cases"`
}

// SetupData contains the common reference string and setup parameters
type SetupData struct {
	// Cryptographic parameters
	SecurityLevel     int    `json:"security_level"`
	HashToPrimeBits    int    `json:"hash_to_prime_bits"`
	FieldSizeBits      int    `json:"field_size_bits"`

	// Generators for integer commitments
	IntegerCommitmentG *big.Int `json:"integer_commitment_g"`
	IntegerCommitmentH *big.Int `json:"integer_commitment_h"`

	// Generators for Pedersen commitments
	PedersenCommitmentG *EllipticPoint `json:"pedersen_commitment_g"`
	PedersenCommitmentH *EllipticPoint `json:"pedersen_commitment_h"`
}

// TestCaseData represents a single test case for benchmarking
type TestCaseData struct {
	// Input values
	Element    *big.Int `json:"element"`
	Randomness *big.Int `json:"randomness"`

	// Generated proof
	ProofData *NonMembershipProofData `json:"proof_data"`

	// Verification results
	VerificationResult bool `json:"verification_result"`
}

// ToWireFormat converts big.Int values to wire format for transmission
func (p *NonMembershipProofData) ToWireFormat() *WireProofData {
	return &WireProofData{
		AccumulatorValue:  p.AccumulatorValue.String(),
		IntegerCommitment: p.IntegerCommitment.String(),
		PedersenCommitment: &WireEllipticPoint{
			X: p.PedersenCommitment.X.String(),
			Y: p.PedersenCommitment.Y.String(),
		},
		// ... convert other fields
	}
}

// WireProofData is the wire format for JSON transmission
type WireProofData struct {
	AccumulatorValue  string             `json:"accumulator_value"`
	IntegerCommitment string             `json:"integer_commitment"`
	PedersenCommitment *WireEllipticPoint `json:"pedersen_commitment"`
	// ... other fields as strings for JSON transmission
}

// WireEllipticPoint is the wire format for elliptic curve points
type WireEllipticPoint struct {
	X string `json:"x"`
	Y string `json:"y"`
}

// MembershipProofData represents data structure for membership proofs
// based on the Rust membership protocol implementation
type MembershipProofData struct {
	// Public inputs from accumulator
	AccumulatorValue string `json:"accumulator_value"`
	IntegerCommitment  string `json:"integer_commitment"`

	// Pedersen commitment (elliptic curve point)
	PedersenCommitment *EllipticPoint `json:"pedersen_commitment"`

	// Root proof for membership (proves element is in accumulator)
	RootProof *RootProofData `json:"root_proof"`

	// ModEq proof components
	ModEqProof *ModEqProofData `json:"modeq_proof"`

	// Hash-to-prime proof components
	HashToPrimeProof *HashToPrimeProofData `json:"hash_to_prime_proof"`

	// Security parameters
	SecurityLevel     int    `json:"security_level"`
	HashToPrimeBits   int    `json:"hash_to_prime_bits"`
	FieldSizeBits      int    `json:"field_size_bits"`

	// Witness data (private)
	WitnessData *MembershipWitnessData `json:"witness_data"`
}

// RootProofData contains proof that element is in accumulator (membership)
type RootProofData struct {
	// Message from first round of sigma protocol for root
	Alpha1 string `json:"alpha1"`

	// Response values from second round
	SE string `json:"s_e"`
	SR string `json:"s_r"`

	// Challenge value
	Challenge string `json:"challenge"`
}

// MembershipWitnessData contains private witness information for membership
type MembershipWitnessData struct {
	// Original element being proven
	Element string `json:"element"`

	// Randomness values
	Randomness     string `json:"randomness"`     // For integer commitment
	RandomnessQ    string `json:"randomness_q"`  // For Pedersen commitment
}

// MembershipTestCaseData represents a single test case for membership benchmarking
type MembershipTestCaseData struct {
	// Input values
	Element    *big.Int `json:"element"`
	Randomness *big.Int `json:"randomness"`

	// Generated proof
	ProofData *MembershipProofData `json:"proof_data"`

	// Verification results
	VerificationResult bool `json:"verification_result"`
}

// MembershipSetupData contains setup data for membership verification
type MembershipSetupData struct {
	// Cryptographic parameters
	SecurityLevel     int    `json:"security_level"`
	HashToPrimeBits   int    `json:"hash_to_prime_bits"`
	FieldSizeBits      int    `json:"field_size_bits"`

	// Generators for integer commitments
	IntegerCommitmentG string `json:"integer_commitment_g"`
	IntegerCommitmentH string `json:"integer_commitment_h"`

	// Generators for Pedersen commitments
	PedersenCommitmentG *EllipticPoint `json:"pedersen_commitment_g"`
	PedersenCommitmentH *EllipticPoint `json:"pedersen_commitment_h"`

	// Generator for accumulator (RSA group generator)
	AccumulatorG string `json:"accumulator_g"`
}

// MembershipProofBenchmarkResult contains membership proof generation benchmark results
type MembershipProofBenchmarkResult struct {
	Iterations         int     `json:"iterations"`
	SuccessfulProofs   int     `json:"successful_proofs"`
	SuccessRate        float64 `json:"success_rate"`
	AverageTimeMs      float64 `json:"average_time_ms"`
	MinTimeMs          float64 `json:"min_time_ms"`
	MaxTimeMs          float64 `json:"max_time_ms"`
	TotalTimeMs        float64 `json:"total_time_ms"`
	AverageProofSize   int     `json:"average_proof_size"`
}

// MembershipVerificationBenchmarkResult contains membership proof verification benchmark results
type MembershipVerificationBenchmarkResult struct {
	Iterations                int     `json:"iterations"`
	SuccessfulVerifications   int     `json:"successful_verifications"`
	SuccessRate               float64 `json:"success_rate"`
	AverageTimeMs             float64 `json:"average_time_ms"`
	MinTimeMs                 float64 `json:"min_time_ms"`
	MaxTimeMs                 float64 `json:"max_time_ms"`
	TotalTimeMs               float64 `json:"total_time_ms"`
}

// MembershipAggregatedStats contains aggregated membership verification statistics
type MembershipAggregatedStats struct {
	TotalMembershipProofs     int     `json:"total_membership_proofs"`
	SuccessfulMembershipProofs int     `json:"successful_membership_proofs"`
	FailedMembershipProofs     int     `json:"failed_membership_proofs"`
	MembershipSuccessRate      float64 `json:"membership_success_rate"`
}

// MembershipVerificationMetrics contains metrics about membership verification setup
type MembershipVerificationMetrics struct {
	SecurityLevel              int    `json:"security_level"`
	HashToPrimeBits            int    `json:"hash_to_prime_bits"`
	FieldSizeBits              int    `json:"field_size_bits"`
	CurveName                 string `json:"curve_name"`
	Backend                   string `json:"backend"`
	MembershipVerificationKeySize int    `json:"membership_verification_key_size"`
	SetupTime                 int64  `json:"setup_time"`  // Using int64 for JSON serialization
	CreatedAt                 int64   `json:"created_at"` // Using int64 for JSON serialization
	AccumulatorG              string  `json:"accumulator_g"`
}

// MembershipSetupBenchmarkResult contains membership setup benchmark results
type MembershipSetupBenchmarkResult struct {
	Iterations    int     `json:"iterations"`
	AverageTimeMs float64 `json:"average_time_ms"`
	MinTimeMs    float64 `json:"min_time_ms"`
	MaxTimeMs    float64 `json:"max_time_ms"`
	TotalTimeMs  float64 `json:"total_time_ms"`
	SuccessRate  float64 `json:"success_rate"`
}

// MembershipBridgeResponse represents bridge API response for membership proofs
type MembershipBridgeResponse struct {
	Status             string                  `json:"status"`
	Error              string                  `json:"error,omitempty"`
	ProofData          *MembershipProofData    `json:"proof_data,omitempty"`
	VerificationResult  *bool                   `json:"verification_result,omitempty"`
	ProcessingTime     float64                 `json:"processing_time_ms"`
	Timestamp          string                  `json:"timestamp"`
}