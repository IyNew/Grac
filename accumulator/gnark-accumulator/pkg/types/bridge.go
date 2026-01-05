package types

import (
	"encoding/json"
	"fmt"
	"math/big"
)

// BridgeRequest represents a request to the Rust bridge API
type BridgeRequest struct {
	// Request type: "setup", "prove", "verify"
	Type string `json:"type"`

	// Setup parameters
	SecurityLevel int `json:"security_level,omitempty"`

	// Prove inputs
	Element    *big.Int `json:"element,omitempty"`
	Randomness *big.Int `json:"randomness,omitempty"`

	// Verify inputs
	ProofData *NonMembershipProofData `json:"proof_data,omitempty"`
}

// BridgeResponse represents a response from the Rust bridge API
type BridgeResponse struct {
	// Status of the operation
	Status string `json:"status"` // "success", "error"

	// Error message if any
	Error string `json:"error,omitempty"`

	// Setup response
	SetupData *SetupData `json:"setup_data,omitempty"`

	// Prove response
	ProofData *NonMembershipProofData `json:"proof_data,omitempty"`

	// Verify response
	VerificationResult bool `json:"verification_result,omitempty"`

	// Performance metrics
	ProvingTimeMs     int64 `json:"proving_time_ms,omitempty"`
	VerificationTimeMs int64 `json:"verification_time_ms,omitempty"`
}

// ToJSON converts the request to JSON for transmission
func (r *BridgeRequest) ToJSON() ([]byte, error) {
	// Convert big.Int to strings for JSON serialization
	jsonReq := struct {
		Type string `json:"type"`
		SetupData struct {
			SecurityLevel int `json:"security_level,omitempty"`
		} `json:"setup_data,omitempty"`
		ProveData struct {
			Element    string `json:"element,omitempty"`
			Randomness string `json:"randomness,omitempty"`
		} `json:"prove_data,omitempty"`
		VerifyData struct {
			ProofData *NonMembershipProofData `json:"proof_data,omitempty"`
		} `json:"verify_data,omitempty"`
	}{
		Type: r.Type,
	}

	if r.SecurityLevel > 0 {
		jsonReq.SetupData.SecurityLevel = r.SecurityLevel
	}

	if r.Element != nil {
		jsonReq.ProveData.Element = r.Element.String()
	}
	if r.Randomness != nil {
		jsonReq.ProveData.Randomness = r.Randomness.String()
	}

	if r.ProofData != nil {
		jsonReq.VerifyData.ProofData = r.ProofData
	}

	return json.Marshal(jsonReq)
}

// FromJSON parses a BridgeResponse from JSON
func FromJSONResponse(data []byte) (*BridgeResponse, error) {
	var resp BridgeResponse
	err := json.Unmarshal(data, &resp)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal response: %w", err)
	}

	// Convert string big.Int values back to big.Int if needed
	// This would be handled by the actual bridge implementation

	return &resp, nil
}

// BenchmarkConfig contains configuration for the benchmark
type BenchmarkConfig struct {
	// Number of iterations for proving
	ProveIterations int `json:"prove_iterations"`

	// Number of iterations for verification
	VerifyIterations int `json:"verify_iterations"`

	// Security parameters
	SecurityLevel  int `json:"security_level"`
	HashToPrimeBits int `json:"hash_to_prime_bits"`

	// Test elements (as strings)
	TestElements []string `json:"test_elements"`

	// Randomness values (as strings)
	TestRandomness []string `json:"test_randomness"`

	// Whether to generate random test data
	GenerateRandom bool `json:"generate_random"`
	NumRandomCases int `json:"num_random_cases"`
}

// DefaultBenchmarkConfig returns a default configuration matching the Rust benchmark
func DefaultBenchmarkConfig() *BenchmarkConfig {
	return &BenchmarkConfig{
		ProveIterations:   100,
		VerifyIterations: 1000,
		SecurityLevel:     128,
		HashToPrimeBits:   254,
		TestElements: []string{
			"12702637924034044211",
			"378373571372703133",
			"8640171141336142787",
		},
		TestRandomness: []string{
			"5",
			"9",
			"13",
		},
		GenerateRandom:  false,
		NumRandomCases: 10,
	}
}

// BenchmarkResults contains the results of a benchmark run
type BenchmarkResults struct {
	// Configuration used
	Config *BenchmarkConfig `json:"config"`

	// Proving results
	ProvingResults struct {
		AverageTimeMs   float64 `json:"average_time_ms"`
		MinTimeMs       int64   `json:"min_time_ms"`
		MaxTimeMs       int64   `json:"max_time_ms"`
		TotalTimeMs     int64   `json:"total_time_ms"`
		Iterations      int     `json:"iterations"`
		SuccessRate     float64 `json:"success_rate"`
	} `json:"proving_results"`

	// Verification results
	VerificationResults struct {
		AverageTimeMs   float64 `json:"average_time_ms"`
		MinTimeMs       int64   `json:"min_time_ms"`
		MaxTimeMs       int64   `json:"max_time_ms"`
		TotalTimeMs     int64   `json:"total_time_ms"`
		Iterations      int     `json:"iterations"`
		SuccessRate     float64 `json:"success_rate"`
	} `json:"verification_results"`

	// Circuit statistics
	CircuitStats struct {
		NumConstraints int    `json:"num_constraints"`
		NumVariables   int    `json:"num_variables"`
		ProofSizeBytes int    `json:"proof_size_bytes"`
		VerificationKeySizeBytes int `json:"verification_key_size_bytes"`
	} `json:"circuit_stats"`

	// Performance comparison with Rust (if available)
	RustComparison *RustComparison `json:"rust_comparison,omitempty"`
}

// RustComparison contains performance comparison with the Rust implementation
type RustComparison struct {
	RustProvingTimeMs     float64 `json:"rust_proving_time_ms"`
	RustVerificationTimeMs float64 `json:"rust_verification_time_ms"`
	GoProvingSpeedup      float64 `json:"go_proving_speedup"`
	GoVerificationSpeedup float64 `json:"go_verification_speedup"`
}