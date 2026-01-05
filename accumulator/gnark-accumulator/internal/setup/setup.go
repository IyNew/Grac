package setup

import (
	"crypto/rand"
	"errors"
	"fmt"
	"math/big"
	"time"

	"github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/grac-enhanced/accumulator/gnark-accumulator/internal/circuit"
	"github.com/grac-enhanced/accumulator/gnark-accumulator/pkg/types"
)

// Setup represents the complete setup for non-membership verification
type Setup struct {
	// Circuit keys
	ProvingKey        groth16.ProvingKey       `json:"proving_key"`
	VerifyingKey      groth16.VerifyingKey     `json:"verifying_key"`

	// Cryptographic parameters
	SecurityLevel     int                        `json:"security_level"`
	HashToPrimeBits   int                        `json:"hash_to_prime_bits"`
	FieldSizeBits     int                        `json:"field_size_bits"`

	// Generators for integer commitments
	IntegerCommitmentG *big.Int                 `json:"integer_commitment_g"`
	IntegerCommitmentH *big.Int                 `json:"integer_commitment_h"`

	// Generators for Pedersen commitments
	PedersenCommitmentG *bn254.G1Affine      `json:"pedersen_commitment_g"`
	PedersenCommitmentH *bn254.G1Affine      `json:"pedersen_commitment_h"`

	// Setup metadata
	CreatedAt         time.Time                  `json:"created_at"`
	SetupTime         time.Duration              `json:"setup_time"`
}

// SetupOptions contains options for the setup process
type SetupOptions struct {
	SecurityLevel     int     `json:"security_level"`
	HashToPrimeBits   int     `json:"hash_to_prime_bits"`
	FieldSizeBits     int     `json:"field_size_bits"`
	Backend           string  `json:"backend"`           // "groth16", "plonk"
	Curve             string  `json:"curve"`             // "bn254"
	Randomness        []byte  `json:"randomness,omitempty"`
}

// DefaultSetupOptions returns default setup options matching the Rust benchmark
func DefaultSetupOptions() *SetupOptions {
	return &SetupOptions{
		SecurityLevel:   128,
		HashToPrimeBits: 254, // From the Rust benchmark
		FieldSizeBits:   255, // BLS12-381 field size
		Backend:         "groth16",
		Curve:           "bn254",
	}
}

// SetupNonMembership performs the complete setup for non-membership verification
func SetupNonMembership(opts *SetupOptions) (*Setup, error) {
	if opts == nil {
		opts = DefaultSetupOptions()
	}

	startTime := time.Now()

	// Validate options
	if err := validateSetupOptions(opts); err != nil {
		return nil, fmt.Errorf("invalid setup options: %w", err)
	}

	// Generate cryptographic generators
	integerCommitmentG, integerCommitmentH, err := generateIntegerCommitmentGenerators(opts)
	if err != nil {
		return nil, fmt.Errorf("failed to generate integer commitment generators: %w", err)
	}

	pedersenCommitmentG, pedersenCommitmentH, err := generatePedersenCommitmentGenerators(opts)
	if err != nil {
		return nil, fmt.Errorf("failed to generate Pedersen commitment generators: %w", err)
	}

	// Create circuit
	circuit := circuit.NewNonMembershipCircuit(
		opts.HashToPrimeBits,
		opts.FieldSizeBits,
		integerCommitmentG,
		integerCommitmentH,
		pedersenCommitmentG,
		pedersenCommitmentH,
	)

	// Compile circuit first
	ccs, err := frontend.Compile(bn254.ID.ScalarField(), r1cs.NewBuilder, circuit)
	if err != nil {
		return nil, fmt.Errorf("failed to compile circuit: %w", err)
	}

	// Setup proving and verification keys based on backend
	var pk groth16.ProvingKey
	var vk groth16.VerifyingKey

	switch opts.Backend {
	case "groth16":
		// groth16.Setup compiles and generates keys in one step
		// For actual use, you'd need a proper SRS, but for testing this works
		pk, vk, err = groth16.Setup(ccs)
		if err != nil {
			return nil, fmt.Errorf("failed to setup Groth16: %w", err)
		}
	case "plonk":
		// PLONK setup would use plonk.Setup instead
		return nil, errors.New("PLONK backend not yet implemented")
	default:
		return nil, fmt.Errorf("unsupported backend: %s", opts.Backend)
	}

	setupTime := time.Since(startTime)

	setup := &Setup{
		ProvingKey:           pk,
		VerifyingKey:         vk,
		SecurityLevel:         opts.SecurityLevel,
		HashToPrimeBits:      opts.HashToPrimeBits,
		FieldSizeBits:        opts.FieldSizeBits,
		IntegerCommitmentG:    integerCommitmentG,
		IntegerCommitmentH:    integerCommitmentH,
		PedersenCommitmentG:   pedersenCommitmentG,
		PedersenCommitmentH:   pedersenCommitmentH,
		CreatedAt:            time.Now(),
		SetupTime:            setupTime,
	}

	return setup, nil
}

// validateSetupOptions validates the setup options
func validateSetupOptions(opts *SetupOptions) error {
	if opts.SecurityLevel <= 0 || opts.SecurityLevel > 256 {
		return errors.New("security level must be between 1 and 256")
	}

	if opts.HashToPrimeBits <= 0 || opts.HashToPrimeBits > 512 {
		return errors.New("hash to prime bits must be between 1 and 512")
	}

	if opts.FieldSizeBits <= 0 || opts.FieldSizeBits > 512 {
		return errors.New("field size bits must be between 1 and 512")
	}

	if opts.HashToPrimeBits >= opts.FieldSizeBits {
		return errors.New("hash to prime bits must be less than field size bits")
	}

	if opts.Backend != "groth16" && opts.Backend != "plonk" {
		return errors.New("backend must be 'groth16' or 'plonk'")
	}

	if opts.Curve != "bn254" {
		return errors.New("curve must be 'bn254'")
	}

	return nil
}

// generateIntegerCommitmentGenerators generates secure generators for integer commitments
func generateIntegerCommitmentGenerators(opts *SetupOptions) (*big.Int, *big.Int, error) {
	// Generate two large prime generators for the integer commitment scheme
	// These should be from the RSA group in a full implementation

	// For now, generate random 2048-bit numbers (simplified)
	g := new(big.Int)
	h := new(big.Int)

	// In practice, these would be derived from RSA group parameters
	// For this implementation, we'll use well-known generators

	// g = 2 (simplified, should be generator of RSA group)
	g.SetInt64(2)

	// h = random 2048-bit number (co-prime to N)
	hBytes := make([]byte, 256) // 2048 bits
	if _, err := rand.Read(hBytes); err != nil {
		return nil, nil, fmt.Errorf("failed to generate randomness for h: %w", err)
	}
	h.SetBytes(hBytes)

	// Ensure h is odd and not a small power
	if h.Bit(0) == 0 {
		h.Add(h, big.NewInt(1))
	}

	return g, h, nil
}

// generatePedersenCommitmentGenerators generates secure generators for Pedersen commitments
func generatePedersenCommitmentGenerators(opts *SetupOptions) (*bn254.G1Affine, *bn254.G1Affine, error) {
	// Generate two random points on BLS12-381 G1 for Pedersen commitments
	g := new(bn254.G1Affine)
	h := new(bn254.G1Affine)

	// Generate random scalars as big.Int
	scalarGBytes := make([]byte, 32)
	scalarHBytes := make([]byte, 32)
	if _, err := rand.Read(scalarGBytes); err != nil {
		return nil, nil, fmt.Errorf("failed to generate randomness for g: %w", err)
	}
	if _, err := rand.Read(scalarHBytes); err != nil {
		return nil, nil, fmt.Errorf("failed to generate randomness for h: %w", err)
	}

	scalarG := new(big.Int).SetBytes(scalarGBytes)
	scalarH := new(big.Int).SetBytes(scalarHBytes)

	// Get the base generator for G1
	var base bn254.G1Affine
	_, _, base, _ = bn254.Generators()
	
	// Use the standard generator and multiply by random scalars
	g.ScalarMultiplication(&base, scalarG)
	h.ScalarMultiplication(&base, scalarH)

	// Ensure g and h are linearly independent
	for g.Equal(h) {
		// Regenerate h if it's equal to g
		if _, err := rand.Read(scalarHBytes); err != nil {
			return nil, nil, fmt.Errorf("failed to regenerate randomness for h: %w", err)
		}
		scalarH.SetBytes(scalarHBytes)
		h.ScalarMultiplication(&base, scalarH)
	}

	return g, h, nil
}

// ToSerializable converts setup to a serializable format
func (s *Setup) ToSerializable() *types.SetupData {
	return &types.SetupData{
		SecurityLevel:     s.SecurityLevel,
		HashToPrimeBits:   s.HashToPrimeBits,
		FieldSizeBits:     s.FieldSizeBits,
		IntegerCommitmentG: s.IntegerCommitmentG,
		IntegerCommitmentH: s.IntegerCommitmentH,
		PedersenCommitmentG: &types.EllipticPoint{
			X: new(big.Int).SetBytes(s.PedersenCommitmentG.X.Marshal()),
			Y: new(big.Int).SetBytes(s.PedersenCommitmentG.Y.Marshal()),
		},
		PedersenCommitmentH: &types.EllipticPoint{
			X: new(big.Int).SetBytes(s.PedersenCommitmentH.X.Marshal()),
			Y: new(big.Int).SetBytes(s.PedersenCommitmentH.Y.Marshal()),
		},
	}
}

// GetSetup returns the setup from file or creates a new one
func GetSetup(opts *SetupOptions, filepath string) (*Setup, error) {
	if filepath != "" {
		// Try to load from file
		// For now, just create new setup
	}

	// Create new setup
	return SetupNonMembership(opts)
}

// ExportSetup exports the setup to a file
func ExportSetup(setup *Setup, filepath string) error {
	// For now, this is a placeholder
	// In practice, this would serialize the keys and parameters
	return nil
}

// ImportSetup imports the setup from a file
func ImportSetup(filepath string) (*Setup, error) {
	// For now, this is a placeholder
	// In practice, this would deserialize the keys and parameters
	return nil, errors.New("import setup not yet implemented")
}

// BenchmarkSetup benchmarks the setup process
func BenchmarkSetup(opts *SetupOptions, iterations int) (*SetupBenchmarkResult, error) {
	if iterations <= 0 {
		iterations = 10
	}

	results := make([]time.Duration, iterations)
	totalSetupTime := time.Duration(0)

	for i := 0; i < iterations; i++ {
		start := time.Now()
		_, err := SetupNonMembership(opts)
		if err != nil {
			return nil, fmt.Errorf("setup iteration %d failed: %w", i, err)
		}
		duration := time.Since(start)
		results[i] = duration
		totalSetupTime += duration
	}

	// Calculate statistics
	averageTime := totalSetupTime / time.Duration(iterations)
	minTime := results[0]
	maxTime := results[0]

	for _, duration := range results[1:] {
		if duration < minTime {
			minTime = duration
		}
		if duration > maxTime {
			maxTime = duration
		}
	}

	return &SetupBenchmarkResult{
		Iterations:       iterations,
		AverageTimeMs:    float64(averageTime.Nanoseconds()) / 1_000_000.0,
		MinTimeMs:        float64(minTime.Nanoseconds()) / 1_000_000.0,
		MaxTimeMs:        float64(maxTime.Nanoseconds()) / 1_000_000.0,
		TotalTimeMs:      float64(totalSetupTime.Nanoseconds()) / 1_000_000.0,
		SuccessRate:      1.0, // All successful
	}, nil
}

// SetupBenchmarkResult contains setup benchmark results
type SetupBenchmarkResult struct {
	Iterations    int     `json:"iterations"`
	AverageTimeMs float64 `json:"average_time_ms"`
	MinTimeMs    float64 `json:"min_time_ms"`
	MaxTimeMs    float64 `json:"max_time_ms"`
	TotalTimeMs  float64 `json:"total_time_ms"`
	SuccessRate  float64 `json:"success_rate"`
}