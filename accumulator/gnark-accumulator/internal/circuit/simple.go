package circuit

import (
	"fmt"
	"math/big"

	"github.com/consensys/gnark/frontend"
)

// SimpleNonMembershipCircuit implements a simplified version for testing
type SimpleNonMembershipCircuit struct {
	// Public inputs from accumulator
	AccumulatorValue    frontend.Variable `gnark:",public"`
	IntegerCommitment   frontend.Variable `gnark:",public"`
	PedersenCommitmentX frontend.Variable `gnark:",public"`
	PedersenCommitmentY frontend.Variable `gnark:",public"`

	// Public proof components
	CoprimeAlpha1        frontend.Variable `gnark:",public"`
	ModEqAlpha1X         frontend.Variable `gnark:",public"`
	ModEqAlpha1Y         frontend.Variable `gnark:",public"`
	HashToPrimeChallenge frontend.Variable `gnark:",public"`

	// Private witness
	Element    frontend.Variable
	Randomness frontend.Variable
	CoprimeSE  frontend.Variable
	CoprimeSR  frontend.Variable
	ModEqSE    frontend.Variable
	ModEqSR    frontend.Variable

	// Circuit constants
	IntegerCommitmentG  frontend.Variable
	IntegerCommitmentH  frontend.Variable
	PedersenCommitmentG frontend.Variable
	PedersenCommitmentH frontend.Variable
}

// Define implements the constraints for non-membership verification
func (circuit *SimpleNonMembershipCircuit) Define(api frontend.API) error {
	// Simplified verification - we'll implement the key checks

	// 1. Verify coprime commitment: g^s_e * h^s_r = α1
	commitmentExp1 := api.Mul(circuit.IntegerCommitmentG, circuit.CoprimeSE)
	commitmentExp2 := api.Mul(circuit.IntegerCommitmentH, circuit.CoprimeSR)
	commitmentSum := api.Add(commitmentExp1, commitmentExp2)
	api.AssertIsEqual(commitmentSum, circuit.CoprimeAlpha1)

	// 2. Verify ModEq - simplified version
	// Convert element to field element (mod q)
	elementBits := api.ToBinary(circuit.Element, 256)
	elementField := api.FromBinary(elementBits)

	// Pedersen commitment: g^element_mod_q * h^s_r_q
	pedersenExp1 := api.Mul(circuit.PedersenCommitmentG, elementField)
	pedersenExp2 := api.Mul(circuit.PedersenCommitmentH, circuit.ModEqSR)
	pedersenCommitment := api.Add(pedersenExp1, pedersenExp2)

	// Verify Pedersen commitment matches public input
	api.AssertIsEqual(pedersenCommitment, circuit.PedersenCommitmentX)

	// 3. Simple hash-to-prime range check
	// Ensure element is in valid range - simplified check
	api.AssertIsDifferent(circuit.Element, 0)

	return nil
}

// NewSimpleNonMembershipCircuit creates a simple non-membership circuit
func NewSimpleNonMembershipCircuit() *SimpleNonMembershipCircuit {
	return &SimpleNonMembershipCircuit{}
}

// SetupSimpleCircuit compiles the circuit and returns proving/verification keys
// Note: This is a placeholder - actual setup requires SRS. Use test helper for testing.
func SetupSimpleCircuit() (interface{}, interface{}, error) {
	// This is a placeholder - actual setup requires SRS (Structured Reference String)
	// Use the test helper or setup package for full functionality
	return nil, nil, fmt.Errorf("use test helper or setup package for circuit setup")
}

// SimpleAssignment represents a witness assignment for the simple circuit
type SimpleAssignment struct {
	// Public inputs
	AccumulatorValue    *big.Int
	IntegerCommitment   *big.Int
	PedersenCommitmentX *big.Int
	PedersenCommitmentY *big.Int

	// Proof components
	CoprimeAlpha1        *big.Int
	ModEqAlpha1X         *big.Int
	ModEqAlpha1Y         *big.Int
	HashToPrimeChallenge *big.Int

	// Private witness
	Element    *big.Int
	Randomness *big.Int
	CoprimeSE  *big.Int
	CoprimeSR  *big.Int
	ModEqSE    *big.Int
	ModEqSR    *big.Int
}

// NewSimpleWitness is deprecated - use frontend.NewWitness(assignment, curveID) directly
func NewSimpleWitness(assignment *SimpleAssignment) (interface{}, error) {
	// Return assignment directly - test helper handles witness creation
	return assignment, nil
}

// CreateMockAssignment creates test data for benchmarking
func CreateMockAssignment() *SimpleAssignment {
	// Generate mock data similar to Rust benchmark
	element, _ := new(big.Int).SetString("12702637924034044211", 10)
	randomness := big.NewInt(5)

	// Mock commitment values (these would come from the actual accumulator)
	accumulatorValue, _ := new(big.Int).SetString("123456789012345678901234567890123456789012345678901234567890", 10)
	integerCommitment, _ := new(big.Int).SetString("98765432109876543210987654321098765432109876543210987654321", 10)
	pedersenCommitmentX := big.NewInt(12345)
	pedersenCommitmentY := big.NewInt(67890)

	// Mock proof values
	coprimeAlpha1, _ := new(big.Int).SetString("1111111111111111111111111111111111111111111111", 10)
	coprimeSE, _ := new(big.Int).SetString("2222222222222222222222222222222222222222222222", 10)
	coprimeSR, _ := new(big.Int).SetString("3333333333333333333333333333333333333333333333", 10)

	modeqAlpha1X := big.NewInt(44444)
	modeqAlpha1Y := big.NewInt(55555)
	modeqSE, _ := new(big.Int).SetString("6666666666666666666666666666666666666666", 10)
	modeqSR, _ := new(big.Int).SetString("7777777777777777777777777777777777777777777", 10)

	hashToPrimeChallenge, _ := new(big.Int).SetString("8888888888888888888888888888888888888888888888", 10)

	return &SimpleAssignment{
		AccumulatorValue:     accumulatorValue,
		IntegerCommitment:    integerCommitment,
		PedersenCommitmentX:  pedersenCommitmentX,
		PedersenCommitmentY:  pedersenCommitmentY,
		CoprimeAlpha1:        coprimeAlpha1,
		ModEqAlpha1X:         modeqAlpha1X,
		ModEqAlpha1Y:         modeqAlpha1Y,
		HashToPrimeChallenge: hashToPrimeChallenge,
		Element:              element,
		Randomness:           randomness,
		CoprimeSE:            coprimeSE,
		CoprimeSR:            coprimeSR,
		ModEqSE:              modeqSE,
		ModEqSR:              modeqSR,
	}
}

// GetCircuitStats returns statistics about the compiled circuit
func GetCircuitStats() map[string]int {
	// These are estimates based on our circuit structure
	return map[string]int{
		"NumConstraints":           15,  // Rough estimate of constraints
		"NumVariables":             12,  // Rough estimate of variables
		"ProofSizeBytes":           288, // PLONK proof size estimate
		"VerificationKeySizeBytes": 400, // Verification key size estimate
	}
}
