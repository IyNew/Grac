package circuit

import (
	"fmt"
	"math/big"

	"github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark/frontend"
)

// CombinedCircuit implements both membership and non-membership verification in one circuit
// The circuit verifies both proofs simultaneously
type CombinedCircuit struct {
	// Public inputs - shared between membership and non-membership
	AccumulatorValue    frontend.Variable `gnark:",public"`
	IntegerCommitment   frontend.Variable `gnark:",public"`
	PedersenCommitmentX frontend.Variable `gnark:",public"`
	PedersenCommitmentY frontend.Variable `gnark:",public"`

	// Membership proof components - public
	MembershipRootAlpha1         frontend.Variable `gnark:",public"`
	MembershipModEqAlpha1X       frontend.Variable `gnark:",public"`
	MembershipModEqAlpha1Y       frontend.Variable `gnark:",public"`
	MembershipModEqAlpha2X       frontend.Variable `gnark:",public"`
	MembershipModEqAlpha2Y       frontend.Variable `gnark:",public"`
	MembershipHashToPrimeChallenge frontend.Variable `gnark:",public"`
	MembershipOriginalElement     frontend.Variable `gnark:",public"`
	MembershipHashedPrime         frontend.Variable `gnark:",public"`

	// Non-membership proof components - public
	NonMembershipCoprimeAlpha1      frontend.Variable `gnark:",public"`
	NonMembershipModEqAlpha1X       frontend.Variable `gnark:",public"`
	NonMembershipModEqAlpha1Y       frontend.Variable `gnark:",public"`
	NonMembershipModEqAlpha2X       frontend.Variable `gnark:",public"`
	NonMembershipModEqAlpha2Y       frontend.Variable `gnark:",public"`
	NonMembershipHashToPrimeChallenge frontend.Variable `gnark:",public"`
	NonMembershipOriginalElement     frontend.Variable `gnark:",public"`
	NonMembershipHashedPrime         frontend.Variable `gnark:",public"`

	// Membership private witness inputs
	MembershipElement            frontend.Variable
	MembershipRandomness         frontend.Variable
	MembershipRandomnessQ        frontend.Variable
	MembershipRootSE             frontend.Variable
	MembershipRootSR             frontend.Variable
	MembershipRootChallenge      frontend.Variable
	MembershipModEqSE            frontend.Variable
	MembershipModEqSR            frontend.Variable
	MembershipModEqSRQ           frontend.Variable
	MembershipModEqChallenge     frontend.Variable
	MembershipBitDecomposition   []frontend.Variable

	// Non-membership private witness inputs
	NonMembershipElement            frontend.Variable
	NonMembershipRandomness         frontend.Variable
	NonMembershipRandomnessQ        frontend.Variable
	NonMembershipCoprimeSE          frontend.Variable
	NonMembershipCoprimeSR           frontend.Variable
	NonMembershipCoprimeChallenge   frontend.Variable
	NonMembershipModEqSE            frontend.Variable
	NonMembershipModEqSR            frontend.Variable
	NonMembershipModEqSRQ           frontend.Variable
	NonMembershipModEqChallenge     frontend.Variable
	NonMembershipBitDecomposition   []frontend.Variable

	// Precomputed generators (circuit constants)
	IntegerCommitmentG frontend.Variable
	IntegerCommitmentH frontend.Variable
	PedersenCommitmentG frontend.Variable
	PedersenCommitmentH frontend.Variable
	AccumulatorG       frontend.Variable

	// Security parameters (stored as constants, not variables)
	HashToPrimeBits    int
	FieldSizeBits      int
}

// Define defines the constraints for the combined membership and non-membership verification circuit
func (circuit *CombinedCircuit) Define(api frontend.API) error {
	// Verify membership circuit
	membershipCircuit := &MembershipCircuit{
		AccumulatorValue:    circuit.AccumulatorValue,
		IntegerCommitment:   circuit.IntegerCommitment,
		PedersenCommitmentX: circuit.PedersenCommitmentX,
		PedersenCommitmentY: circuit.PedersenCommitmentY,
		RootAlpha1:          circuit.MembershipRootAlpha1,
		ModEqAlpha1X:        circuit.MembershipModEqAlpha1X,
		ModEqAlpha1Y:        circuit.MembershipModEqAlpha1Y,
		ModEqAlpha2X:        circuit.MembershipModEqAlpha2X,
		ModEqAlpha2Y:        circuit.MembershipModEqAlpha2Y,
		HashToPrimeChallenge: circuit.MembershipHashToPrimeChallenge,
		OriginalElement:      circuit.MembershipOriginalElement,
		HashedPrime:          circuit.MembershipHashedPrime,
		Element:              circuit.MembershipElement,
		Randomness:           circuit.MembershipRandomness,
		RandomnessQ:          circuit.MembershipRandomnessQ,
		RootSE:               circuit.MembershipRootSE,
		RootSR:               circuit.MembershipRootSR,
		RootChallenge:        circuit.MembershipRootChallenge,
		ModEqSE:              circuit.MembershipModEqSE,
		ModEqSR:              circuit.MembershipModEqSR,
		ModEqSRQ:             circuit.MembershipModEqSRQ,
		ModEqChallenge:       circuit.MembershipModEqChallenge,
		BitDecomposition:     circuit.MembershipBitDecomposition,
		IntegerCommitmentG:   circuit.IntegerCommitmentG,
		IntegerCommitmentH:   circuit.IntegerCommitmentH,
		PedersenCommitmentG:  circuit.PedersenCommitmentG,
		PedersenCommitmentH:  circuit.PedersenCommitmentH,
		AccumulatorG:         circuit.AccumulatorG,
		HashToPrimeBits:      circuit.HashToPrimeBits,
		FieldSizeBits:        circuit.FieldSizeBits,
	}

	if err := membershipCircuit.Define(api); err != nil {
		return fmt.Errorf("membership circuit verification failed: %w", err)
	}

	// Verify non-membership circuit
	nonMembershipCircuit := &NonMembershipCircuit{
		AccumulatorValue:    circuit.AccumulatorValue,
		IntegerCommitment:   circuit.IntegerCommitment,
		PedersenCommitmentX: circuit.PedersenCommitmentX,
		PedersenCommitmentY: circuit.PedersenCommitmentY,
		CoprimeAlpha1:       circuit.NonMembershipCoprimeAlpha1,
		ModEqAlpha1X:        circuit.NonMembershipModEqAlpha1X,
		ModEqAlpha1Y:        circuit.NonMembershipModEqAlpha1Y,
		ModEqAlpha2X:        circuit.NonMembershipModEqAlpha2X,
		ModEqAlpha2Y:        circuit.NonMembershipModEqAlpha2Y,
		HashToPrimeChallenge: circuit.NonMembershipHashToPrimeChallenge,
		OriginalElement:      circuit.NonMembershipOriginalElement,
		HashedPrime:          circuit.NonMembershipHashedPrime,
		Element:              circuit.NonMembershipElement,
		Randomness:           circuit.NonMembershipRandomness,
		RandomnessQ:          circuit.NonMembershipRandomnessQ,
		CoprimeSE:            circuit.NonMembershipCoprimeSE,
		CoprimeSR:            circuit.NonMembershipCoprimeSR,
		CoprimeChallenge:     circuit.NonMembershipCoprimeChallenge,
		ModEqSE:              circuit.NonMembershipModEqSE,
		ModEqSR:              circuit.NonMembershipModEqSR,
		ModEqSRQ:             circuit.NonMembershipModEqSRQ,
		ModEqChallenge:       circuit.NonMembershipModEqChallenge,
		BitDecomposition:     circuit.NonMembershipBitDecomposition,
		IntegerCommitmentG:   circuit.IntegerCommitmentG,
		IntegerCommitmentH:   circuit.IntegerCommitmentH,
		PedersenCommitmentG:  circuit.PedersenCommitmentG,
		PedersenCommitmentH:  circuit.PedersenCommitmentH,
		HashToPrimeBits:      circuit.HashToPrimeBits,
		FieldSizeBits:        circuit.FieldSizeBits,
	}

	if err := nonMembershipCircuit.Define(api); err != nil {
		return fmt.Errorf("non-membership circuit verification failed: %w", err)
	}

	return nil
}

// NewCombinedCircuit creates a new combined membership and non-membership verification circuit
func NewCombinedCircuit(
	hashToPrimeBits, fieldSizeBits int,
	integerCommitmentG, integerCommitmentH *big.Int,
	pedersenCommitmentG, pedersenCommitmentH *bn254.G1Affine,
	accumulatorG *big.Int,
) *CombinedCircuit {
	return &CombinedCircuit{
		HashToPrimeBits:    hashToPrimeBits,
		FieldSizeBits:      fieldSizeBits,
		IntegerCommitmentG: frontend.Variable(integerCommitmentG),
		IntegerCommitmentH: frontend.Variable(integerCommitmentH),
		PedersenCommitmentG: frontend.Variable(pedersenCommitmentG),
		PedersenCommitmentH: frontend.Variable(pedersenCommitmentH),
		AccumulatorG:       frontend.Variable(accumulatorG),
	}
}

// SetupCombinedCircuit compiles the combined circuit and returns proving and verification keys
// Note: This function is simplified - for full setup with SRS, use the setup package
func SetupCombinedCircuit(
	hashToPrimeBits, fieldSizeBits int,
	integerCommitmentG, integerCommitmentH *big.Int,
	pedersenCommitmentG, pedersenCommitmentH *bn254.G1Affine,
	accumulatorG *big.Int,
) (interface{}, interface{}, error) {
	// This is a placeholder - actual setup requires SRS (Structured Reference String)
	// Use the test helper or setup package for full functionality
	return nil, nil, fmt.Errorf("use test helper or setup package for circuit setup")
}

// CombinedCircuitAssignment represents a complete assignment to the combined circuit
// This struct must match the CombinedCircuit struct exactly, but with concrete types
type CombinedCircuitAssignment struct {
	// Public inputs - shared
	AccumulatorValue    *big.Int `gnark:",public"`
	IntegerCommitment   *big.Int `gnark:",public"`
	PedersenCommitmentX *big.Int `gnark:",public"`
	PedersenCommitmentY *big.Int `gnark:",public"`

	// Membership proof components - public
	MembershipRootAlpha1         *big.Int `gnark:",public"`
	MembershipModEqAlpha1X       *big.Int `gnark:",public"`
	MembershipModEqAlpha1Y       *big.Int `gnark:",public"`
	MembershipModEqAlpha2X       *big.Int `gnark:",public"`
	MembershipModEqAlpha2Y       *big.Int `gnark:",public"`
	MembershipHashToPrimeChallenge *big.Int `gnark:",public"`
	MembershipOriginalElement     *big.Int `gnark:",public"`
	MembershipHashedPrime         *big.Int `gnark:",public"`

	// Non-membership proof components - public
	NonMembershipCoprimeAlpha1      *big.Int `gnark:",public"`
	NonMembershipModEqAlpha1X       *big.Int `gnark:",public"`
	NonMembershipModEqAlpha1Y       *big.Int `gnark:",public"`
	NonMembershipModEqAlpha2X       *big.Int `gnark:",public"`
	NonMembershipModEqAlpha2Y       *big.Int `gnark:",public"`
	NonMembershipHashToPrimeChallenge *big.Int `gnark:",public"`
	NonMembershipOriginalElement     *big.Int `gnark:",public"`
	NonMembershipHashedPrime         *big.Int `gnark:",public"`

	// Membership private witness
	MembershipElement            *big.Int
	MembershipRandomness         *big.Int
	MembershipRandomnessQ        *big.Int
	MembershipRootSE             *big.Int
	MembershipRootSR             *big.Int
	MembershipRootChallenge      *big.Int
	MembershipModEqSE            *big.Int
	MembershipModEqSR            *big.Int
	MembershipModEqSRQ           *big.Int
	MembershipModEqChallenge     *big.Int
	MembershipBitDecomposition   []*big.Int

	// Non-membership private witness
	NonMembershipElement             *big.Int
	NonMembershipRandomness          *big.Int
	NonMembershipRandomnessQ        *big.Int
	NonMembershipCoprimeSE           *big.Int
	NonMembershipCoprimeSR           *big.Int
	NonMembershipCoprimeChallenge   *big.Int
	NonMembershipModEqSE             *big.Int
	NonMembershipModEqSR             *big.Int
	NonMembershipModEqSRQ            *big.Int
	NonMembershipModEqChallenge      *big.Int
	NonMembershipBitDecomposition    []*big.Int
}

// NewCombinedWitness is deprecated - use frontend.NewWitness(assignment, curveID) directly
// or let the test helper handle witness creation automatically

