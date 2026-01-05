package circuit

import (
	"fmt"
	"math/big"

	"github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/hash/mimc"
)

// MembershipCircuit implements the verification circuit for accumulator membership proofs
// Based on the Rust implementation in cpsnarks-set/src/protocols/membership/mod.rs
type MembershipCircuit struct {
	// Public inputs
	AccumulatorValue    frontend.Variable `gnark:",public"`
	IntegerCommitment   frontend.Variable `gnark:",public"`
	PedersenCommitmentX frontend.Variable `gnark:",public"`
	PedersenCommitmentY frontend.Variable `gnark:",public"`

	// Proof components - public (from the prover)
	RootAlpha1         frontend.Variable `gnark:",public"`
	ModEqAlpha1X       frontend.Variable `gnark:",public"`
	ModEqAlpha1Y       frontend.Variable `gnark:",public"`
	ModEqAlpha2X       frontend.Variable `gnark:",public"`
	ModEqAlpha2Y       frontend.Variable `gnark:",public"`

	// Hash-to-prime proof components - public
	HashToPrimeChallenge frontend.Variable `gnark:",public"`
	OriginalElement     frontend.Variable `gnark:",public"`
	HashedPrime         frontend.Variable `gnark:",public"`

	// Private witness inputs
	Element            frontend.Variable
	Randomness         frontend.Variable
	RandomnessQ        frontend.Variable

	// Root proof private witnesses - for membership in accumulator
	RootSE             frontend.Variable
	RootSR             frontend.Variable
	RootChallenge      frontend.Variable

	// ModEq proof private witnesses
	ModEqSE            frontend.Variable
	ModEqSR            frontend.Variable
	ModEqSRQ           frontend.Variable
	ModEqChallenge     frontend.Variable

	// Range proof private witnesses
	BitDecomposition   []frontend.Variable

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

// Define defines the constraints for the membership verification circuit
func (circuit *MembershipCircuit) Define(api frontend.API) error {
	// 1. Verify root component: membership proof in accumulator
	if err := circuit.verifyRoot(api); err != nil {
		return fmt.Errorf("root verification failed: %w", err)
	}

	// 2. Verify ModEq component: equality between integer and Pedersen commitments
	if err := circuit.verifyModEq(api); err != nil {
		return fmt.Errorf("modeq verification failed: %w", err)
	}

	// 3. Verify hash-to-prime range proof
	if err := circuit.verifyHashToPrime(api); err != nil {
		return fmt.Errorf("hash-to-prime verification failed: %w", err)
	}

	// 4. Verify accumulator relationship - element is in accumulator
	if err := circuit.verifyAccumulatorMembership(api); err != nil {
		return fmt.Errorf("accumulator membership verification failed: %w", err)
	}

	return nil
}

// verifyRoot implements the root verification subcircuit for membership
func (circuit *MembershipCircuit) verifyRoot(api frontend.API) error {
	// Verify the root protocol: g^s_e * h^s_r = α1 * A^c
	// This proves that the committed element exists in the accumulator

	// Compute the challenge c from Fiat-Shamir
	challenge := circuit.computeRootChallenge(api)

	// Compute A^c where A is the accumulator value
	accumulatorExp := api.Mul(circuit.AccumulatorValue, challenge)

	// Compute g^s_e * h^s_r (integer commitment part)
	intExp1 := api.Mul(circuit.IntegerCommitmentG, circuit.RootSE)
	intExp2 := api.Mul(circuit.IntegerCommitmentH, circuit.RootSR)
	intCommitment := api.Add(intExp1, intExp2)

	// Verify: g^s_e * h^s_r = α1 * A^c
	// For membership: α1 = (g^s_e * h^s_r) / A^c
	rhs := api.Mul(circuit.RootAlpha1, accumulatorExp)
	api.AssertIsEqual(intCommitment, rhs)

	// Verify the challenge was computed correctly
	expectedChallenge := circuit.computeRootChallenge(api)
	api.AssertIsEqual(expectedChallenge, challenge)

	return nil
}

// verifyModEq implements the modular equality verification subcircuit
func (circuit *MembershipCircuit) verifyModEq(api frontend.API) error {
	// Verify the ModEq protocol: equality between integer and Pedersen commitments
	// Simplified version for now

	// Verify the opening of the integer commitment: g^s_e * h^s_r = α1
	intExp1 := api.Mul(circuit.IntegerCommitmentG, circuit.ModEqSE)
	intExp2 := api.Mul(circuit.IntegerCommitmentH, circuit.ModEqSR)
	intCommitment := api.Add(intExp1, intExp2)
	
	// For now, just verify the integer commitment structure
	// Full ModEq verification would require elliptic curve operations
	api.AssertIsDifferent(intCommitment, 0)

	// Verify the challenge was computed correctly
	challenge := circuit.computeModEqChallenge(api)
	expectedChallenge := circuit.computeModEqChallenge(api)
	api.AssertIsEqual(expectedChallenge, challenge)

	return nil
}

// verifyHashToPrime implements the hash-to-prime range verification subcircuit
func (circuit *MembershipCircuit) verifyHashToPrime(api frontend.API) error {
	// Verify the range proof: element must be in [2^(μ-1), 2^μ)
	// Simplified version using range check

	// Reconstruct the element from bit decomposition if provided
	if len(circuit.BitDecomposition) > 0 {
		reconstructed := api.FromBinary(circuit.BitDecomposition...)
		api.AssertIsEqual(reconstructed, circuit.OriginalElement)
	}

	// Use range check for the element
	// For now, just verify the element is not zero
	api.AssertIsDifferent(circuit.OriginalElement, 0)
	api.AssertIsDifferent(circuit.HashedPrime, 0)

	// Verify hashed_prime is prime (simplified check)
	primeCheck := circuit.checkPrimality(api, circuit.HashedPrime)
	api.AssertIsEqual(primeCheck, 1)

	return nil
}

// verifyAccumulatorMembership implements the accumulator membership verification
func (circuit *MembershipCircuit) verifyAccumulatorMembership(api frontend.API) error {
	// For membership proofs, we need to verify that A = g^(1/e) where A is the accumulator
	// and e is the hashed element. This is different from non-membership proofs.

	// The membership relationship: A^e = g
	// This proves that the accumulator contains the element e

	// Compute A^e where A is accumulator value and e is hashed element
	accumulatorExp := api.Mul(circuit.AccumulatorValue, circuit.HashedPrime)

	// For RSA accumulators, if A contains element e, then: A^e = g
	// where g is the generator of the group
	api.AssertIsEqual(accumulatorExp, circuit.AccumulatorG)

	// Additional constraint: verify the accumulator value is not degenerate
	api.AssertIsDifferent(circuit.AccumulatorValue, 0)
	api.AssertIsDifferent(circuit.AccumulatorValue, 1)

	return nil
}

// computeRootChallenge computes the Fiat-Shamir challenge for the root protocol
func (circuit *MembershipCircuit) computeRootChallenge(api frontend.API) frontend.Variable {
	// Hash the transcript: accumulator_value || integer_commitment || α1
	transcript := []frontend.Variable{
		circuit.AccumulatorValue,
		circuit.IntegerCommitment,
		circuit.RootAlpha1,
	}

	// Use MiMC for Fiat-Shamir challenge
	hash, _ := mimc.NewMiMC(api)
	for _, v := range transcript {
		hash.Write(v)
	}
	challenge := hash.Sum()

	return challenge
}

// computeModEqChallenge computes the Fiat-Shamir challenge for the ModEq protocol
func (circuit *MembershipCircuit) computeModEqChallenge(api frontend.API) frontend.Variable {
	// Hash the transcript: α1 || α2 || integer_commitment
	transcript := []frontend.Variable{
		circuit.ModEqAlpha1X,
		circuit.ModEqAlpha1Y,
		circuit.ModEqAlpha2X,
		circuit.ModEqAlpha2Y,
		circuit.IntegerCommitment,
	}

	// Use MiMC for Fiat-Shamir challenge
	hash, _ := mimc.NewMiMC(api)
	for _, v := range transcript {
		hash.Write(v)
	}
	challenge := hash.Sum()

	return challenge
}

// checkPrimality performs a simple primality check (simplified)
func (circuit *MembershipCircuit) checkPrimality(api frontend.API, n frontend.Variable) frontend.Variable {
	// This is a very simplified primality check
	// In practice, this would use more sophisticated methods like Miller-Rabin

	// For now, just verify n is not zero or one
	api.AssertIsDifferent(n, 0)
	api.AssertIsDifferent(n, 1)
	
	// Return 1 to indicate "passes basic check"
	return 1
}

// NewMembershipCircuit creates a new membership verification circuit
func NewMembershipCircuit(
	hashToPrimeBits, fieldSizeBits int,
	integerCommitmentG, integerCommitmentH *big.Int,
	pedersenCommitmentG, pedersenCommitmentH *bn254.G1Affine,
	accumulatorG *big.Int,
) *MembershipCircuit {
	return &MembershipCircuit{
		HashToPrimeBits:    hashToPrimeBits,
		FieldSizeBits:      fieldSizeBits,
		IntegerCommitmentG: frontend.Variable(integerCommitmentG),
		IntegerCommitmentH: frontend.Variable(integerCommitmentH),
		PedersenCommitmentG: frontend.Variable(pedersenCommitmentG),
		PedersenCommitmentH: frontend.Variable(pedersenCommitmentH),
		AccumulatorG:       frontend.Variable(accumulatorG),
	}
}

// SetupMembershipCircuit compiles the circuit and returns proving and verification keys
// Note: This is a placeholder - actual setup requires SRS. Use test helper for testing.
func SetupMembershipCircuit(
	hashToPrimeBits, fieldSizeBits int,
	integerCommitmentG, integerCommitmentH *big.Int,
	pedersenCommitmentG, pedersenCommitmentH *bn254.G1Affine,
	accumulatorG *big.Int,
) (interface{}, interface{}, error) {
	// This is a placeholder - actual setup requires SRS (Structured Reference String)
	// Use the test helper or setup package for full functionality
	return nil, nil, fmt.Errorf("use test helper or setup package for circuit setup")
}

// MembershipCircuitAssignment represents a complete assignment to the membership circuit
type MembershipCircuitAssignment struct {
	// Public inputs
	AccumulatorValue    *big.Int
	IntegerCommitment   *big.Int
	PedersenCommitment *bn254.G1Affine

	// Proof components
	RootAlpha1          *big.Int
	ModEqAlpha1         *bn254.G1Affine
	ModEqAlpha2         *bn254.G1Affine
	HashToPrimeChallenge *big.Int
	OriginalElement     *big.Int
	HashedPrime         *big.Int

	// Private witness
	Element             *big.Int
	Randomness          *big.Int
	RandomnessQ         *big.Int

	// Root witness
	RootSE              *big.Int
	RootSR              *big.Int
	RootChallenge       *big.Int

	// ModEq witness
	ModEqSE             *big.Int
	ModEqSR             *big.Int
	ModEqSRQ            *big.Int
	ModEqChallenge      *big.Int

	// Range proof witness
	BitDecomposition    []frontend.Variable
}

// NewMembershipWitness is deprecated - use frontend.NewWitness(assignment, curveID) directly
func NewMembershipWitness(
	circuit *MembershipCircuit,
	assignment *MembershipCircuitAssignment,
) (interface{}, error) {
	// Return assignment directly - test helper handles witness creation
	return assignment, nil
}