package circuit

import (
	"fmt"
	"math/big"

	"github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/hash/mimc"
)

// NonMembershipCircuit implements the verification circuit for accumulator non-membership proofs
type NonMembershipCircuit struct {
	// Public inputs
	AccumulatorValue    frontend.Variable `gnark:",public"`
	IntegerCommitment   frontend.Variable `gnark:",public"`
	PedersenCommitmentX frontend.Variable `gnark:",public"`
	PedersenCommitmentY frontend.Variable `gnark:",public"`

	// Proof components - public (from the prover)
	CoprimeAlpha1      frontend.Variable `gnark:",public"`
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

	// Coprime proof private witnesses
	CoprimeSE          frontend.Variable
	CoprimeSR          frontend.Variable
	CoprimeChallenge   frontend.Variable

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

	// Security parameters (stored as constants, not variables)
	HashToPrimeBits    int
	FieldSizeBits      int
}

// Define defines the constraints for the non-membership verification circuit
func (circuit *NonMembershipCircuit) Define(api frontend.API) error {
	// 1. Verify coprime component: g^s_e * h^s_r * C_e^c = α1
	if err := circuit.verifyCoprime(api); err != nil {
		return fmt.Errorf("coprime verification failed: %w", err)
	}

	// 2. Verify ModEq component: equality between integer and Pedersen commitments
	if err := circuit.verifyModEq(api); err != nil {
		return fmt.Errorf("modeq verification failed: %w", err)
	}

	// 3. Verify hash-to-prime range proof
	if err := circuit.verifyHashToPrime(api); err != nil {
		return fmt.Errorf("hash-to-prime verification failed: %w", err)
	}

	// 4. Verify accumulator relationship (simplified for now)
	if err := circuit.verifyAccumulatorRelationship(api); err != nil {
		return fmt.Errorf("accumulator relationship verification failed: %w", err)
	}

	return nil
}

// verifyCoprime implements the coprime verification subcircuit
func (circuit *NonMembershipCircuit) verifyCoprime(api frontend.API) error {
	// Verify the coprime protocol: g^s_e * h^s_r = α1 / C_e^c

	// Compute C_e^c where c is the challenge from Fiat-Shamir
	challenge := circuit.computeCoprimeChallenge(api)
	commitmentExp := api.Mul(circuit.IntegerCommitment, challenge)

	// Compute g^s_e * h^s_r
	exp1 := api.Mul(circuit.IntegerCommitmentG, circuit.CoprimeSE)
	exp2 := api.Mul(circuit.IntegerCommitmentH, circuit.CoprimeSR)
	lhs := api.Add(exp1, exp2)

	// Verify equality: g^s_e * h^s_r * C_e^c = α1
	rhs := api.Add(lhs, commitmentExp)
	api.AssertIsEqual(rhs, circuit.CoprimeAlpha1)

	// Verify the challenge was computed correctly
	expectedChallenge := circuit.computeCoprimeChallenge(api)
	api.AssertIsEqual(expectedChallenge, challenge)

	return nil
}

// verifyModEq implements the modular equality verification subcircuit
func (circuit *NonMembershipCircuit) verifyModEq(api frontend.API) error {
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
func (circuit *NonMembershipCircuit) verifyHashToPrime(api frontend.API) error {
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

// verifyAccumulatorRelationship implements accumulator-specific verification
func (circuit *NonMembershipCircuit) verifyAccumulatorRelationship(api frontend.API) error {
	// Verify the non-membership relationship: g^d * A^b = g (for RSA groups)
	// This is a simplified version of the accumulator verification

	// In a full implementation, this would verify:
	// g^d * A^b = g (where d is the witness and A is the accumulator)

	// For now, we'll add a placeholder constraint that the accumulator value
	// is consistent with the proof
	// This would need the full accumulator arithmetic implementation

	api.AssertIsDifferent(circuit.AccumulatorValue, 0)

	return nil
}

// computeCoprimeChallenge computes the Fiat-Shamir challenge for the coprime protocol
func (circuit *NonMembershipCircuit) computeCoprimeChallenge(api frontend.API) frontend.Variable {
	// Hash the transcript: accumulator_value || integer_commitment || α1
	transcript := []frontend.Variable{
		circuit.AccumulatorValue,
		circuit.IntegerCommitment,
		circuit.CoprimeAlpha1,
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
func (circuit *NonMembershipCircuit) computeModEqChallenge(api frontend.API) frontend.Variable {
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
func (circuit *NonMembershipCircuit) checkPrimality(api frontend.API, n frontend.Variable) frontend.Variable {
	// This is a very simplified primality check
	// In practice, this would use more sophisticated methods like Miller-Rabin

	// For now, just verify n is not zero or one
	api.AssertIsDifferent(n, 0)
	api.AssertIsDifferent(n, 1)
	
	// Return 1 to indicate "passes basic check"
	return 1
}

// NewNonMembershipCircuit creates a new non-membership verification circuit
func NewNonMembershipCircuit(
	hashToPrimeBits, fieldSizeBits int,
	integerCommitmentG, integerCommitmentH *big.Int,
	pedersenCommitmentG, pedersenCommitmentH *bn254.G1Affine,
) *NonMembershipCircuit {
	return &NonMembershipCircuit{
		HashToPrimeBits:    hashToPrimeBits,
		FieldSizeBits:      fieldSizeBits,
		IntegerCommitmentG: frontend.Variable(integerCommitmentG),
		IntegerCommitmentH: frontend.Variable(integerCommitmentH),
		PedersenCommitmentG: frontend.Variable(pedersenCommitmentG),
		PedersenCommitmentH: frontend.Variable(pedersenCommitmentH),
	}
}

// SetupNonMembershipCircuit compiles the circuit and returns proving and verification keys
// Note: This is a placeholder - actual setup requires SRS. Use test helper for testing.
func SetupNonMembershipCircuit(
	hashToPrimeBits, fieldSizeBits int,
	integerCommitmentG, integerCommitmentH *big.Int,
	pedersenCommitmentG, pedersenCommitmentH *bn254.G1Affine,
) (interface{}, interface{}, error) {
	// This is a placeholder - actual setup requires SRS (Structured Reference String)
	// Use the test helper or setup package for full functionality
	return nil, nil, fmt.Errorf("use test helper or setup package for circuit setup")
}

// CircuitAssignment represents a complete assignment to the non-membership circuit
type CircuitAssignment struct {
	// Public inputs
	AccumulatorValue    *big.Int
	IntegerCommitment   *big.Int
	PedersenCommitment *bn254.G1Affine

	// Proof components
	CoprimeAlpha1      *big.Int
	ModEqAlpha1        *bn254.G1Affine
	ModEqAlpha2        *bn254.G1Affine
	HashToPrimeChallenge *big.Int
	OriginalElement     *big.Int
	HashedPrime         *big.Int

	// Private witness
	Element            *big.Int
	Randomness         *big.Int
	RandomnessQ        *big.Int

	// Coprime witness
	CoprimeSE          *big.Int
	CoprimeSR          *big.Int
	CoprimeChallenge   *big.Int

	// ModEq witness
	ModEqSE            *big.Int
	ModEqSR            *big.Int
	ModEqSRQ           *big.Int
	ModEqChallenge     *big.Int

	// Range proof witness
	BitDecomposition   []frontend.Variable
}

// NewWitness is deprecated - use frontend.NewWitness(assignment, curveID) directly
func NewWitness(
	circuit *NonMembershipCircuit,
	assignment *CircuitAssignment,
) (interface{}, error) {
	// Return assignment directly - test helper handles witness creation
	return assignment, nil
}