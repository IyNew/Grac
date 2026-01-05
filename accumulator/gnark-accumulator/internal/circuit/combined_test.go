package circuit

import (
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/test"
)

// TestCombinedCircuit tests the combined membership and non-membership circuit
func TestCombinedCircuit(t *testing.T) {
	// Use Rust test data for parameters
	rustData := NewRustTestData()
	hashToPrimeBits := rustData.HashToPrimeBits // 254
	fieldSizeBits := rustData.FieldSizeBits     // 255

	// Generate mock generators
	integerCommitmentG := big.NewInt(2)
	integerCommitmentH := big.NewInt(3)
	var pedersenCommitmentG, pedersenCommitmentH bn254.G1Affine
	pedersenCommitmentG.X.SetOne()
	pedersenCommitmentG.Y.SetUint64(2)
	pedersenCommitmentH.X.SetUint64(2)
	pedersenCommitmentH.Y.SetOne()
	accumulatorG := big.NewInt(5)

	// Create circuit
	circuit := NewCombinedCircuit(
		hashToPrimeBits, fieldSizeBits,
		integerCommitmentG, integerCommitmentH,
		&pedersenCommitmentG, &pedersenCommitmentH,
		accumulatorG,
	)

	// Create assignment with mock data - assignment must match circuit structure
	assignment := createMockCombinedAssignment()

	// Test circuit compilation and solving
	assert := test.NewAssert(t)
	// Use CheckCircuit which is the recommended way
	assert.CheckCircuit(circuit, test.WithValidAssignment(assignment))
}

// TestCombinedCircuitSetup tests the setup process for the combined circuit
func TestCombinedCircuitSetup(t *testing.T) {
	// Setup circuit parameters
	hashToPrimeBits := 254
	fieldSizeBits := 255

	// Generate mock generators
	integerCommitmentG := big.NewInt(2)
	integerCommitmentH := big.NewInt(3)
	var pedersenCommitmentG, pedersenCommitmentH bn254.G1Affine
	pedersenCommitmentG.X.SetOne()
	pedersenCommitmentG.Y.SetUint64(2)
	pedersenCommitmentH.X.SetUint64(2)
	pedersenCommitmentH.Y.SetOne()
	accumulatorG := big.NewInt(5)

	// Create circuit
	circuit := NewCombinedCircuit(
		hashToPrimeBits, fieldSizeBits,
		integerCommitmentG, integerCommitmentH,
		&pedersenCommitmentG, &pedersenCommitmentH,
		accumulatorG,
	)

	// Test that circuit can be compiled (setup requires SRS which is handled by test helper)
	assert := test.NewAssert(t)
	assignment := createMockCombinedAssignment()
	
	// The test helper handles compilation and setup automatically
	assert.ProverSucceeded(circuit, assignment)
	
	t.Logf("Circuit setup and compilation successful")
}

// TestCombinedCircuitProveAndVerify tests the full prove and verify cycle
// This uses the test helper which handles all the setup automatically
func TestCombinedCircuitProveAndVerify(t *testing.T) {
	// Setup circuit parameters
	hashToPrimeBits := 254
	fieldSizeBits := 255

	// Generate mock generators
	integerCommitmentG := big.NewInt(2)
	integerCommitmentH := big.NewInt(3)
	var pedersenCommitmentG, pedersenCommitmentH bn254.G1Affine
	pedersenCommitmentG.X.SetOne()
	pedersenCommitmentG.Y.SetUint64(2)
	pedersenCommitmentH.X.SetUint64(2)
	pedersenCommitmentH.Y.SetOne()
	accumulatorG := big.NewInt(5)

	// Create circuit
	circuit := NewCombinedCircuit(
		hashToPrimeBits, fieldSizeBits,
		integerCommitmentG, integerCommitmentH,
		&pedersenCommitmentG, &pedersenCommitmentH,
		accumulatorG,
	)

	// Create assignment
	assignment := createMockCombinedAssignment()

	// Use test helper which handles compilation, setup, proving, and verification
	assert := test.NewAssert(t)
	assert.ProverSucceeded(circuit, assignment)

	t.Logf("Proof generation and verification successful")
}

// createMockCombinedAssignment creates mock assignment data for testing
// Returns a CombinedCircuit with concrete values that match the circuit structure
// NOTE: This uses base values from the Rust implementation (cpsnarks-set), but the proof
// components (alpha1, se, sr, challenges) are generated during the interactive protocol
// and cannot be directly copied. For a fully working test, these would need to be
// computed by actually running the protocol.
func createMockCombinedAssignment() *CombinedCircuit {
	// Use Rust test data helper
	rustData := NewRustTestData()

	// Shared values - these would come from actual accumulator and commitments
	// For now using placeholder values that would need to be computed from actual protocol
	accumulatorValue, _ := new(big.Int).SetString("123456789012345678901234567890123456789012345678901234567890", 10)
	integerCommitment, _ := new(big.Int).SetString("98765432109876543210987654321098765432109876543210987654321", 10)
	pedersenCommitmentX := big.NewInt(12345)
	pedersenCommitmentY := big.NewInt(67890)

	// Membership values - using Rust test data
	membershipElement := rustData.GetMembershipElement() // 2^254 - 245
	membershipRandomness := rustData.GetRandomness()     // 5
	membershipRandomnessQ := rustData.GetRandomness()    // 5
	membershipRootAlpha1, _ := new(big.Int).SetString("1111111111111111111111111111111111111111111111", 10)
	membershipRootSE, _ := new(big.Int).SetString("2222222222222222222222222222222222222222222222", 10)
	membershipRootSR, _ := new(big.Int).SetString("3333333333333333333333333333333333333333333333", 10)
	membershipRootChallenge, _ := new(big.Int).SetString("4444444444444444444444444444444444444444444444", 10)
	membershipModEqAlpha1X := big.NewInt(11111)
	membershipModEqAlpha1Y := big.NewInt(22222)
	membershipModEqAlpha2X := big.NewInt(33333)
	membershipModEqAlpha2Y := big.NewInt(44444)
	membershipModEqSE, _ := new(big.Int).SetString("5555555555555555555555555555555555555555", 10)
	membershipModEqSR, _ := new(big.Int).SetString("6666666666666666666666666666666666666666", 10)
	membershipModEqSRQ, _ := new(big.Int).SetString("7777777777777777777777777777777777777777", 10)
	membershipModEqChallenge, _ := new(big.Int).SetString("8888888888888888888888888888888888888888", 10)
	membershipHashToPrimeChallenge, _ := new(big.Int).SetString("9999999999999999999999999999999999999999", 10)
	membershipOriginalElement, _ := new(big.Int).SetString("10000000000000000000000000000000000000000", 10)
	membershipHashedPrime, _ := new(big.Int).SetString("11000000000000000000000000000000000000000", 10)

	// Create membership bit decomposition (254 bits)
	membershipBitDecomposition := make([]*big.Int, 254)
	for i := 0; i < 254; i++ {
		membershipBitDecomposition[i] = big.NewInt(int64(i % 2))
	}

	// Non-membership values - using Rust test data
	nonMembershipElement := rustData.GetNonMembershipElement() // 2^254 - 245
	nonMembershipRandomness := rustData.GetRandomness()         // 5
	nonMembershipRandomnessQ := rustData.GetRandomness()        // 5
	nonMembershipCoprimeAlpha1, _ := new(big.Int).SetString("1212121212121212121212121212121212121212121212", 10)
	nonMembershipCoprimeSE, _ := new(big.Int).SetString("2323232323232323232323232323232323232323232323", 10)
	nonMembershipCoprimeSR, _ := new(big.Int).SetString("3434343434343434343434343434343434343434343434", 10)
	nonMembershipCoprimeChallenge, _ := new(big.Int).SetString("4545454545454545454545454545454545454545454545", 10)
	nonMembershipModEqAlpha1X := big.NewInt(55555)
	nonMembershipModEqAlpha1Y := big.NewInt(66666)
	nonMembershipModEqAlpha2X := big.NewInt(77777)
	nonMembershipModEqAlpha2Y := big.NewInt(88888)
	nonMembershipModEqSE, _ := new(big.Int).SetString("9999999999999999999999999999999999999999", 10)
	nonMembershipModEqSR, _ := new(big.Int).SetString("1010101010101010101010101010101010101010", 10)
	nonMembershipModEqSRQ, _ := new(big.Int).SetString("1111111111111111111111111111111111111111", 10)
	nonMembershipModEqChallenge, _ := new(big.Int).SetString("1212121212121212121212121212121212121212", 10)
	nonMembershipHashToPrimeChallenge, _ := new(big.Int).SetString("1313131313131313131313131313131313131313", 10)
	nonMembershipOriginalElement, _ := new(big.Int).SetString("1414141414141414141414141414141414141414", 10)
	nonMembershipHashedPrime, _ := new(big.Int).SetString("1515151515151515151515151515151515151515", 10)

	// Create non-membership bit decomposition (254 bits)
	nonMembershipBitDecomposition := make([]*big.Int, 254)
	for i := 0; i < 254; i++ {
		nonMembershipBitDecomposition[i] = big.NewInt(int64((i + 1) % 2))
	}

	// Create a CombinedCircuit with concrete values (assignment)
	// Parameters matching Rust
	hashToPrimeBits := rustData.HashToPrimeBits // 254
	fieldSizeBits := rustData.FieldSizeBits     // 255
	integerCommitmentG := big.NewInt(2)
	integerCommitmentH := big.NewInt(3)
	// PedersenCommitmentG and H are frontend.Variable (scalars), not curve points
	// These would be actual curve points in the real protocol
	pedersenCommitmentG := big.NewInt(10)
	pedersenCommitmentH := big.NewInt(11)
	accumulatorG := big.NewInt(5)

	return &CombinedCircuit{
		HashToPrimeBits:    hashToPrimeBits,
		FieldSizeBits:      fieldSizeBits,
		IntegerCommitmentG: frontend.Variable(integerCommitmentG),
		IntegerCommitmentH: frontend.Variable(integerCommitmentH),
		PedersenCommitmentG: frontend.Variable(pedersenCommitmentG),
		PedersenCommitmentH: frontend.Variable(pedersenCommitmentH),
		AccumulatorG:       frontend.Variable(accumulatorG),
		// Public inputs
		AccumulatorValue:    frontend.Variable(accumulatorValue),
		IntegerCommitment:   frontend.Variable(integerCommitment),
		PedersenCommitmentX: frontend.Variable(pedersenCommitmentX),
		PedersenCommitmentY: frontend.Variable(pedersenCommitmentY),
		// Membership
		MembershipRootAlpha1:          frontend.Variable(membershipRootAlpha1),
		MembershipModEqAlpha1X:       frontend.Variable(membershipModEqAlpha1X),
		MembershipModEqAlpha1Y:       frontend.Variable(membershipModEqAlpha1Y),
		MembershipModEqAlpha2X:       frontend.Variable(membershipModEqAlpha2X),
		MembershipModEqAlpha2Y:       frontend.Variable(membershipModEqAlpha2Y),
		MembershipHashToPrimeChallenge: frontend.Variable(membershipHashToPrimeChallenge),
		MembershipOriginalElement:     frontend.Variable(membershipOriginalElement),
		MembershipHashedPrime:         frontend.Variable(membershipHashedPrime),
		MembershipElement:             frontend.Variable(membershipElement),
		MembershipRandomness:          frontend.Variable(membershipRandomness),
		MembershipRandomnessQ:         frontend.Variable(membershipRandomnessQ),
		MembershipRootSE:              frontend.Variable(membershipRootSE),
		MembershipRootSR:              frontend.Variable(membershipRootSR),
		MembershipRootChallenge:       frontend.Variable(membershipRootChallenge),
		MembershipModEqSE:             frontend.Variable(membershipModEqSE),
		MembershipModEqSR:             frontend.Variable(membershipModEqSR),
		MembershipModEqSRQ:            frontend.Variable(membershipModEqSRQ),
		MembershipModEqChallenge:      frontend.Variable(membershipModEqChallenge),
		MembershipBitDecomposition:    convertToFrontendVars(membershipBitDecomposition),
		// Non-membership
		NonMembershipCoprimeAlpha1:      frontend.Variable(nonMembershipCoprimeAlpha1),
		NonMembershipModEqAlpha1X:       frontend.Variable(nonMembershipModEqAlpha1X),
		NonMembershipModEqAlpha1Y:       frontend.Variable(nonMembershipModEqAlpha1Y),
		NonMembershipModEqAlpha2X:       frontend.Variable(nonMembershipModEqAlpha2X),
		NonMembershipModEqAlpha2Y:       frontend.Variable(nonMembershipModEqAlpha2Y),
		NonMembershipHashToPrimeChallenge: frontend.Variable(nonMembershipHashToPrimeChallenge),
		NonMembershipOriginalElement:     frontend.Variable(nonMembershipOriginalElement),
		NonMembershipHashedPrime:         frontend.Variable(nonMembershipHashedPrime),
		NonMembershipElement:             frontend.Variable(nonMembershipElement),
		NonMembershipRandomness:          frontend.Variable(nonMembershipRandomness),
		NonMembershipRandomnessQ:         frontend.Variable(nonMembershipRandomnessQ),
		NonMembershipCoprimeSE:           frontend.Variable(nonMembershipCoprimeSE),
		NonMembershipCoprimeSR:           frontend.Variable(nonMembershipCoprimeSR),
		NonMembershipCoprimeChallenge:    frontend.Variable(nonMembershipCoprimeChallenge),
		NonMembershipModEqSE:             frontend.Variable(nonMembershipModEqSE),
		NonMembershipModEqSR:             frontend.Variable(nonMembershipModEqSR),
		NonMembershipModEqSRQ:            frontend.Variable(nonMembershipModEqSRQ),
		NonMembershipModEqChallenge:      frontend.Variable(nonMembershipModEqChallenge),
		NonMembershipBitDecomposition:    convertToFrontendVars(nonMembershipBitDecomposition),
	}
}

// convertToFrontendVars converts []*big.Int to []frontend.Variable
func convertToFrontendVars(bits []*big.Int) []frontend.Variable {
	result := make([]frontend.Variable, len(bits))
	for i, b := range bits {
		result[i] = frontend.Variable(b)
	}
	return result
}

