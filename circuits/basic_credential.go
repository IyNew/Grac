// circuits/basic_credential.go
package circuits

import (
	"github.com/consensys/gnark/frontend"
	"github.com/research/gr2ac-poc/crypto"
)

// BasicCredentialCircuit proves possession of an attribute
type BasicCredentialCircuit struct {
	// Public inputs
	AccumulatorState frontend.Variable `gnark:",public"`
	AttributeID      frontend.Variable `gnark:",public"`

	// Private inputs (witness)
	SecretKey        frontend.Variable
	Index            frontend.Variable
	ControlP         frontend.Variable
	ControlNext      frontend.Variable
	MembershipWitness frontend.Variable
}

// Define constraints for the basic credential circuit
func (circuit *BasicCredentialCircuit) Define(api frontend.API) error {
	// Initialize ZK hash function
	hasher := crypto.NewZKHash(api)

	// Constraint 1: H(sk | idx) = CT.P
	computedP := hasher.HashTwo(circuit.SecretKey, circuit.Index)
	api.AssertIsEqual(computedP, circuit.ControlP)

	// Constraint 2: Enc(sk, AttID) = CT.Next
	// For ZK efficiency, we use H(sk | AttID) as a simplified encryption
	computedNext := hasher.HashTwo(circuit.SecretKey, circuit.AttributeID)
	api.AssertIsEqual(computedNext, circuit.ControlNext)

	// Constraint 3: H(CT) ∈ accCT (membership proof)
	// Compute H(CT.P | CT.Next)
	ctHash := hasher.HashTwo(circuit.ControlP, circuit.ControlNext)

	// Verify membership in accumulator
	// This is simplified - in production, use proper accumulator circuit
	// For now, we use H(ctHash | membershipWitness) = accumulatorState
	memberResult := hasher.HashTwo(ctHash, circuit.MembershipWitness)
	api.AssertIsEqual(memberResult, circuit.AccumulatorState)

	return nil
}