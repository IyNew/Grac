package circuit

import (
	"fmt"
	"math/big"
)

// RustTestData contains test data extracted from the Rust cpsnarks-set implementation
// These values are used in the Rust benchmarks and tests
type RustTestData struct {
	// Large primes used in Rust tests
	LargePrimes []*big.Int

	// Computed values matching Rust implementation
	MembershipValue      *big.Int // 2^254 - 245
	NonMembershipValue   *big.Int // 2^254 - 245
	Randomness           *big.Int // 5 (from Rust: Integer::from(5))
	
	// Parameters matching Rust
	HashToPrimeBits      int // 254 (from 2 * security_level - 2, where security_level = 128)
	FieldSizeBits        int // 255 (from 2 * security_level, where security_level = 128)
	SecurityLevel        int // 128
}

// NewRustTestData creates test data matching the Rust implementation
func NewRustTestData() *RustTestData {
	// Large primes from Rust: const LARGE_PRIMES: [u64; 3] = [
	//     12_702_637_924_034_044_211,
	//     378_373_571_372_703_133,
	//     8_640_171_141_336_142_787,
	// ];
	largePrimes := []*big.Int{
		new(big.Int),
		new(big.Int),
		new(big.Int),
	}
	largePrimes[0].SetString("12702637924034044211", 10)
	largePrimes[1].SetString("378373571372703133", 10)
	largePrimes[2].SetString("8640171141336142787", 10)

	// Parameters from Rust: hash_to_prime_bits = 254, field_size_bits = 255 (for security_level = 128)
	hashToPrimeBits := 254
	fieldSizeBits := 255
	securityLevel := 128

	// Compute value = 2^254 - 245 (matching Rust: Integer::u_pow_u(2, 254) - 245)
	two := big.NewInt(2)
	valueBase := new(big.Int).Exp(two, big.NewInt(int64(hashToPrimeBits)), nil)
	value := new(big.Int).Sub(valueBase, big.NewInt(245))

	// Randomness from Rust: Integer::from(5)
	randomness := big.NewInt(5)

	return &RustTestData{
		LargePrimes:         largePrimes,
		MembershipValue:      new(big.Int).Set(value),
		NonMembershipValue:   new(big.Int).Set(value),
		Randomness:           randomness,
		HashToPrimeBits:      hashToPrimeBits,
		FieldSizeBits:        fieldSizeBits,
		SecurityLevel:        securityLevel,
	}
}

// GetMembershipElement returns the membership element value (2^254 - 245)
func (r *RustTestData) GetMembershipElement() *big.Int {
	return new(big.Int).Set(r.MembershipValue)
}

// GetNonMembershipElement returns the non-membership element value (2^254 - 245)
func (r *RustTestData) GetNonMembershipElement() *big.Int {
	return new(big.Int).Set(r.NonMembershipValue)
}

// GetRandomness returns the randomness value (5)
func (r *RustTestData) GetRandomness() *big.Int {
	return new(big.Int).Set(r.Randomness)
}

// String returns a string representation of the test data
func (r *RustTestData) String() string {
	return fmt.Sprintf("RustTestData{HashToPrimeBits: %d, FieldSizeBits: %d, SecurityLevel: %d, Value: %s, Randomness: %s}",
		r.HashToPrimeBits, r.FieldSizeBits, r.SecurityLevel, r.MembershipValue.String(), r.Randomness.String())
}

