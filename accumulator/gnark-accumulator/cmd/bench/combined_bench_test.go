package main

import (
	"math/big"
	"testing"
	"time"

	"github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark/backend/plonk"
	"github.com/consensys/gnark/frontend"
	"github.com/grac-enhanced/accumulator/gnark-accumulator/internal/circuit"
)

// BenchmarkCombinedCircuitSetup benchmarks the setup phase
func BenchmarkCombinedCircuitSetup(b *testing.B) {
	hashToPrimeBits := 254
	fieldSizeBits := 255
	integerCommitmentG := big.NewInt(2)
	integerCommitmentH := big.NewInt(3)
	pedersenCommitmentG := bn254.G1Affine{X: *big.NewInt(1), Y: *big.NewInt(2)}
	pedersenCommitmentH := bn254.G1Affine{X: *big.NewInt(2), Y: *big.NewInt(1)}
	accumulatorG := big.NewInt(5)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _, err := circuit.SetupCombinedCircuit(
			hashToPrimeBits, fieldSizeBits,
			integerCommitmentG, integerCommitmentH,
			&pedersenCommitmentG, &pedersenCommitmentH,
			accumulatorG,
		)
		if err != nil {
			b.Fatalf("Setup failed: %v", err)
		}
	}
}

// BenchmarkCombinedCircuitCompile benchmarks the compilation phase
func BenchmarkCombinedCircuitCompile(b *testing.B) {
	hashToPrimeBits := 254
	fieldSizeBits := 255
	integerCommitmentG := big.NewInt(2)
	integerCommitmentH := big.NewInt(3)
	pedersenCommitmentG := bn254.G1Affine{X: *big.NewInt(1), Y: *big.NewInt(2)}
	pedersenCommitmentH := bn254.G1Affine{X: *big.NewInt(2), Y: *big.NewInt(1)}
	accumulatorG := big.NewInt(5)

	circ := circuit.NewCombinedCircuit(
		hashToPrimeBits, fieldSizeBits,
		integerCommitmentG, integerCommitmentH,
		&pedersenCommitmentG, &pedersenCommitmentH,
		accumulatorG,
	)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := frontend.Compile(bn254.ID.ScalarField(), circ)
		if err != nil {
			b.Fatalf("Compilation failed: %v", err)
		}
	}
}

// BenchmarkCombinedCircuitProve benchmarks the proof generation
func BenchmarkCombinedCircuitProve(b *testing.B) {
	hashToPrimeBits := 254
	fieldSizeBits := 255
	integerCommitmentG := big.NewInt(2)
	integerCommitmentH := big.NewInt(3)
	pedersenCommitmentG := bn254.G1Affine{X: *big.NewInt(1), Y: *big.NewInt(2)}
	pedersenCommitmentH := bn254.G1Affine{X: *big.NewInt(2), Y: *big.NewInt(1)}
	accumulatorG := big.NewInt(5)

	// Setup circuit once
	circ := circuit.NewCombinedCircuit(
		hashToPrimeBits, fieldSizeBits,
		integerCommitmentG, integerCommitmentH,
		&pedersenCommitmentG, &pedersenCommitmentH,
		accumulatorG,
	)

	ccs, err := frontend.Compile(bn254.ID.ScalarField(), circ)
	if err != nil {
		b.Fatalf("Compilation failed: %v", err)
	}

	pk, _, err := plonk.Setup(ccs)
	if err != nil {
		b.Fatalf("Setup failed: %v", err)
	}

	assignment := createMockCombinedAssignmentForBench()
	witness, err := frontend.NewWitness(assignment, bn254.ID.ScalarField())
	if err != nil {
		b.Fatalf("Failed to create witness: %v", err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := plonk.Prove(ccs, pk, witness)
		if err != nil {
			b.Fatalf("Prove failed: %v", err)
		}
	}
}

// BenchmarkCombinedCircuitVerify benchmarks the proof verification
func BenchmarkCombinedCircuitVerify(b *testing.B) {
	hashToPrimeBits := 254
	fieldSizeBits := 255
	integerCommitmentG := big.NewInt(2)
	integerCommitmentH := big.NewInt(3)
	pedersenCommitmentG := bn254.G1Affine{X: *big.NewInt(1), Y: *big.NewInt(2)}
	pedersenCommitmentH := bn254.G1Affine{X: *big.NewInt(2), Y: *big.NewInt(1)}
	accumulatorG := big.NewInt(5)

	// Setup circuit once
	circ := circuit.NewCombinedCircuit(
		hashToPrimeBits, fieldSizeBits,
		integerCommitmentG, integerCommitmentH,
		&pedersenCommitmentG, &pedersenCommitmentH,
		accumulatorG,
	)

	ccs, err := frontend.Compile(bn254.ID.ScalarField(), circ)
	if err != nil {
		b.Fatalf("Compilation failed: %v", err)
	}

	pk, vk, err := plonk.Setup(ccs)
	if err != nil {
		b.Fatalf("Setup failed: %v", err)
	}

	assignment := createMockCombinedAssignmentForBench()
	witness, err := frontend.NewWitness(assignment, bn254.ID.ScalarField())
	if err != nil {
		b.Fatalf("Failed to create witness: %v", err)
	}

	proof, err := plonk.Prove(ccs, pk, witness)
	if err != nil {
		b.Fatalf("Prove failed: %v", err)
	}

	publicWitness, err := witness.Public()
	if err != nil {
		b.Fatalf("Failed to create public witness: %v", err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		err := plonk.Verify(proof, vk, publicWitness)
		if err != nil {
			b.Fatalf("Verify failed: %v", err)
		}
	}
}

// BenchmarkCombinedCircuitFullCycle benchmarks the full prove and verify cycle
func BenchmarkCombinedCircuitFullCycle(b *testing.B) {
	hashToPrimeBits := 254
	fieldSizeBits := 255
	integerCommitmentG := big.NewInt(2)
	integerCommitmentH := big.NewInt(3)
	pedersenCommitmentG := bn254.G1Affine{X: *big.NewInt(1), Y: *big.NewInt(2)}
	pedersenCommitmentH := bn254.G1Affine{X: *big.NewInt(2), Y: *big.NewInt(1)}
	accumulatorG := big.NewInt(5)

	// Setup circuit once
	circ := circuit.NewCombinedCircuit(
		hashToPrimeBits, fieldSizeBits,
		integerCommitmentG, integerCommitmentH,
		&pedersenCommitmentG, &pedersenCommitmentH,
		accumulatorG,
	)

	ccs, err := frontend.Compile(bn254.ID.ScalarField(), circ)
	if err != nil {
		b.Fatalf("Compilation failed: %v", err)
	}

	pk, vk, err := plonk.Setup(ccs)
	if err != nil {
		b.Fatalf("Setup failed: %v", err)
	}

	assignment := createMockCombinedAssignmentForBench()
	witness, err := frontend.NewWitness(assignment, bn254.ID.ScalarField())
	if err != nil {
		b.Fatalf("Failed to create witness: %v", err)
	}

	publicWitness, err := witness.Public()
	if err != nil {
		b.Fatalf("Failed to create public witness: %v", err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		// Prove
		proof, err := plonk.Prove(ccs, pk, witness)
		if err != nil {
			b.Fatalf("Prove failed: %v", err)
		}

		// Verify
		err = plonk.Verify(proof, vk, publicWitness)
		if err != nil {
			b.Fatalf("Verify failed: %v", err)
		}
	}
}

// createMockCombinedAssignmentForBench creates mock assignment for benchmarking
func createMockCombinedAssignmentForBench() *circuit.CombinedCircuitAssignment {
	// Shared values
	accumulatorValue := big.NewInt(123456789012345678901234567890123456789012345678901234567890)
	integerCommitment := big.NewInt(98765432109876543210987654321098765432109876543210987654321)
	pedersenCommitmentX := big.NewInt(12345)
	pedersenCommitmentY := big.NewInt(67890)

	// Membership values
	membershipElement := big.NewInt(12702637924034044211)
	membershipRandomness := big.NewInt(5)
	membershipRandomnessQ := big.NewInt(7)
	membershipRootAlpha1 := big.NewInt(1111111111111111111111111111111111111111111111)
	membershipRootSE := big.NewInt(2222222222222222222222222222222222222222222222)
	membershipRootSR := big.NewInt(3333333333333333333333333333333333333333333333)
	membershipRootChallenge := big.NewInt(4444444444444444444444444444444444444444444444)
	membershipModEqAlpha1X := big.NewInt(11111)
	membershipModEqAlpha1Y := big.NewInt(22222)
	membershipModEqAlpha2X := big.NewInt(33333)
	membershipModEqAlpha2Y := big.NewInt(44444)
	membershipModEqSE := big.NewInt(5555555555555555555555555555555555555555)
	membershipModEqSR := big.NewInt(6666666666666666666666666666666666666666)
	membershipModEqSRQ := big.NewInt(7777777777777777777777777777777777777777)
	membershipModEqChallenge := big.NewInt(8888888888888888888888888888888888888888)
	membershipHashToPrimeChallenge := big.NewInt(9999999999999999999999999999999999999999)
	membershipOriginalElement := big.NewInt(10000000000000000000000000000000000000000)
	membershipHashedPrime := big.NewInt(11000000000000000000000000000000000000000)

	// Create membership bit decomposition (254 bits)
	membershipBitDecomposition := make([]frontend.Variable, 254)
	for i := 0; i < 254; i++ {
		membershipBitDecomposition[i] = frontend.Variable(big.NewInt(int64(i % 2)))
	}

	// Non-membership values
	nonMembershipElement := big.NewInt(378373571372703133)
	nonMembershipRandomness := big.NewInt(9)
	nonMembershipRandomnessQ := big.NewInt(11)
	nonMembershipCoprimeAlpha1 := big.NewInt(1212121212121212121212121212121212121212121212)
	nonMembershipCoprimeSE := big.NewInt(2323232323232323232323232323232323232323232323)
	nonMembershipCoprimeSR := big.NewInt(3434343434343434343434343434343434343434343434)
	nonMembershipCoprimeChallenge := big.NewInt(4545454545454545454545454545454545454545454545)
	nonMembershipModEqAlpha1X := big.NewInt(55555)
	nonMembershipModEqAlpha1Y := big.NewInt(66666)
	nonMembershipModEqAlpha2X := big.NewInt(77777)
	nonMembershipModEqAlpha2Y := big.NewInt(88888)
	nonMembershipModEqSE := big.NewInt(9999999999999999999999999999999999999999)
	nonMembershipModEqSR := big.NewInt(1010101010101010101010101010101010101010)
	nonMembershipModEqSRQ := big.NewInt(1111111111111111111111111111111111111111)
	nonMembershipModEqChallenge := big.NewInt(1212121212121212121212121212121212121212)
	nonMembershipHashToPrimeChallenge := big.NewInt(1313131313131313131313131313131313131313)
	nonMembershipOriginalElement := big.NewInt(1414141414141414141414141414141414141414)
	nonMembershipHashedPrime := big.NewInt(1515151515151515151515151515151515151515)

	// Create non-membership bit decomposition (254 bits)
	nonMembershipBitDecomposition := make([]frontend.Variable, 254)
	for i := 0; i < 254; i++ {
		nonMembershipBitDecomposition[i] = frontend.Variable(big.NewInt(int64((i + 1) % 2)))
	}

	return &circuit.CombinedCircuitAssignment{
		// Shared
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
		MembershipBitDecomposition:    membershipBitDecomposition,

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
		NonMembershipBitDecomposition:    nonMembershipBitDecomposition,
	}
}

// runCombinedBenchmark runs a comprehensive benchmark and prints results
func runCombinedBenchmark() {
	hashToPrimeBits := 254
	fieldSizeBits := 255
	integerCommitmentG := big.NewInt(2)
	integerCommitmentH := big.NewInt(3)
	pedersenCommitmentG := bn254.G1Affine{X: *big.NewInt(1), Y: *big.NewInt(2)}
	pedersenCommitmentH := bn254.G1Affine{X: *big.NewInt(2), Y: *big.NewInt(1)}
	accumulatorG := big.NewInt(5)

	iterations := 10

	println("=== Combined Circuit Benchmark ===")
	println()

	// Benchmark setup
	println("Benchmarking Setup...")
	setupTimes := make([]time.Duration, iterations)
	for i := 0; i < iterations; i++ {
		start := time.Now()
		_, _, err := circuit.SetupCombinedCircuit(
			hashToPrimeBits, fieldSizeBits,
			integerCommitmentG, integerCommitmentH,
			&pedersenCommitmentG, &pedersenCommitmentH,
			accumulatorG,
		)
		if err != nil {
			println("Setup failed:", err)
			return
		}
		setupTimes[i] = time.Since(start)
	}
	avgSetupTime := averageDuration(setupTimes)
	println("Average Setup Time:", avgSetupTime)
	println()

	// Setup circuit once for prove/verify benchmarks
	circ := circuit.NewCombinedCircuit(
		hashToPrimeBits, fieldSizeBits,
		integerCommitmentG, integerCommitmentH,
		&pedersenCommitmentG, &pedersenCommitmentH,
		accumulatorG,
	)

	ccs, err := frontend.Compile(bn254.ID.ScalarField(), circ)
	if err != nil {
		println("Compilation failed:", err)
		return
	}

	pk, vk, err := plonk.Setup(ccs)
	if err != nil {
		println("Setup failed:", err)
		return
	}

	assignment := createMockCombinedAssignmentForBench()
	witness, err := frontend.NewWitness(assignment, bn254.ID.ScalarField())
	if err != nil {
		println("Failed to create witness:", err)
		return
	}

	publicWitness, err := witness.Public()
	if err != nil {
		println("Failed to create public witness:", err)
		return
	}

	// Benchmark prove
	println("Benchmarking Prove...")
	proveTimes := make([]time.Duration, iterations)
	for i := 0; i < iterations; i++ {
		start := time.Now()
		_, err := plonk.Prove(ccs, pk, witness)
		if err != nil {
			println("Prove failed:", err)
			return
		}
		proveTimes[i] = time.Since(start)
	}
	avgProveTime := averageDuration(proveTimes)
	println("Average Prove Time:", avgProveTime)
	println()

	// Generate proof once for verify benchmark
	proof, err := plonk.Prove(ccs, pk, witness)
	if err != nil {
		println("Prove failed:", err)
		return
	}

	// Benchmark verify
	println("Benchmarking Verify...")
	verifyTimes := make([]time.Duration, iterations)
	for i := 0; i < iterations; i++ {
		start := time.Now()
		err := plonk.Verify(proof, vk, publicWitness)
		if err != nil {
			println("Verify failed:", err)
			return
		}
		verifyTimes[i] = time.Since(start)
	}
	avgVerifyTime := averageDuration(verifyTimes)
	println("Average Verify Time:", avgVerifyTime)
	println()

	// Summary
	println("=== Summary ===")
	println("Setup:", avgSetupTime)
	println("Prove:", avgProveTime)
	println("Verify:", avgVerifyTime)
}

func averageDuration(durations []time.Duration) time.Duration {
	var sum time.Duration
	for _, d := range durations {
		sum += d
	}
	return sum / time.Duration(len(durations))
}

