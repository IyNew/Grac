// tests/integration_test.go
package tests

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"testing"

	"github.com/research/gr2ac-poc/integration"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Hash is a utility function for computing SHA256 hashes
func Hash(data ...[]byte) string {
	h := sha256.New()
	for _, d := range data {
		h.Write(d)
	}
	return hex.EncodeToString(h.Sum(nil))
}

func TestCredentialServiceEndToEnd(t *testing.T) {
	ctx := context.Background()

	// Setup credential service
	service, err := integration.NewCredentialService()
	require.NoError(t, err, "Failed to create credential service")

	// Test parameters
	accumulatorState := "test_acc_state_456"
	attributeID := "employee@company.com"

	// Generate random secret key
	secretKeyBytes := make([]byte, 32)
	_, err = rand.Read(secretKeyBytes)
	require.NoError(t, err, "Failed to generate random secret key")

	secretKeyHex := hex.EncodeToString(secretKeyBytes)

	// Prepare witness data
	indexBytes := []byte("99999")
	controlP := Hash(secretKeyBytes, indexBytes)
	controlNext := Hash(secretKeyBytes, []byte(attributeID))
	membershipWitness := "test_membership_witness"

	witnessData := map[string]interface{}{
		"secretKey":         secretKeyHex,
		"index":             "99999",
		"controlP":          controlP,
		"controlNext":       controlNext,
		"membershipWitness": membershipWitness,
	}

	// Generate proof
	proof, err := service.GenerateCredential(ctx, accumulatorState, attributeID, witnessData)
	require.NoError(t, err, "Failed to generate credential")
	assert.NotNil(t, proof, "Proof should not be nil")

	// Verify proof with correct parameters
	valid, err := service.VerifyCredential(ctx, proof, accumulatorState, attributeID)
	require.NoError(t, err, "Verification should not error")
	assert.True(t, valid, "Proof should verify with correct parameters")
}

func TestCredentialServiceInvalidParameters(t *testing.T) {
	ctx := context.Background()

	service, err := integration.NewCredentialService()
	require.NoError(t, err, "Failed to create credential service")

	// Test parameters
	accumulatorState := "test_acc_state_789"
	attributeID := "member@organization.org"
	wrongAttributeID := "wrong@attribute.com"

	// Generate random secret key
	secretKeyBytes := make([]byte, 32)
	_, err = rand.Read(secretKeyBytes)
	require.NoError(t, err, "Failed to generate random secret key")

	secretKeyHex := hex.EncodeToString(secretKeyBytes)

	// Prepare witness data
	indexBytes := []byte("54321")
	controlP := Hash(secretKeyBytes, indexBytes)
	controlNext := Hash(secretKeyBytes, []byte(attributeID))
	membershipWitness := "test_membership_witness_invalid"

	witnessData := map[string]interface{}{
		"secretKey":         secretKeyHex,
		"index":             "54321",
		"controlP":          controlP,
		"controlNext":       controlNext,
		"membershipWitness": membershipWitness,
	}

	// Generate proof
	proof, err := service.GenerateCredential(ctx, accumulatorState, attributeID, witnessData)
	require.NoError(t, err, "Failed to generate credential")

	// Verify proof with wrong attribute ID - should fail
	valid, err := service.VerifyCredential(ctx, proof, accumulatorState, wrongAttributeID)
	require.NoError(t, err, "Verification should not error")
	assert.False(t, valid, "Proof should not verify with wrong attribute ID")

	// Verify proof with wrong accumulator state - should fail
	valid, err = service.VerifyCredential(ctx, proof, "wrong_state", attributeID)
	require.NoError(t, err, "Verification should not error")
	assert.False(t, valid, "Proof should not verify with wrong accumulator state")
}

func TestMultipleProofs(t *testing.T) {
	ctx := context.Background()

	service, err := integration.NewCredentialService()
	require.NoError(t, err, "Failed to create credential service")

	// Test multiple different credentials
	testCases := []struct {
		accumulatorState string
		attributeID      string
		secretKey        string
		index            string
	}{
		{"acc_state_1", "user1@domain.com", "secret_key_1", "10001"},
		{"acc_state_2", "user2@domain.com", "secret_key_2", "10002"},
		{"acc_state_3", "user3@domain.com", "secret_key_3", "10003"},
	}

	for i, tc := range testCases {
		t.Run(fmt.Sprintf("Case_%d", i+1), func(t *testing.T) {
			// Generate random secret key for this test case
			secretKeyBytes := make([]byte, 32)
			_, err := rand.Read(secretKeyBytes)
			require.NoError(t, err)

			secretKeyHex := hex.EncodeToString(secretKeyBytes)

			// Prepare witness data
			indexBytes := []byte(tc.index)
			controlP := Hash(secretKeyBytes, indexBytes)
			controlNext := Hash(secretKeyBytes, []byte(tc.attributeID))
			membershipWitness := fmt.Sprintf("witness_%d", i+1)

			witnessData := map[string]interface{}{
				"secretKey":         secretKeyHex,
				"index":             tc.index,
				"controlP":          controlP,
				"controlNext":       controlNext,
				"membershipWitness": membershipWitness,
			}

			// Generate proof
			proof, err := service.GenerateCredential(ctx, tc.accumulatorState, tc.attributeID, witnessData)
			require.NoError(t, err)
			assert.NotNil(t, proof)

			// Verify proof
			valid, err := service.VerifyCredential(ctx, proof, tc.accumulatorState, tc.attributeID)
			require.NoError(t, err)
			assert.True(t, valid)
		})
	}
}

func BenchmarkProofGeneration(b *testing.B) {
	ctx := context.Background()

	service, err := integration.NewCredentialService()
	require.NoError(b, err, "Failed to create credential service")

	// Benchmark parameters
	accumulatorState := "bench_acc_state"
	attributeID := "bench@user.com"

	// Generate random secret key
	secretKeyBytes := make([]byte, 32)
	_, err = rand.Read(secretKeyBytes)
	require.NoError(b, err)

	secretKeyHex := hex.EncodeToString(secretKeyBytes)

	// Prepare witness data
	indexBytes := []byte("bench_index")
	controlP := Hash(secretKeyBytes, indexBytes)
	controlNext := Hash(secretKeyBytes, []byte(attributeID))
	membershipWitness := "bench_witness"

	witnessData := map[string]interface{}{
		"secretKey":         secretKeyHex,
		"index":             "bench_index",
		"controlP":          controlP,
		"controlNext":       controlNext,
		"membershipWitness": membershipWitness,
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := service.GenerateCredential(ctx, accumulatorState, attributeID, witnessData)
		if err != nil {
			b.Fatalf("Failed to generate proof: %v", err)
		}
	}
}

func BenchmarkProofVerification(b *testing.B) {
	ctx := context.Background()

	service, err := integration.NewCredentialService()
	require.NoError(b, err, "Failed to create credential service")

	// Generate a proof once for benchmarking
	accumulatorState := "bench_verify_state"
	attributeID := "verify@user.com"

	secretKeyBytes := make([]byte, 32)
	_, err = rand.Read(secretKeyBytes)
	require.NoError(b, err)

	secretKeyHex := hex.EncodeToString(secretKeyBytes)

	indexBytes := []byte("verify_index")
	controlP := Hash(secretKeyBytes, indexBytes)
	controlNext := Hash(secretKeyBytes, []byte(attributeID))
	membershipWitness := "verify_witness"

	witnessData := map[string]interface{}{
		"secretKey":         secretKeyHex,
		"index":             "verify_index",
		"controlP":          controlP,
		"controlNext":       controlNext,
		"membershipWitness": membershipWitness,
	}

	proof, err := service.GenerateCredential(ctx, accumulatorState, attributeID, witnessData)
	require.NoError(b, err)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := service.VerifyCredential(ctx, proof, accumulatorState, attributeID)
		if err != nil {
			b.Fatalf("Failed to verify proof: %v", err)
		}
	}
}