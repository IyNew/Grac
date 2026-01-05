// examples/demo.go
package main

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"

	"github.com/research/gr2ac-poc/integration"
)

// Hash is a utility function for computing SHA256 hashes
func Hash(data ...[]byte) string {
	h := sha256.New()
	for _, d := range data {
		h.Write(d)
	}
	return hex.EncodeToString(h.Sum(nil))
}

func main() {
	ctx := context.Background()

	// Setup credential service
	service, err := integration.NewCredentialService()
	if err != nil {
		panic(fmt.Sprintf("Failed to create service: %v", err))
	}

	fmt.Println("Gr2AC zkSNARK Demo")
	fmt.Println("==================")

	// Example parameters that would normally come from blockchain
	accumulatorState := "acc_state_123"
	attributeID := "student@university.edu"

	// Generate random secret key
	secretKeyBytes := make([]byte, 32)
	if _, err := rand.Read(secretKeyBytes); err != nil {
		panic(fmt.Sprintf("Failed to generate random secret key: %v", err))
	}
	secretKeyHex := hex.EncodeToString(secretKeyBytes)

	// Example witness data (in real implementation, this would come from blockchain queries)
	// These values would be computed based on the actual cryptographic operations
	indexBytes := []byte("12345")
	controlP := Hash(secretKeyBytes, indexBytes)                     // H(sk|idx)
	controlNext := Hash(secretKeyBytes, []byte(attributeID))        // H(sk|AttID)
	membershipWitness := "membership_witness_data"

	witnessData := map[string]interface{}{
		"secretKey":         secretKeyHex,
		"index":             "12345",
		"controlP":          controlP,
		"controlNext":       controlNext,
		"membershipWitness": membershipWitness,
	}

	fmt.Printf("Secret Key: %s\n", secretKeyHex)
	fmt.Printf("Attribute ID: %s\n", attributeID)
	fmt.Printf("Accumulator State: %s\n", accumulatorState)
	fmt.Printf("Control P: %s\n", controlP)
	fmt.Printf("Control Next: %s\n", controlNext)
	fmt.Println()

	// Generate credential proof
	fmt.Println("Generating credential proof...")
	proof, err := service.GenerateCredential(ctx, accumulatorState, attributeID, witnessData)
	if err != nil {
		panic(fmt.Sprintf("Failed to generate credential: %v", err))
	}

	fmt.Printf("Generated credential proof successfully\n")
	fmt.Println()

	// Verify credential proof
	fmt.Println("Verifying credential proof...")
	valid, err := service.VerifyCredential(ctx, proof, accumulatorState, attributeID)
	if err != nil {
		panic(fmt.Sprintf("Verification failed: %v", err))
	}

	fmt.Printf("Credential verification result: %v\n", valid)

	if valid {
		fmt.Println("✅ Success! The zkSNARK proof is valid.")
		fmt.Println("✅ Anonymous authentication proved without revealing identity.")
	} else {
		fmt.Println("❌ Failed! The proof verification failed.")
	}
}