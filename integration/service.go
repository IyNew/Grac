// integration/service.go
package integration

import (
	"context"
	"fmt"

	"github.com/research/gr2ac-poc/zk"
)

// CredentialService provides interface for generating and verifying credentials
type CredentialService struct {
	proofSystem *zk.ProofSystem
}

// NewCredentialService creates a new service instance
func NewCredentialService() (*CredentialService, error) {
	// Setup proof system
	ps, err := zk.Setup()
	if err != nil {
		return nil, fmt.Errorf("failed to setup proof system: %v", err)
	}

	return &CredentialService{
		proofSystem: ps,
	}, nil
}

// GenerateCredential generates a credential proof
func (svc *CredentialService) GenerateCredential(
	ctx context.Context,
	accumulatorState string,
	attributeID string,
	witnessData map[string]interface{},
) (*zk.Proof, error) {
	proof, err := svc.proofSystem.GenerateProof(
		accumulatorState,
		attributeID,
		witnessData,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to generate credential: %v", err)
	}

	return proof, nil
}

// VerifyCredential verifies a credential proof
func (svc *CredentialService) VerifyCredential(
	ctx context.Context,
	proof *zk.Proof,
	accumulatorState string,
	attributeID string,
) (bool, error) {
	return svc.proofSystem.VerifyProof(proof, accumulatorState, attributeID)
}