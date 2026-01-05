// crypto/zk_hash.go
package crypto

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/hash/mimc"
)

// ZKHash provides a ZK-friendly hash implementation using MiMC
type ZKHash struct {
	hasher mimc.MiMC
}

// NewZKHash creates a new ZK-friendly hash instance
func NewZKHash(api frontend.API) *ZKHash {
	hasher, err := mimc.NewMiMC(api)
	if err != nil {
		panic(err) // In production, handle this properly
	}
	return &ZKHash{
		hasher: hasher,
	}
}

// Hash computes hash of multiple inputs
func (h *ZKHash) Hash(inputs ...frontend.Variable) frontend.Variable {
	h.hasher.Reset()
	for _, input := range inputs {
		h.hasher.Write(input)
	}
	return h.hasher.Sum()
}

// HashTwo computes hash of exactly two inputs (optimized version)
func (h *ZKHash) HashTwo(a, b frontend.Variable) frontend.Variable {
	h.hasher.Reset()
	h.hasher.Write(a, b)
	return h.hasher.Sum()
}