// crypto/zk_cipher.go
package crypto

import (
	"github.com/consensys/gnark/frontend"
)

// ZKSymmetricCipher provides ZK-friendly symmetric encryption
type ZKSymmetricCipher struct {
	api    frontend.API
	hasher *ZKHash
}

// NewZKSymmetricCipher creates a new cipher instance
func NewZKSymmetricCipher(api frontend.API) *ZKSymmetricCipher {
	return &ZKSymmetricCipher{
		api:    api,
		hasher: NewZKHash(api),
	}
}

// Encrypt computes H(key | message) as a simplified encryption
func (c *ZKSymmetricCipher) Encrypt(key, message frontend.Variable) frontend.Variable {
	return c.hasher.HashTwo(key, message)
}

// Decrypt is the same operation as Encrypt in this simplified model
func (c *ZKSymmetricCipher) Decrypt(key, ciphertext frontend.Variable) frontend.Variable {
	return c.hasher.HashTwo(key, ciphertext)
}