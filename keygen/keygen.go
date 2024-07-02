package keygen

import (
	"crypto/rand"
	"io"
)

type BytesKeyGenerator interface {
	// KeyLength() int

	GenerateKey() ([]byte, error)
}

type SecureRandomBytesKeyGenerator struct {
	keyLength int
	rand      io.Reader
}

func NewSecureRandomBytesKeyGenerator(keyLength int) *SecureRandomBytesKeyGenerator {
	return &SecureRandomBytesKeyGenerator{
		keyLength: keyLength,
		rand:      rand.Reader,
	}
}

func (g *SecureRandomBytesKeyGenerator) KeyLength() int {
	return g.keyLength
}

func (g *SecureRandomBytesKeyGenerator) GenerateKey() ([]byte, error) {
	b := make([]byte, g.keyLength)

	_, err := g.rand.Read(b)

	if err != nil {
		return nil, err
	}

	return b, nil
}
