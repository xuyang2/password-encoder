package keygentest

import "github.com/xuyang2/password-encoder/keygen"

type errBytesKeyGenerator struct {
	err       error
	keyLength int
}

func (g *errBytesKeyGenerator) KeyLength() int {
	return g.keyLength
}

func (g *errBytesKeyGenerator) GenerateKey() ([]byte, error) {
	return nil, g.err
}

func ErrBytesKeyGenerator(err error, keyLength int) keygen.BytesKeyGenerator {
	return &errBytesKeyGenerator{
		err:       err,
		keyLength: keyLength,
	}
}
