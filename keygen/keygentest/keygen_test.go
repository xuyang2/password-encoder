package keygentest

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestErrBytesKeyGenerator(t *testing.T) {
	{
		gen := ErrBytesKeyGenerator(errors.New("WTF"), 8)
		_, err := gen.GenerateKey()
		assert.Error(t, err)
	}

	{
		gen := &errBytesKeyGenerator{
			err:       errors.New("WTF"),
			keyLength: 8,
		}
		assert.Equal(t, 8, gen.KeyLength())
	}
}
