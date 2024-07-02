package keygen

import (
	"errors"
	"io"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestSecureRandomBytesKeyGenerator_GenerateKey(t *testing.T) {
	t.Run("ok", func(t *testing.T) {
		gen := NewSecureRandomBytesKeyGenerator(8)
		key, err := gen.GenerateKey()
		assert.NoError(t, err)
		assert.Equal(t, 8, len(key))
	})

	t.Run("err", func(t *testing.T) {
		gen := NewSecureRandomBytesKeyGenerator(8)
		gen.rand = ErrReader(errors.New("WTF"))
		_, err := gen.GenerateKey()
		assert.Error(t, err)
	})
}

func TestSecureRandomBytesKeyGenerator_KeyLength(t *testing.T) {
	gen := NewSecureRandomBytesKeyGenerator(8)
	assert.Equal(t, 8, gen.KeyLength())
}

// ErrReader returns an io.Reader that returns 0, err from all Read calls.
func ErrReader(err error) io.Reader {
	return &errReader{err: err}
}

// TODO: go 1.16 iotest.ErrReader
type errReader struct {
	err error
}

func (r *errReader) Read(p []byte) (int, error) {
	return 0, r.err
}
