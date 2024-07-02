package password

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/xuyang2/password-encoder/keygen"
	"github.com/xuyang2/password-encoder/keygen/keygentest"
)

func TestSha256PasswordEncoder_Matches(t *testing.T) {
	encoder := Sha256PasswordEncoder{
		saltGen: keygen.NewSecureRandomBytesKeyGenerator(8),
	}

	t.Run("ok", func(t *testing.T) {
		rawPassword := "password"
		encodedPassword, err := encoder.Encode(rawPassword)

		assert.NoError(t, err)
		assert.NotEqual(t, rawPassword, encodedPassword)
		assert.True(t, encoder.Matches(rawPassword, encodedPassword))
		assert.False(t, encoder.Matches(rawPassword+"a", encodedPassword))
	})

	t.Run("err", func(t *testing.T) {
		rawPassword := "password"
		encodedPassword := "gg" // invalid hex

		assert.False(t, encoder.Matches(rawPassword, encodedPassword))
	})
}

func TestSha256PasswordEncoder_Encode(t *testing.T) {
	t.Run("err", func(t *testing.T) {
		encoder := Sha256PasswordEncoder{
			saltGen: keygentest.ErrBytesKeyGenerator(errors.New("WTF"), 8),
		}
		_, err := encoder.Encode("?")
		assert.Error(t, err)
	})
}

func TestSha256PasswordEncoder_Upgradable(t *testing.T) {
	t.Run("always false", func(t *testing.T) {
		encoder := Sha256PasswordEncoder{
			saltGen: keygen.NewSecureRandomBytesKeyGenerator(8),
		}

		encodedPassword, err := encoder.Encode("password")
		require.NoError(t, err)

		assert.Equal(t, false, encoder.Upgradable(encodedPassword))
	})
}