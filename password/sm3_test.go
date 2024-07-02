package password

import (
	"errors"
	"testing"

	"github.com/emmansun/gmsm/sm3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/xuyang2/password-encoder/keygen"
	"github.com/xuyang2/password-encoder/keygen/keygentest"
)

func TestSm3PasswordEncoder_Matches(t *testing.T) {
	encoder := Sm3PasswordEncoder{
		saltGen: keygen.NewSecureRandomBytesKeyGenerator(8),
	}

	t.Run("ok", func(t *testing.T) {
		rawPassword := "password"

		encodedPassword, err := encoder.Encode(rawPassword)

		assert.NoError(t, err)
		assert.NotEqual(t, rawPassword, encodedPassword)
		assert.True(t, encoder.Matches(rawPassword, encodedPassword))
		assert.False(t, encoder.Matches(rawPassword+"a", encodedPassword))

		assert.False(t, encoder.Matches(rawPassword, encodedPassword[0:sm3.Size-1])) // odd length hex string
		assert.False(t, encoder.Matches(rawPassword, encodedPassword[0:sm3.Size-2])) // encodedPassword too short

		assert.False(t, encoder.Matches(rawPassword, "gg")) // invalid hex
		assert.False(t, encoder.Matches(rawPassword, ""))
	})
}

func TestSm3PasswordEncoder_Encode(t *testing.T) {
	t.Run("err", func(t *testing.T) {
		encoder := Sm3PasswordEncoder{
			saltGen: keygentest.ErrBytesKeyGenerator(errors.New("WTF"), 8),
		}
		_, err := encoder.Encode("?")
		assert.Error(t, err)
	})
}

func TestSm3PasswordEncoder_UpgradeEncoding(t *testing.T) {
	t.Run("always false", func(t *testing.T) {
		encoder := Sm3PasswordEncoder{
			saltGen: keygen.NewSecureRandomBytesKeyGenerator(8),
		}

		encodedPassword, err := encoder.Encode("password")
		require.NoError(t, err)

		assert.Equal(t, false, encoder.UpgradeEncoding(encodedPassword))
	})
}
