package password

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/xuyang2/password-encoder/keygen/keygentest"
)

func TestPbkdf2PasswordEncoder_Matches(t *testing.T) {
	t.Run("ok", func(t *testing.T) {
		encoder := DefaultPbkdf2PasswordEncoder()

		rawPassword := "myPassword"
		encodedPassword, err := encoder.Encode(rawPassword)

		assert.NoError(t, err)
		assert.NotEqual(t, rawPassword, encodedPassword)
		assert.True(t, encoder.Matches(rawPassword, encodedPassword))
		assert.False(t, encoder.Matches(rawPassword+"a", encodedPassword))
	})

	t.Run("spring-security encoded", func(t *testing.T) {
		// Pbkdf2PasswordEncoder encoder = Pbkdf2PasswordEncoder.defaultsForSpringSecurity_v5_8();
		// String encodedPassword = encoder.encode("myPassword");
		encoder := DefaultPbkdf2PasswordEncoder()
		rawPassword := "myPassword"
		encodedPassword := "828bd964df921c17dc966dd20638df86583ce04cc7ba25c372813809bb2ad05badcadabb66e03203443fa198ecc70668"
		assert.True(t, encoder.Matches(rawPassword, encodedPassword))
		assert.False(t, encoder.Matches(rawPassword+"a", encodedPassword))

		assert.False(t, encoder.Matches(rawPassword, encodedPassword[0:encoder.keyLen-1])) // odd length hex string
		assert.False(t, encoder.Matches(rawPassword, encodedPassword[0:encoder.keyLen-2])) // encodedPassword too short

		assert.False(t, encoder.Matches(rawPassword, "gg")) // invalid hex
		assert.False(t, encoder.Matches(rawPassword, ""))
	})
}

func TestPbkdf2PasswordEncoder_Encode(t *testing.T) {
	t.Run("err saltGen", func(t *testing.T) {
		encoder := DefaultPbkdf2PasswordEncoder()
		encoder.saltGen = keygentest.ErrBytesKeyGenerator(errors.New("oops"), 8)
		_, err := encoder.Encode("?")
		assert.Error(t, err)
	})
}

func TestPbkdf2PasswordEncoder_UpgradeEncoding(t *testing.T) {
	t.Run("always false", func(t *testing.T) {
		encoder := DefaultPbkdf2PasswordEncoder()

		encodedPassword, err := encoder.Encode("password")
		require.NoError(t, err)

		assert.Equal(t, false, encoder.UpgradeEncoding(encodedPassword))
	})
}
