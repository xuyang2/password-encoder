package password

import (
	"errors"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/xuyang2/password-encoder/keygen/keygentest"
)

func TestSCryptPasswordEncoder_Matches(t *testing.T) {
	t.Run("ok", func(t *testing.T) {
		encoder := DefaultSCryptPasswordEncoder()

		rawPassword := "myPassword"
		encodedPassword, err := encoder.Encode(rawPassword)

		assert.NoError(t, err)
		assert.NotEqual(t, rawPassword, encodedPassword)

		assert.True(t, encoder.Matches(rawPassword, encodedPassword))
		assert.False(t, encoder.Matches(rawPassword+"a", encodedPassword))

		parts := strings.Split(encodedPassword, "$")
		assert.Len(t, parts, 4)
		assert.True(t, encoder.Matches(rawPassword, strings.Join([]string{"", parts[1], parts[2], parts[3]}, "$")))
		assert.False(t, encoder.Matches(rawPassword, strings.Join([]string{"", "_", parts[2], parts[3]}, "$")))
		assert.False(t, encoder.Matches(rawPassword, strings.Join([]string{"", parts[1], "_", parts[3]}, "$")))
		assert.False(t, encoder.Matches(rawPassword, strings.Join([]string{"", parts[1], parts[2], "_"}, "$")))

		assert.False(t, encoder.Matches(rawPassword, ""))
	})

	t.Run("spring-security encoded", func(t *testing.T) {
		encoder := DefaultSCryptPasswordEncoder()

		// SCryptPasswordEncoder encoder = SCryptPasswordEncoder.defaultsForSpringSecurity_v5_8();
		// String encodedPassword = encoder.encode("myPassword");
		rawPassword := "myPassword"
		encodedPassword := "$100801$4P6llsBJYk/EbyFZaq6yyw==$+G59NWVc3S/n67Eo5+bxjY7RP9NsDAclJzorgIet0Rs="

		assert.True(t, encoder.Matches(rawPassword, encodedPassword))
		assert.False(t, encoder.Matches(rawPassword+"a", encodedPassword))
	})
}

func TestSCryptPasswordEncoder_Encode(t *testing.T) {
	t.Run("no err", func(t *testing.T) {
		encoder := DefaultSCryptPasswordEncoder()
		encoded, err := encoder.Encode("?")
		assert.NoError(t, err)
		assert.True(t, encoded != "")
	})

	t.Run("err saltGen", func(t *testing.T) {
		encoder := DefaultSCryptPasswordEncoder()
		encoder.saltGen = keygentest.ErrBytesKeyGenerator(errors.New("oops"), 8)
		_, err := encoder.Encode("?")
		assert.Error(t, err)
	})
}

func TestSCryptPasswordEncoder_UpgradeEncoding(t *testing.T) {
	t.Run("always false", func(t *testing.T) {
		encoder := DefaultSCryptPasswordEncoder()

		encodedPassword, err := encoder.Encode("password")
		require.NoError(t, err)

		assert.Equal(t, false, encoder.UpgradeEncoding(encodedPassword))
	})
}
