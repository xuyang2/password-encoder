package password

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/bcrypt"
)

func TestBCryptPasswordEncoder_Matches(t *testing.T) {
	t.Run("ok", func(t *testing.T) {
		encoder := NewBCryptPasswordEncoder(bcrypt.DefaultCost)

		rawPassword := "password"

		encodedPassword, err := encoder.Encode(rawPassword)

		assert.NoError(t, err)
		assert.NotEqual(t, rawPassword, encodedPassword)
		assert.True(t, encoder.Matches(rawPassword, encodedPassword))
		assert.False(t, encoder.Matches(rawPassword+"a", encodedPassword))
	})

	t.Run("err", func(t *testing.T) {
		encoder := NewBCryptPasswordEncoder(bcrypt.MaxCost + 1)

		rawPassword := "password"

		_, err := encoder.Encode(rawPassword)

		assert.Error(t, err)
	})
}

func TestBCryptPasswordEncoder_Upgradable(t *testing.T) {
	t.Run("always false", func(t *testing.T) {
		encoder := NewBCryptPasswordEncoder(bcrypt.DefaultCost)

		encodedPassword, err := encoder.Encode("password")
		require.NoError(t, err)

		assert.Equal(t, false, encoder.Upgradable(encodedPassword))
	})
}
