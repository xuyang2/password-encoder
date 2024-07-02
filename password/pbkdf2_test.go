package password

import (
	"testing"

	"github.com/stretchr/testify/assert"
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
	})
}
