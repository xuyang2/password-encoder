package password

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/bcrypt"

	"github.com/xuyang2/password-encoder/keygen"
)

func TestNewDelegatingPasswordEncoder(t *testing.T) {
	t.Run("ok", func(t *testing.T) {
		saltGen := keygen.NewSecureRandomBytesKeyGenerator(8)
		idToPasswordEncoder := map[string]PasswordEncoder{
			"bcrypt": NewBCryptPasswordEncoder(bcrypt.DefaultCost),
			"sm3":    NewSm3PasswordEncoder(saltGen),
			"sha256": NewSha256PasswordEncoder(saltGen),
		}
		idForEncode := "bcrypt"
		delegatingEncoder := NewDelegatingPasswordEncoder(idForEncode, idToPasswordEncoder)
		assert.NotNil(t, delegatingEncoder)
	})

	t.Run("panics idForEncode not found", func(t *testing.T) {
		saltGen := keygen.NewSecureRandomBytesKeyGenerator(8)
		idToPasswordEncoder := map[string]PasswordEncoder{
			"bcrypt": NewBCryptPasswordEncoder(bcrypt.DefaultCost),
			"sm3":    NewSm3PasswordEncoder(saltGen),
			"sha256": NewSha256PasswordEncoder(saltGen),
		}
		idForEncode := ""
		assert.Panics(t, func() {
			NewDelegatingPasswordEncoder(idForEncode, idToPasswordEncoder)
		})
	})

}

func TestDelegatingPasswordEncoder_Matches(t *testing.T) {

	saltGen := keygen.NewSecureRandomBytesKeyGenerator(8)

	idToPasswordEncoder := map[string]PasswordEncoder{
		"bcrypt": NewBCryptPasswordEncoder(bcrypt.DefaultCost),
		"pbkdf2": DefaultPbkdf2PasswordEncoder(),
		"sm3":    NewSm3PasswordEncoder(saltGen),
		"sha256": NewSha256PasswordEncoder(saltGen),
	}

	delegatingEncoder := DelegatingPasswordEncoder{
		idPrefix:                 DefaultIdPrefix,
		idSuffix:                 DefaultIdSuffix,
		idForEncode:              "bcrypt",
		passwordEncoderForEncode: idToPasswordEncoder["bcrypt"],
		idToPasswordEncoder:      idToPasswordEncoder,
	}

	{
		rawPassword := "password"
		encodedPassword, err := delegatingEncoder.Encode(rawPassword)

		assert.NoError(t, err)
		assert.NotEqual(t, rawPassword, encodedPassword)
		assert.True(t, delegatingEncoder.Matches(rawPassword, encodedPassword))
	}

	for encoderId, delegateEncoder := range idToPasswordEncoder {
		rawPassword := "password"
		encodedPassword, err := delegateEncoder.Encode(rawPassword)

		assert.NoError(t, err)
		assert.NotEqual(t, rawPassword, encodedPassword)
		assert.True(t, delegateEncoder.Matches(rawPassword, encodedPassword))
		assert.False(t, delegateEncoder.Matches(rawPassword+"a", encodedPassword))

		prefixEncodedPassword := delegatingEncoder.idPrefix + encoderId + delegatingEncoder.idSuffix + encodedPassword
		assert.True(t, delegatingEncoder.Matches(rawPassword, prefixEncodedPassword))
		assert.False(t, delegatingEncoder.Matches(rawPassword+"a", prefixEncodedPassword))
	}

	t.Run("no prefix", func(t *testing.T) {
		assert.False(t, delegatingEncoder.Matches("password", "password"))
	})
}

func TestDelegatingPasswordEncoder_Encode(t *testing.T) {
	t.Run("err", func(t *testing.T) {
		delegatingEncoder := DelegatingPasswordEncoder{
			passwordEncoderForEncode: &errEncodePasswordEncoder{err: errors.New("WTF")},
		}
		_, err := delegatingEncoder.Encode("?")
		assert.Error(t, err)
	})
}

func TestDelegatingPasswordEncoder_Upgradable(t *testing.T) {

	saltGen := keygen.NewSecureRandomBytesKeyGenerator(8)

	idToPasswordEncoder := map[string]PasswordEncoder{
		"bcrypt": NewBCryptPasswordEncoder(bcrypt.DefaultCost),
		"sm3":    NewSm3PasswordEncoder(saltGen),
		"sha256": NewSha256PasswordEncoder(saltGen),
		"noop":   NopPasswordEncoder(),
	}

	delegatingEncoder := DelegatingPasswordEncoder{
		idPrefix:                 DefaultIdPrefix,
		idSuffix:                 DefaultIdSuffix,
		idForEncode:              "bcrypt",
		passwordEncoderForEncode: idToPasswordEncoder["bcrypt"],
		idToPasswordEncoder:      idToPasswordEncoder,
	}

	t.Run("not upgradable", func(t *testing.T) {
		encodedPassword, err := delegatingEncoder.Encode("password")
		require.NoError(t, err)

		assert.Equal(t, false, delegatingEncoder.Upgradable(encodedPassword))
	})

	t.Run("different encode id", func(t *testing.T) {
		encodedPassword := "{noop}password"

		assert.Equal(t, true, delegatingEncoder.Upgradable(encodedPassword))
	})

	t.Run("encode id not found", func(t *testing.T) {
		idToPasswordEncoder := map[string]PasswordEncoder{
			"bcrypt": NewBCryptPasswordEncoder(bcrypt.DefaultCost),
			"sm3":    NewSm3PasswordEncoder(saltGen),
			"sha256": NewSha256PasswordEncoder(saltGen),
		}

		delegatingEncoder := DelegatingPasswordEncoder{
			idPrefix:                 DefaultIdPrefix,
			idSuffix:                 DefaultIdSuffix,
			idForEncode:              "bcrypt",
			passwordEncoderForEncode: idToPasswordEncoder["bcrypt"],
			idToPasswordEncoder:      idToPasswordEncoder,
		}

		encodedPassword, err := delegatingEncoder.Encode("password")
		require.NoError(t, err)

		delete(delegatingEncoder.idToPasswordEncoder, "bcrypt")

		assert.Equal(t, false, delegatingEncoder.Upgradable(encodedPassword))
	})
}

func Test_extractId(t *testing.T) {
	type args struct {
		prefixEncodedPassword string
		idPrefix              string
		idSuffix              string
	}
	tests := []struct {
		name string
		args args
		want string
	}{
		{
			name: "bcrypt",
			args: args{
				idPrefix: DefaultIdPrefix, idSuffix: DefaultIdSuffix,
				prefixEncodedPassword: "{bcrypt}$2a$10$dXJ3SW6G7P50lGmMkkmwe.20cQQubK3.HZWzG3YB1tlRy.fqvM/BG",
			},
			want: "bcrypt",
		},
		{
			name: "noop",
			args: args{
				idPrefix: DefaultIdPrefix, idSuffix: DefaultIdSuffix,
				prefixEncodedPassword: "{noop}password",
			},
			want: "noop",
		},
		{
			name: "pbkdf2",
			args: args{
				idPrefix: DefaultIdPrefix, idSuffix: DefaultIdSuffix,
				prefixEncodedPassword: "{pbkdf2}5d923b44a6d129f3ddf3e3c8d29412723dcbde72445e8ef6bf3b508fbf17fa4ed4d6b99ca763d8dc",
			},
			want: "pbkdf2",
		},
		{
			name: "scrypt",
			args: args{
				idPrefix: DefaultIdPrefix, idSuffix: DefaultIdSuffix,
				prefixEncodedPassword: "{scrypt}$e0801$8bWJaSu2IKSn9Z9kM+TPXfOc/9bdYSrN1oD9qfVThWEwdRTnO7re7Ei+fUZRJ68k9lTyuTeUp4of4g24hHnazw==$OAOec05+bXxvuu/1qZ6NUR+xQYvYv7BeL1QxwRpY5Pc=",
			},
			want: "scrypt",
		},
		{
			name: "sha256",
			args: args{
				idPrefix: DefaultIdPrefix, idSuffix: DefaultIdSuffix,
				prefixEncodedPassword: "{sha256}97cde38028ad898ebc02e690819fa220e88c62e0699403e94fff291cfffaf8410849f27605abcbc0",
			},
			want: "sha256",
		},

		{
			name: "empty",
			args: args{
				idPrefix: DefaultIdPrefix, idSuffix: DefaultIdSuffix,
				prefixEncodedPassword: "",
			},
			want: "",
		},
		{
			name: "no prefix",
			args: args{
				idPrefix: DefaultIdPrefix, idSuffix: DefaultIdSuffix,
				prefixEncodedPassword: " noop}password",
			},
			want: "",
		},
		{
			name: "no suffix",
			args: args{
				idPrefix: DefaultIdPrefix, idSuffix: DefaultIdSuffix,
				prefixEncodedPassword: "{noop password",
			},
			want: "",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractId(tt.args.prefixEncodedPassword, tt.args.idPrefix, tt.args.idSuffix)
			assert.Equalf(t, tt.want, got, "extractId(%v, %v, %v)", tt.args.prefixEncodedPassword, tt.args.idPrefix, tt.args.idSuffix)
		})
	}
}

func Test_extractEncodedPassword(t *testing.T) {
	type args struct {
		prefixEncodedPassword string
		idSuffix              string
	}
	tests := []struct {
		name string
		args args
		want string
	}{
		{
			name: "bcrypt",
			args: args{
				idSuffix:              DefaultIdSuffix,
				prefixEncodedPassword: "{bcrypt}$2a$10$dXJ3SW6G7P50lGmMkkmwe.20cQQubK3.HZWzG3YB1tlRy.fqvM/BG",
			},
			want: "$2a$10$dXJ3SW6G7P50lGmMkkmwe.20cQQubK3.HZWzG3YB1tlRy.fqvM/BG",
		},
		{
			name: "noop",
			args: args{
				idSuffix:              DefaultIdSuffix,
				prefixEncodedPassword: "{noop}password",
			},
			want: "password",
		},
		{
			name: "pbkdf2",
			args: args{
				idSuffix:              DefaultIdSuffix,
				prefixEncodedPassword: "{pbkdf2}5d923b44a6d129f3ddf3e3c8d29412723dcbde72445e8ef6bf3b508fbf17fa4ed4d6b99ca763d8dc",
			},
			want: "5d923b44a6d129f3ddf3e3c8d29412723dcbde72445e8ef6bf3b508fbf17fa4ed4d6b99ca763d8dc",
		},
		{
			name: "scrypt",
			args: args{
				idSuffix:              DefaultIdSuffix,
				prefixEncodedPassword: "{scrypt}$e0801$8bWJaSu2IKSn9Z9kM+TPXfOc/9bdYSrN1oD9qfVThWEwdRTnO7re7Ei+fUZRJ68k9lTyuTeUp4of4g24hHnazw==$OAOec05+bXxvuu/1qZ6NUR+xQYvYv7BeL1QxwRpY5Pc=",
			},
			want: "$e0801$8bWJaSu2IKSn9Z9kM+TPXfOc/9bdYSrN1oD9qfVThWEwdRTnO7re7Ei+fUZRJ68k9lTyuTeUp4of4g24hHnazw==$OAOec05+bXxvuu/1qZ6NUR+xQYvYv7BeL1QxwRpY5Pc=",
		},
		{
			name: "sha256",
			args: args{
				idSuffix:              DefaultIdSuffix,
				prefixEncodedPassword: "{sha256}97cde38028ad898ebc02e690819fa220e88c62e0699403e94fff291cfffaf8410849f27605abcbc0",
			},
			want: "97cde38028ad898ebc02e690819fa220e88c62e0699403e94fff291cfffaf8410849f27605abcbc0",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equalf(t, tt.want, extractEncodedPassword(tt.args.prefixEncodedPassword, tt.args.idSuffix), "extractEncodedPassword(%v, %v)", tt.args.prefixEncodedPassword, tt.args.idSuffix)
		})
	}
}
