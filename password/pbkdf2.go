package password

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"hash"

	"golang.org/x/crypto/pbkdf2"

	"github.com/xuyang2/password-encoder/keygen"
)

type Pbkdf2PasswordEncoder struct {
	saltGen keygen.BytesKeyGenerator
	iter    int
	keyLen  int
	h       func() hash.Hash
}

var _ PasswordEncoder = (*Pbkdf2PasswordEncoder)(nil)

// Pbkdf2PasswordEncoder.defaultsForSpringSecurity_v5_8()
func DefaultPbkdf2PasswordEncoder() *Pbkdf2PasswordEncoder {
	saltLen := 16
	saltGen := keygen.NewSecureRandomBytesKeyGenerator(saltLen)
	return &Pbkdf2PasswordEncoder{
		saltGen: saltGen,
		iter:    310000,
		keyLen:  sha256.Size, // 32 bytes for SHA-256
		h:       sha256.New,
	}
}

func (e *Pbkdf2PasswordEncoder) Encode(rawPassword string) (string, error) {
	salt, err := e.saltGen.GenerateKey()
	if err != nil {
		return "", err
	}
	saltKey := e.encode(rawPassword, salt)
	return hex.EncodeToString(saltKey), nil
}

func (e *Pbkdf2PasswordEncoder) encode(rawPassword string, salt []byte) []byte {
	key := pbkdf2.Key([]byte(rawPassword), salt, e.iter, e.keyLen, e.h)
	saltKey := bytes.NewBuffer(make([]byte, 0, len(salt)+len(key)))
	saltKey.Write(salt)
	saltKey.Write(key)
	return saltKey.Bytes()
}

func (e *Pbkdf2PasswordEncoder) Matches(rawPassword string, encodedPassword string) bool {
	saltKey, err := hex.DecodeString(encodedPassword)
	if err != nil {
		return false
	}

	// extract salt
	if len(saltKey) < e.keyLen {
		return false
	}
	salt := make([]byte, len(saltKey)-e.keyLen)
	copy(salt, saltKey[0:len(saltKey)-e.keyLen])

	return bytes.Equal(saltKey, e.encode(rawPassword, salt))
}

func (e *Pbkdf2PasswordEncoder) UpgradeEncoding(encodedPassword string) bool {
	return false
}
