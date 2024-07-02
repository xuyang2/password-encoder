package password

import (
	"bytes"
	"encoding/hex"

	"github.com/emmansun/gmsm/sm3"

	"github.com/xuyang2/password-encoder/keygen"
)

type Sm3PasswordEncoder struct {
	saltGen keygen.BytesKeyGenerator
}

func NewSm3PasswordEncoder(saltGen keygen.BytesKeyGenerator) *Sm3PasswordEncoder {
	return &Sm3PasswordEncoder{saltGen: saltGen}
}

var _ PasswordEncoder = (*Sm3PasswordEncoder)(nil)

func (e *Sm3PasswordEncoder) Encode(rawPassword string) (string, error) {
	salt, err := e.saltGen.GenerateKey()
	if err != nil {
		return "", err
	}
	digest := e.digest(rawPassword, salt)
	return hex.EncodeToString(digest), nil
}

func (e *Sm3PasswordEncoder) Matches(rawPassword string, encodedPassword string) bool {
	digested, err := hex.DecodeString(encodedPassword)
	if err != nil {
		return false
	}

	if len(digested) < sm3.Size {
		return false
	}
	salt := make([]byte, len(digested)-sm3.Size)
	copy(salt, digested[0:len(digested)-sm3.Size])

	return bytes.Equal(digested, e.digest(rawPassword, salt))
}

// return salt + sm3(salt + rawPassword)
func (e *Sm3PasswordEncoder) digest(rawPassword string, salt []byte) []byte {
	var bb bytes.Buffer
	bb.Write(salt)
	bb.Write([]byte(rawPassword))
	saltPassword := bb.Bytes()
	digest := sm3.Sum(saltPassword)
	saltDigest := append(salt[:], digest[:]...)
	return saltDigest
}

func (e *Sm3PasswordEncoder) Upgradable(encodedPassword string) bool {
	return false
}
