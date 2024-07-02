package password

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"

	"github.com/xuyang2/password-encoder/keygen"
)

// Deprecated
type Sha256PasswordEncoder struct {
	saltGen keygen.BytesKeyGenerator
}

var _ PasswordEncoder = (*Sha256PasswordEncoder)(nil)

// Deprecated
func NewSha256PasswordEncoder(saltGen keygen.BytesKeyGenerator) *Sha256PasswordEncoder {
	return &Sha256PasswordEncoder{saltGen: saltGen}
}

func (e *Sha256PasswordEncoder) Encode(rawPassword string) (string, error) {
	salt, err := e.saltGen.GenerateKey()
	if err != nil {
		return "", err
	}
	digest := e.digest(rawPassword, salt)
	return hex.EncodeToString(digest), nil
}

func (e *Sha256PasswordEncoder) Matches(rawPassword string, encodedPassword string) bool {
	digested, err := hex.DecodeString(encodedPassword)
	if err != nil {
		return false
	}

	salt := make([]byte, len(digested)-sha256.Size)
	copy(salt, digested[0:len(digested)-sha256.Size])

	return bytes.Equal(digested, e.digest(rawPassword, salt))
}

// return salt + sha1(salt + rawPassword)
func (e *Sha256PasswordEncoder) digest(rawPassword string, salt []byte) []byte {
	var bb bytes.Buffer
	bb.Write(salt)
	bb.Write([]byte(rawPassword))
	saltPassword := bb.Bytes()
	digest := sha256.Sum256(saltPassword)
	saltDigest := append(salt[:], digest[:]...)
	return saltDigest
}

func (e *Sha256PasswordEncoder) Upgradable(encodedPassword string) bool {
	return false
}
