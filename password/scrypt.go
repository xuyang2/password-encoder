package password

import (
	"bytes"
	"encoding/base64"
	"math"
	"strconv"
	"strings"

	"golang.org/x/crypto/scrypt"

	"github.com/xuyang2/password-encoder/keygen"
)

type SCryptPasswordEncoder struct {
	saltGen keygen.BytesKeyGenerator

	cpuCost         int // cpu cost of the algorithm (as defined in scrypt this is N)
	memoryCost      int // memory cost of the algorithm (as defined in scrypt this is r)
	parallelization int // the parallelization of the algorithm (as defined in scrypt this is p)
	keyLen          int
}

var _ PasswordEncoder = (*SCryptPasswordEncoder)(nil)

func DefaultSCryptPasswordEncoder() *SCryptPasswordEncoder {
	saltLen := 16
	saltGen := keygen.NewSecureRandomBytesKeyGenerator(saltLen)
	return &SCryptPasswordEncoder{
		saltGen:         saltGen,
		cpuCost:         65536,
		memoryCost:      8,
		parallelization: 1,
		keyLen:          32,
	}
}

func (e *SCryptPasswordEncoder) Encode(rawPassword string) (string, error) {
	salt, err := e.saltGen.GenerateKey()
	if err != nil {
		return "", err
	}

	derived, err := scrypt.Key([]byte(rawPassword), salt, e.cpuCost, e.memoryCost, e.parallelization, e.keyLen)
	return e.encode(derived, salt), nil
}

func (e *SCryptPasswordEncoder) encode(derived, salt []byte) string {
	params := ((int)(math.Log2(float64(e.cpuCost))) << 16) | e.memoryCost<<8 | e.parallelization
	var sb strings.Builder
	sb.WriteString("$")
	sb.WriteString(strconv.FormatInt(int64(params), 16))
	sb.WriteString("$")
	sb.WriteString(e.encodePart(salt))
	sb.WriteString("$")
	sb.WriteString(e.encodePart(derived))
	return sb.String()
}

func (e *SCryptPasswordEncoder) encodePart(part []byte) string {
	encoded := base64.StdEncoding.EncodeToString(part)
	// encoded = strings.Replace(encoded, "\n", "", -1)
	return encoded
}

func (e *SCryptPasswordEncoder) Matches(rawPassword string, encodedPassword string) bool {
	parts := strings.Split(encodedPassword, "$")
	if len(parts) != 4 { // ["", params, salt, derived]
		return false
	}

	params, err := strconv.ParseInt(parts[1], 16, 64)
	if err != nil {
		return false
	}

	salt, err := base64.StdEncoding.DecodeString(parts[2])
	if err != nil {
		return false
	}

	derived, err := base64.StdEncoding.DecodeString(parts[3])
	if err != nil {
		return false
	}

	cpuCost := int(math.Pow(2, float64(params>>16&0xffff)))
	memoryCost := int(params) >> 8 & 0xff
	parallelization := int(params) & 0xff

	generated, err := scrypt.Key([]byte(rawPassword), salt, cpuCost, memoryCost, parallelization, e.keyLen)

	return bytes.Equal(derived, generated)
}

func (e *SCryptPasswordEncoder) UpgradeEncoding(encodedPassword string) bool {
	// TODO: compare cost
	return false
}
