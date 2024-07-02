package password

import (
	"fmt"
	"strings"
)

const (
	DefaultIdPrefix = "{"
	DefaultIdSuffix = "}"
)

// https://docs.spring.io/spring-security/site/docs/5.6.0/api/org/springframework/security/crypto/password/DelegatingPasswordEncoder.html
type DelegatingPasswordEncoder struct {
	idPrefix    string
	idSuffix    string
	idForEncode string

	passwordEncoderForEncode PasswordEncoder
	idToPasswordEncoder      map[string]PasswordEncoder
}

// TODO: options / builder
func NewDelegatingPasswordEncoder(idForEncode string, idToPasswordEncoder map[string]PasswordEncoder) *DelegatingPasswordEncoder {
	passwordEncoderForEncode := idToPasswordEncoder[idForEncode]

	if passwordEncoderForEncode == nil {
		panic(fmt.Errorf("idForEncode %q is not found in idToPasswordEncoder %+v", idForEncode, idToPasswordEncoder))
	}

	return &DelegatingPasswordEncoder{
		idPrefix:    DefaultIdPrefix,
		idSuffix:    DefaultIdSuffix,
		idForEncode: idForEncode,

		passwordEncoderForEncode: passwordEncoderForEncode,

		idToPasswordEncoder: idToPasswordEncoder,
	}
}

func (e *DelegatingPasswordEncoder) Encode(rawPassword string) (string, error) {
	encodedPassword, err := e.passwordEncoderForEncode.Encode(rawPassword)
	if err != nil {
		return "", err
	}
	return e.idPrefix + e.idForEncode + e.idSuffix + encodedPassword, nil
}

func (e *DelegatingPasswordEncoder) Matches(rawPassword string, prefixEncodedPassword string) bool {
	id := extractId(prefixEncodedPassword, e.idPrefix, e.idSuffix)
	delegate, ok := e.idToPasswordEncoder[id]
	if !ok {
		// "There is no PasswordEncoder mapped for the id \"" + id + "\""
		return false
	}
	encodedPassword := extractEncodedPassword(prefixEncodedPassword, e.idSuffix)
	return delegate.Matches(rawPassword, encodedPassword)
}

func (e *DelegatingPasswordEncoder) UpgradeEncoding(prefixEncodedPassword string) bool {
	id := extractId(prefixEncodedPassword, e.idPrefix, e.idSuffix)

	if e.idForEncode != id {
		return true
	}

	delegate, ok := e.idToPasswordEncoder[id]
	if !ok {
		// "There is no PasswordEncoder mapped for the id \"" + id + "\""
		return false
	}

	encodedPassword := extractEncodedPassword(prefixEncodedPassword, e.idSuffix)
	return delegate.UpgradeEncoding(encodedPassword)
}

func extractId(prefixEncodedPassword string, idPrefix, idSuffix string) string {
	if prefixEncodedPassword == "" {
		return ""
	}
	start := strings.Index(prefixEncodedPassword, idPrefix)
	if start != 0 {
		return ""
	}
	end := strings.Index(prefixEncodedPassword, idSuffix)
	if end < 0 {
		return ""
	}
	return prefixEncodedPassword[start+len(idPrefix) : end]
}

func extractEncodedPassword(prefixEncodedPassword, idSuffix string) string {
	start := strings.Index(prefixEncodedPassword, idSuffix)
	return prefixEncodedPassword[start+len(idSuffix):]
}
