package password

import "golang.org/x/crypto/bcrypt"

type BCryptPasswordEncoder struct {
	cost int // cost is exponential
}

func NewBCryptPasswordEncoder(cost int) *BCryptPasswordEncoder {
	return &BCryptPasswordEncoder{cost: cost}
}

var _ PasswordEncoder = (*BCryptPasswordEncoder)(nil)

func (e *BCryptPasswordEncoder) Encode(rawPassword string) (string, error) {
	encodedPassword, err := bcrypt.GenerateFromPassword([]byte(rawPassword), e.cost)
	if err != nil {
		return "", err
	}
	return string(encodedPassword), nil
}

func (e *BCryptPasswordEncoder) Matches(rawPassword string, encodedPassword string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(encodedPassword), []byte(rawPassword))
	return err == nil
}

func (e *BCryptPasswordEncoder) UpgradeEncoding(encodedPassword string) bool {
	// TODO: compare cost
	return false
}
