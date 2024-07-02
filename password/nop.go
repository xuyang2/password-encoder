package password

// Deprecated. For testing purposes only
func NopPasswordEncoder() PasswordEncoder {
	return nopPasswordEncoder{}
}

type nopPasswordEncoder struct{}

func (e nopPasswordEncoder) Encode(rawPassword string) (string, error) {
	return rawPassword, nil
}

func (e nopPasswordEncoder) Matches(rawPassword string, encodedPassword string) bool {
	return rawPassword == encodedPassword
}

func (e nopPasswordEncoder) Upgradable(encodedPassword string) bool {
	return false
}
