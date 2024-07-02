package password

type errEncodePasswordEncoder struct {
	PasswordEncoder
	err error
}

func (e *errEncodePasswordEncoder) Encode(rawPassword string) (string, error) {
	return "", e.err
}
