package password

// https://docs.spring.io/spring-security/site/docs/5.6.0/api/org/springframework/security/crypto/password/PasswordEncoder.html
type PasswordEncoder interface {
	Encode(rawPassword string) (string, error)

	Matches(rawPassword string, encodedPassword string) bool

	Upgradable(encodedPassword string) bool
}
