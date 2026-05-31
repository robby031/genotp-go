package genotp

type HotpConfig struct {
	Algorithm Algorithm
	Digits    uint32
}

func NewHotpConfig() HotpConfig {
	return HotpConfig{
		Algorithm: SHA1,
		Digits:    6,
	}
}

func (c HotpConfig) WithAlgorithm(algorithm Algorithm) HotpConfig {
	c.Algorithm = algorithm
	return c
}

func (c HotpConfig) WithDigits(digits uint32) HotpConfig {
	c.Digits = digits
	return c
}

func NewHotpFromConfig(secret []byte, c HotpConfig) (*HOTP, error) {
	return NewHOTP(secret, c.Algorithm, c.Digits)
}

type TotpConfig struct {
	Algorithm Algorithm
	Digits    uint32
	Period    uint64
}

func NewTotpConfig() TotpConfig {
	return TotpConfig{
		Algorithm: SHA1,
		Digits:    6,
		Period:    30,
	}
}

func (c TotpConfig) WithAlgorithm(algorithm Algorithm) TotpConfig {
	c.Algorithm = algorithm
	return c
}

func (c TotpConfig) WithDigits(digits uint32) TotpConfig {
	c.Digits = digits
	return c
}

func (c TotpConfig) WithPeriod(period uint64) TotpConfig {
	c.Period = period
	return c
}

func NewTotpFromConfig(secret []byte, c TotpConfig) (*TOTP, error) {
	return NewTOTP(secret, c.Algorithm, c.Digits, c.Period)
}
