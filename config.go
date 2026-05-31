package genotp

type HotpConfig struct {
	Secret    []byte
	Algorithm Algorithm
	Digits    uint32
}

func (c *HotpConfig) ToHOTP() (*HOTP, error) {
	return NewHOTP(c.Secret, c.Algorithm, c.Digits)
}

type TotpConfig struct {
	Secret    []byte
	Algorithm Algorithm
	Digits    uint32
	Period    uint64
}

func (c *TotpConfig) ToTOTP() (*TOTP, error) {
	return NewTOTP(c.Secret, c.Algorithm, c.Digits, c.Period)
}
