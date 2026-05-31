package genotp

type HotpBuilder struct {
	secret    []byte
	algorithm Algorithm
	digits    uint32
}

func NewHotpBuilder() *HotpBuilder {
	return &HotpBuilder{
		algorithm: SHA1,
		digits:    6,
	}
}

func (b *HotpBuilder) Secret(secret []byte) *HotpBuilder {
	b.secret = secret
	return b
}

func (b *HotpBuilder) Algorithm(algorithm Algorithm) *HotpBuilder {
	b.algorithm = algorithm
	return b
}

func (b *HotpBuilder) Digits(digits uint32) *HotpBuilder {
	b.digits = digits
	return b
}

func (b *HotpBuilder) Build() (*HOTP, error) {
	if len(b.secret) == 0 {
		return nil, ErrInvalidSecret
	}
	return NewHOTP(b.secret, b.algorithm, b.digits)
}

type TotpBuilder struct {
	secret    []byte
	algorithm Algorithm
	digits    uint32
	period    uint64
}

func NewTotpBuilder() *TotpBuilder {
	return &TotpBuilder{
		algorithm: SHA1,
		digits:    6,
		period:    30,
	}
}

func (b *TotpBuilder) Secret(secret []byte) *TotpBuilder {
	b.secret = secret
	return b
}

func (b *TotpBuilder) Algorithm(algorithm Algorithm) *TotpBuilder {
	b.algorithm = algorithm
	return b
}

func (b *TotpBuilder) Digits(digits uint32) *TotpBuilder {
	b.digits = digits
	return b
}

func (b *TotpBuilder) Period(period uint64) *TotpBuilder {
	b.period = period
	return b
}

func (b *TotpBuilder) Build() (*TOTP, error) {
	if len(b.secret) == 0 {
		return nil, ErrInvalidSecret
	}
	return NewTOTP(b.secret, b.algorithm, b.digits, b.period)
}
