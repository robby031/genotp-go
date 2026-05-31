package genotp

func GenerateHotpDefault(secret []byte, counter uint64) (string, error) {
	hotp, err := NewHOTP(secret, SHA1, 6)
	if err != nil {
		return "", err
	}
	return hotp.Generate(counter)
}

func GenerateTotpDefault(secret []byte) (string, error) {
	totp, err := NewTOTP(secret, SHA1, 6, 30)
	if err != nil {
		return "", err
	}
	return totp.Generate(nil)
}

func VerifyHotpDefault(secret []byte, code string, counter uint64) (bool, error) {
	hotp, err := NewHOTP(secret, SHA1, 6)
	if err != nil {
		return false, err
	}
	return hotp.Verify(code, counter)
}

func VerifyTotpDefault(secret []byte, code string) (bool, error) {
	totp, err := NewTOTP(secret, SHA1, 6, 30)
	if err != nil {
		return false, err
	}
	return totp.Verify(code, nil, 1)
}
