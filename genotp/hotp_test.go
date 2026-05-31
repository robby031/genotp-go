package genotp

import (
	"testing"
)

func TestHOTPRFC4226Vectors(t *testing.T) {
	secret := []byte{
		0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x30,
		0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x30,
	}

	hotp, err := NewHOTP(secret, SHA1, 6)
	if err != nil {
		t.Fatalf("Failed to create HOTP: %v", err)
	}

	expected := []string{
		"755224", "287082", "359152", "969429", "338314",
		"254676", "287922", "162583", "399871", "520489",
	}

	for counter, expectedCode := range expected {
		code, err := hotp.Generate(uint64(counter))
		if err != nil {
			t.Fatalf("Failed to generate code at counter %d: %v", counter, err)
		}
		if code != expectedCode {
			t.Errorf("Counter %d: expected %s, got %s", counter, expectedCode, code)
		}
	}
}

func TestHOTPGeneration(t *testing.T) {
	secret := []byte{
		0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x30,
		0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x30,
	}

	hotp, err := NewHOTP(secret, SHA1, 6)
	if err != nil {
		t.Fatalf("Failed to create HOTP: %v", err)
	}

	code, err := hotp.Generate(1)
	if err != nil {
		t.Fatalf("Failed to generate code: %v", err)
	}

	if len(code) != 6 {
		t.Errorf("Expected code length 6, got %d", len(code))
	}
}

func TestHOTPVerify(t *testing.T) {
	secret := []byte{
		0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x30,
		0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x30,
	}

	hotp, err := NewHOTP(secret, SHA1, 6)
	if err != nil {
		t.Fatalf("Failed to create HOTP: %v", err)
	}

	code, err := hotp.Generate(1)
	if err != nil {
		t.Fatalf("Failed to generate code: %v", err)
	}

	valid, err := hotp.Verify(code, 1)
	if err != nil {
		t.Fatalf("Failed to verify code: %v", err)
	}
	if !valid {
		t.Error("Expected valid code to verify successfully")
	}

	valid, err = hotp.Verify(code, 2)
	if err != nil {
		t.Fatalf("Failed to verify code: %v", err)
	}
	if valid {
		t.Error("Expected code to fail verification at different counter")
	}
}

func TestHOTPInvalidDigits(t *testing.T) {
	secret := []byte{0x31, 0x32, 0x33, 0x34, 0x35}

	_, err := NewHOTP(secret, SHA1, 5)
	if err != ErrInvalidDigits {
		t.Errorf("Expected ErrInvalidDigits, got %v", err)
	}

	_, err = NewHOTP(secret, SHA1, 9)
	if err != ErrInvalidDigits {
		t.Errorf("Expected ErrInvalidDigits, got %v", err)
	}
}

func TestHOTPInvalidSecret(t *testing.T) {
	secret := []byte{}

	_, err := NewHOTP(secret, SHA1, 6)
	if err != ErrInvalidSecret {
		t.Errorf("Expected ErrInvalidSecret, got %v", err)
	}
}

func TestHOTPVerifyWithResync(t *testing.T) {
	secret := []byte{
		0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x30,
		0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x30,
	}

	hotp, err := NewHOTP(secret, SHA1, 6)
	if err != nil {
		t.Fatalf("Failed to create HOTP: %v", err)
	}

	stored := uint64(10)
	userCode, err := hotp.Generate(13)
	if err != nil {
		t.Fatalf("Failed to generate code: %v", err)
	}

	matched, ok, err := hotp.VerifyWithResync(userCode, stored, 5)
	if err != nil {
		t.Fatalf("Failed to verify with resync: %v", err)
	}
	if !ok || matched != 13 {
		t.Errorf("Expected match at counter 13, got matched=%d, ok=%v", matched, ok)
	}

	matched, ok, err = hotp.VerifyWithResync(userCode, stored, 2)
	if err != nil {
		t.Fatalf("Failed to verify with resync: %v", err)
	}
	if ok {
		t.Error("Expected no match with small look-ahead window")
	}
}

func TestHOTPDifferentAlgorithms(t *testing.T) {
	secret := []byte{
		0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x30,
		0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x30,
	}

	hotp256, err := NewHOTP(secret, SHA256, 6)
	if err != nil {
		t.Fatalf("Failed to create HOTP with SHA256: %v", err)
	}
	code256, err := hotp256.Generate(0)
	if err != nil {
		t.Fatalf("Failed to generate code with SHA256: %v", err)
	}
	if len(code256) != 6 {
		t.Errorf("Expected code length 6, got %d", len(code256))
	}

	hotp512, err := NewHOTP(secret, SHA512, 6)
	if err != nil {
		t.Fatalf("Failed to create HOTP with SHA512: %v", err)
	}
	code512, err := hotp512.Generate(0)
	if err != nil {
		t.Fatalf("Failed to generate code with SHA512: %v", err)
	}
	if len(code512) != 6 {
		t.Errorf("Expected code length 6, got %d", len(code512))
	}
}

func TestHOTPBoundEmptyContext(t *testing.T) {
	secret := []byte{
		0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x30,
		0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x30,
	}

	hotp, err := NewHOTP(secret, SHA1, 6)
	if err != nil {
		t.Fatalf("Failed to create HOTP: %v", err)
	}

	empty := NewOtpContext()
	for c := uint64(0); c < 10; c++ {
		standard, err := hotp.Generate(c)
		if err != nil {
			t.Fatalf("Failed to generate standard code: %v", err)
		}
		bound, err := hotp.GenerateBound(c, empty)
		if err != nil {
			t.Fatalf("Failed to generate bound code: %v", err)
		}
		if standard != bound {
			t.Errorf("Counter %d: empty context should equal standard HOTP", c)
		}
	}
}

func TestHOTPBoundDifferentContexts(t *testing.T) {
	secret := []byte{
		0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x30,
		0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x30,
	}

	hotp, err := NewHOTP(secret, SHA1, 6)
	if err != nil {
		t.Fatalf("Failed to create HOTP: %v", err)
	}

	ctx1 := NewOtpContextBuilder().Session("login-123").Build()
	ctx2 := NewOtpContextBuilder().Session("login-999").Build()

	code, err := hotp.GenerateBound(42, ctx1)
	if err != nil {
		t.Fatalf("Failed to generate bound code: %v", err)
	}

	valid, err := hotp.VerifyBound(code, 42, ctx1)
	if err != nil {
		t.Fatalf("Failed to verify bound code: %v", err)
	}
	if !valid {
		t.Error("Expected code to verify with matching context")
	}

	valid, err = hotp.VerifyBound(code, 42, ctx2)
	if err != nil {
		t.Fatalf("Failed to verify bound code: %v", err)
	}
	if valid {
		t.Error("Expected code to fail verification with different context")
	}
}
