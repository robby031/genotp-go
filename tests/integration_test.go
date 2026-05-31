package genotp_test

import (
	"testing"

	genotp "github.com/robby031/genotp-go"
)

func TestHOTPIntegration(t *testing.T) {
	secret := []byte{
		0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x30,
		0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x30,
	}
	hotp, err := genotp.NewHOTP(secret, genotp.SHA1, 6)
	if err != nil {
		t.Fatalf("NewHOTP: %v", err)
	}

	code1, err := hotp.Generate(1)
	if err != nil {
		t.Fatalf("Generate(1): %v", err)
	}
	code2, err := hotp.Generate(2)
	if err != nil {
		t.Fatalf("Generate(2): %v", err)
	}

	if code1 == code2 {
		t.Errorf("expected different codes for counter 1 and 2, got %q", code1)
	}
	if len(code1) != 6 || len(code2) != 6 {
		t.Errorf("expected length 6, got %d and %d", len(code1), len(code2))
	}

	ok, err := hotp.Verify(code1, 1)
	if err != nil || !ok {
		t.Errorf("verify(code1, 1): ok=%v err=%v", ok, err)
	}
	ok, _ = hotp.Verify(code1, 2)
	if ok {
		t.Errorf("verify(code1, 2): expected false, got true")
	}
}

func TestTOTPIntegration(t *testing.T) {
	secret := []byte{
		0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x30,
		0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x30,
	}
	totp, err := genotp.NewTOTP(secret, genotp.SHA1, 6, 30)
	if err != nil {
		t.Fatalf("NewTOTP: %v", err)
	}

	at := uint64(1234567890)
	code, err := totp.Generate(&at)
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if len(code) != 6 {
		t.Errorf("expected length 6, got %d", len(code))
	}

	ok, err := totp.Verify(code, &at, 1)
	if err != nil || !ok {
		t.Errorf("Verify: ok=%v err=%v", ok, err)
	}
}

func TestKeyGenerationIntegration(t *testing.T) {
	kg := &genotp.KeyGen{}

	secret, err := kg.GenerateDefaultSecret()
	if err != nil {
		t.Fatalf("GenerateDefaultSecret: %v", err)
	}
	if len(secret) != 20 {
		t.Errorf("expected default length 20, got %d", len(secret))
	}

	secret256, err := kg.GenerateSecret(256)
	if err != nil {
		t.Fatalf("GenerateSecret(256): %v", err)
	}
	if len(secret256) != 32 {
		t.Errorf("expected length 32, got %d", len(secret256))
	}
}
