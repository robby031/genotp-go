package genotp

import (
	"testing"
)

func TestGenerateHotpDefault(t *testing.T) {
	secret := []byte{
		0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x30,
		0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x30,
	}

	code, err := GenerateHotpDefault(secret, 0)
	if err != nil {
		t.Fatalf("Failed to generate HOTP: %v", err)
	}

	if len(code) != 6 {
		t.Errorf("Expected code length 6, got %d", len(code))
	}
}

func TestGenerateTotpDefault(t *testing.T) {
	secret := []byte{
		0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x30,
		0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x30,
	}

	code, err := GenerateTotpDefault(secret)
	if err != nil {
		t.Fatalf("Failed to generate TOTP: %v", err)
	}

	if len(code) != 6 {
		t.Errorf("Expected code length 6, got %d", len(code))
	}
}

func TestVerifyHotpDefault(t *testing.T) {
	secret := []byte{
		0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x30,
		0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x30,
	}

	code, err := GenerateHotpDefault(secret, 0)
	if err != nil {
		t.Fatalf("Failed to generate HOTP: %v", err)
	}

	valid, err := VerifyHotpDefault(secret, code, 0)
	if err != nil {
		t.Fatalf("Failed to verify HOTP: %v", err)
	}
	if !valid {
		t.Error("Expected code to verify successfully")
	}
}

func TestVerifyTotpDefault(t *testing.T) {
	secret := []byte{
		0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x30,
		0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x30,
	}

	code, err := GenerateTotpDefault(secret)
	if err != nil {
		t.Fatalf("Failed to generate TOTP: %v", err)
	}

	valid, err := VerifyTotpDefault(secret, code)
	if err != nil {
		t.Fatalf("Failed to verify TOTP: %v", err)
	}
	if !valid {
		t.Error("Expected code to verify successfully")
	}
}

func TestCreateSecret(t *testing.T) {
	secret, err := CreateSecret()
	if err != nil {
		t.Fatalf("Failed to create secret: %v", err)
	}

	if len(secret) != DefaultSecretBytes {
		t.Errorf("Expected secret length %d, got %d", DefaultSecretBytes, len(secret))
	}
}
