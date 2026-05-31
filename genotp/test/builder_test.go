package genotp_test

import (
	"testing"

	"github.com/robby031/genotp-go/genotp"
)

func TestHotpBuilder(t *testing.T) {
	secret := []byte{
		0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x30,
		0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x30,
	}

	hotp, err := genotp.NewHotpBuilder().
		Secret(secret).
		Algorithm(genotp.SHA1).
		Digits(6).
		Build()

	if err != nil {
		t.Fatalf("Failed to build HOTP: %v", err)
	}

	code, err := hotp.Generate(0)
	if err != nil {
		t.Fatalf("Failed to generate code: %v", err)
	}

	if len(code) != 6 {
		t.Errorf("Expected code length 6, got %d", len(code))
	}
}

func TestHotpBuilderWithoutSecret(t *testing.T) {
	_, err := genotp.NewHotpBuilder().Build()
	if err != genotp.ErrInvalidSecret {
		t.Errorf("Expected ErrInvalidSecret, got %v", err)
	}
}

func TestTotpBuilder(t *testing.T) {
	secret := []byte{
		0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x30,
		0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x30,
	}

	totp, err := genotp.NewTotpBuilder().
		Secret(secret).
		Algorithm(genotp.SHA1).
		Digits(6).
		Period(30).
		Build()

	if err != nil {
		t.Fatalf("Failed to build TOTP: %v", err)
	}

	timeVal := uint64(1234567890)
	code, err := totp.Generate(&timeVal)
	if err != nil {
		t.Fatalf("Failed to generate code: %v", err)
	}

	if len(code) != 6 {
		t.Errorf("Expected code length 6, got %d", len(code))
	}
}

func TestTotpBuilderWithoutSecret(t *testing.T) {
	_, err := genotp.NewTotpBuilder().Build()
	if err != genotp.ErrInvalidSecret {
		t.Errorf("Expected ErrInvalidSecret, got %v", err)
	}
}

func TestHotpBuilderDefaults(t *testing.T) {
	secret := []byte{
		0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x30,
		0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x30,
	}

	hotp, err := genotp.NewHotpBuilder().Secret(secret).Build()
	if err != nil {
		t.Fatalf("Failed to build HOTP: %v", err)
	}

	code, err := hotp.Generate(0)
	if err != nil {
		t.Fatalf("Failed to generate code: %v", err)
	}

	if len(code) != 6 {
		t.Errorf("Expected default code length 6, got %d", len(code))
	}
}

func TestTotpBuilderDefaults(t *testing.T) {
	secret := []byte{
		0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x30,
		0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x30,
	}

	totp, err := genotp.NewTotpBuilder().Secret(secret).Build()
	if err != nil {
		t.Fatalf("Failed to build TOTP: %v", err)
	}

	timeVal := uint64(1234567890)
	code, err := totp.Generate(&timeVal)
	if err != nil {
		t.Fatalf("Failed to generate code: %v", err)
	}

	if len(code) != 6 {
		t.Errorf("Expected default code length 6, got %d", len(code))
	}
}
