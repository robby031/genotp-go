package genotp_test

import (
	"crypto/hmac"
	"crypto/sha1"
	"crypto/sha256"
	"errors"
	"testing"

	"github.com/robby031/genotp-go"
)

func TestHOTPFromSecretProviderMatchesStaticSecret(t *testing.T) {
	secret := []byte("12345678901234567890")

	staticHOTP, err := genotp.NewHOTP(secret, genotp.SHA1, 6)
	if err != nil {
		t.Fatalf("NewHOTP: %v", err)
	}

	providerCalls := 0
	providerHOTP, err := genotp.NewHOTPFromSecretProvider(genotp.SecretProviderFunc(func() ([]byte, error) {
		providerCalls++
		return append([]byte(nil), secret...), nil
	}), genotp.SHA1, 6)
	if err != nil {
		t.Fatalf("NewHOTPFromSecretProvider: %v", err)
	}

	expected, err := staticHOTP.Generate(7)
	if err != nil {
		t.Fatalf("static Generate: %v", err)
	}
	got, err := providerHOTP.Generate(7)
	if err != nil {
		t.Fatalf("provider Generate: %v", err)
	}

	if got != expected {
		t.Fatalf("provider HOTP mismatch: got %q want %q", got, expected)
	}
	if providerCalls == 0 {
		t.Fatal("provider should be called at least once")
	}
}

func TestTOTPFromSecretProviderMatchesStaticSecret(t *testing.T) {
	secret := []byte("12345678901234567890")
	timeVal := uint64(1234567890)

	staticTOTP, err := genotp.NewTOTP(secret, genotp.SHA256, 6, 30)
	if err != nil {
		t.Fatalf("NewTOTP: %v", err)
	}

	providerTOTP, err := genotp.NewTOTPFromSecretProvider(genotp.SecretProviderFunc(func() ([]byte, error) {
		return append([]byte(nil), secret...), nil
	}), genotp.SHA256, 6, 30)
	if err != nil {
		t.Fatalf("NewTOTPFromSecretProvider: %v", err)
	}

	expected, err := staticTOTP.Generate(&timeVal)
	if err != nil {
		t.Fatalf("static Generate: %v", err)
	}
	got, err := providerTOTP.Generate(&timeVal)
	if err != nil {
		t.Fatalf("provider Generate: %v", err)
	}

	if got != expected {
		t.Fatalf("provider TOTP mismatch: got %q want %q", got, expected)
	}
}

func TestSecretProviderErrorPropagates(t *testing.T) {
	providerErr := errors.New("kms unwrap failed")
	hotp, err := genotp.NewHOTPFromSecretProvider(genotp.SecretProviderFunc(func() ([]byte, error) {
		return nil, providerErr
	}), genotp.SHA1, 6)
	if err != nil {
		t.Fatalf("NewHOTPFromSecretProvider: %v", err)
	}

	_, err = hotp.Generate(1)
	if !errors.Is(err, genotp.ErrSecretProvider) {
		t.Fatalf("expected ErrSecretProvider, got %v", err)
	}
	if !errors.Is(err, providerErr) {
		t.Fatalf("expected wrapped provider error, got %v", err)
	}
}

func TestProviderBackedClearSecretBlocksUsage(t *testing.T) {
	totp, err := genotp.NewTOTPFromSecretProvider(genotp.SecretProviderFunc(func() ([]byte, error) {
		return []byte("12345678901234567890"), nil
	}), genotp.SHA1, 6, 30)
	if err != nil {
		t.Fatalf("NewTOTPFromSecretProvider: %v", err)
	}

	totp.ClearSecret()
	timeVal := uint64(1234567890)

	if _, err := totp.Generate(&timeVal); !errors.Is(err, genotp.ErrInvalidSecret) {
		t.Fatalf("Generate after ClearSecret: got %v want ErrInvalidSecret", err)
	}
}

func TestHOTPFromHMACProviderMatchesStaticSecret(t *testing.T) {
	secret := []byte("12345678901234567890")

	staticHOTP, err := genotp.NewHOTP(secret, genotp.SHA1, 6)
	if err != nil {
		t.Fatalf("NewHOTP: %v", err)
	}

	providerCalls := 0
	providerHOTP, err := genotp.NewHOTPFromHMACProvider(genotp.HMACProviderFunc(func(algorithm genotp.Algorithm, message []byte) ([]byte, error) {
		providerCalls++
		if algorithm != genotp.SHA1 {
			t.Fatalf("unexpected algorithm: %v", algorithm)
		}
		mac := hmac.New(sha1.New, secret)
		mac.Write(message)
		return mac.Sum(nil), nil
	}), genotp.SHA1, 6)
	if err != nil {
		t.Fatalf("NewHOTPFromHMACProvider: %v", err)
	}

	expected, err := staticHOTP.Generate(12)
	if err != nil {
		t.Fatalf("static Generate: %v", err)
	}
	got, err := providerHOTP.Generate(12)
	if err != nil {
		t.Fatalf("provider Generate: %v", err)
	}

	if got != expected {
		t.Fatalf("provider HOTP mismatch: got %q want %q", got, expected)
	}
	if providerCalls == 0 {
		t.Fatal("HMAC provider should be called at least once")
	}
}

func TestTOTPFromHMACProviderMatchesStaticSecret(t *testing.T) {
	secret := []byte("12345678901234567890")
	timeVal := uint64(1234567890)
	ctx := genotp.NewOtpContextBuilder().
		Session("sess-1").
		Region("id-jkts-sudirman").
		Build()

	staticTOTP, err := genotp.NewTOTP(secret, genotp.SHA256, 6, 30)
	if err != nil {
		t.Fatalf("NewTOTP: %v", err)
	}

	providerTOTP, err := genotp.NewTOTPFromHMACProvider(genotp.HMACProviderFunc(func(algorithm genotp.Algorithm, message []byte) ([]byte, error) {
		if algorithm != genotp.SHA256 {
			t.Fatalf("unexpected algorithm: %v", algorithm)
		}
		mac := hmac.New(sha256.New, secret)
		mac.Write(message)
		return mac.Sum(nil), nil
	}), genotp.SHA256, 6, 30)
	if err != nil {
		t.Fatalf("NewTOTPFromHMACProvider: %v", err)
	}

	expected, err := staticTOTP.GenBound(ctx, &timeVal)
	if err != nil {
		t.Fatalf("static GenBound: %v", err)
	}
	got, err := providerTOTP.GenBound(ctx, &timeVal)
	if err != nil {
		t.Fatalf("provider GenBound: %v", err)
	}

	if got != expected {
		t.Fatalf("provider TOTP mismatch: got %q want %q", got, expected)
	}
}

func TestHMACProviderErrorPropagates(t *testing.T) {
	providerErr := errors.New("hsm sign failed")
	totp, err := genotp.NewTOTPFromHMACProvider(genotp.HMACProviderFunc(func(algorithm genotp.Algorithm, message []byte) ([]byte, error) {
		return nil, providerErr
	}), genotp.SHA1, 6, 30)
	if err != nil {
		t.Fatalf("NewTOTPFromHMACProvider: %v", err)
	}

	timeVal := uint64(1234567890)
	_, err = totp.Generate(&timeVal)
	if !errors.Is(err, genotp.ErrHMACProvider) {
		t.Fatalf("expected ErrHMACProvider, got %v", err)
	}
	if !errors.Is(err, providerErr) {
		t.Fatalf("expected wrapped provider error, got %v", err)
	}
}

func TestHMACProviderBackedClearSecretBlocksUsage(t *testing.T) {
	hotp, err := genotp.NewHOTPFromHMACProvider(genotp.HMACProviderFunc(func(algorithm genotp.Algorithm, message []byte) ([]byte, error) {
		mac := hmac.New(sha1.New, []byte("12345678901234567890"))
		mac.Write(message)
		return mac.Sum(nil), nil
	}), genotp.SHA1, 6)
	if err != nil {
		t.Fatalf("NewHOTPFromHMACProvider: %v", err)
	}

	hotp.ClearSecret()
	if _, err := hotp.Generate(1); !errors.Is(err, genotp.ErrInvalidSecret) {
		t.Fatalf("Generate after ClearSecret: got %v want ErrInvalidSecret", err)
	}
}
