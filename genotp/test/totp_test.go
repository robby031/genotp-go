package genotp_test

import (
	"testing"

	"github.com/robby031/genotp-go/genotp"
)

func TestTOTPRFC6238VectorsSHA1(t *testing.T) {
	secret := []byte{
		0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x30,
		0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x30,
	}

	totp, err := genotp.NewTOTP(secret, genotp.SHA1, 8, 30)
	if err != nil {
		t.Fatalf("Failed to create TOTP: %v", err)
	}

	testCases := []struct {
		time     uint64
		expected string
	}{
		{59, "94287082"},
		{1111111109, "07081804"},
		{1111111111, "14050471"},
		{1234567890, "89005924"},
		{2000000000, "69279037"},
		{20000000000, "65353130"},
	}

	for _, tc := range testCases {
		code, err := totp.Generate(&tc.time)
		if err != nil {
			t.Fatalf("Failed to generate code at time %d: %v", tc.time, err)
		}
		if code != tc.expected {
			t.Errorf("Time %d: expected %s, got %s", tc.time, tc.expected, code)
		}
	}
}

func TestTOTPRFC6238VectorsSHA256(t *testing.T) {
	secret := []byte{
		0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x30,
		0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x30,
		0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x30,
		0x31, 0x32,
	}

	totp, err := genotp.NewTOTP(secret, genotp.SHA256, 8, 30)
	if err != nil {
		t.Fatalf("Failed to create TOTP: %v", err)
	}

	code, err := totp.Generate(&[]uint64{59}[0])
	if err != nil {
		t.Fatalf("Failed to generate code: %v", err)
	}

	if len(code) != 8 {
		t.Errorf("Expected code length 8, got %d", len(code))
	}
}

func TestTOTPRFC6238VectorsSHA512(t *testing.T) {
	secret := []byte{
		0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x30,
		0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x30,
		0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x30,
		0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x30,
		0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x30,
		0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x30,
		0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x30,
		0x31, 0x32,
	}

	totp, err := genotp.NewTOTP(secret, genotp.SHA512, 8, 30)
	if err != nil {
		t.Fatalf("Failed to create TOTP: %v", err)
	}

	code, err := totp.Generate(&[]uint64{59}[0])
	if err != nil {
		t.Fatalf("Failed to generate code: %v", err)
	}

	if len(code) != 8 {
		t.Errorf("Expected code length 8, got %d", len(code))
	}
}

func TestTOTPGeneration(t *testing.T) {
	secret := []byte{
		0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x30,
		0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x30,
	}

	totp, err := genotp.NewTOTP(secret, genotp.SHA1, 6, 30)
	if err != nil {
		t.Fatalf("Failed to create TOTP: %v", err)
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

func TestTOTPVerify(t *testing.T) {
	secret := []byte{
		0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x30,
		0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x30,
	}

	totp, err := genotp.NewTOTP(secret, genotp.SHA1, 6, 30)
	if err != nil {
		t.Fatalf("Failed to create TOTP: %v", err)
	}

	timeVal := uint64(1234567890)
	code, err := totp.Generate(&timeVal)
	if err != nil {
		t.Fatalf("Failed to generate code: %v", err)
	}

	valid, err := totp.Verify(code, &timeVal, 1)
	if err != nil {
		t.Fatalf("Failed to verify code: %v", err)
	}
	if !valid {
		t.Error("Expected valid code to verify successfully")
	}
}

func TestTOTPVerifyWithWindow(t *testing.T) {
	secret := []byte{
		0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x30,
		0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x30,
	}

	totp, err := genotp.NewTOTP(secret, genotp.SHA1, 6, 30)
	if err != nil {
		t.Fatalf("Failed to create TOTP: %v", err)
	}

	timeVal := uint64(59)
	code, err := totp.Generate(&timeVal)
	if err != nil {
		t.Fatalf("Failed to generate code: %v", err)
	}

	valid, err := totp.Verify(code, &timeVal, 1)
	if err != nil {
		t.Fatalf("Failed to verify code: %v", err)
	}
	if !valid {
		t.Error("Expected code to verify with window=1")
	}

	valid, err = totp.Verify(code, &[]uint64{89}[0], 1)
	if err != nil {
		t.Fatalf("Failed to verify code: %v", err)
	}
	if !valid {
		t.Error("Expected code to verify at time=89 with window=1")
	}

	valid, err = totp.Verify(code, &[]uint64{119}[0], 1)
	if err != nil {
		t.Fatalf("Failed to verify code: %v", err)
	}
	if valid {
		t.Error("Expected code to fail verification at time=119 with window=1")
	}
}

func TestTOTPInvalidDigits(t *testing.T) {
	secret := []byte{0x31, 0x32, 0x33, 0x34, 0x35}

	_, err := genotp.NewTOTP(secret, genotp.SHA1, 5, 30)
	if err != genotp.ErrInvalidDigits {
		t.Errorf("Expected ErrInvalidDigits, got %v", err)
	}

	_, err = genotp.NewTOTP(secret, genotp.SHA1, 9, 30)
	if err != genotp.ErrInvalidDigits {
		t.Errorf("Expected ErrInvalidDigits, got %v", err)
	}
}

func TestTOTPInvalidPeriod(t *testing.T) {
	secret := []byte{0x31, 0x32, 0x33, 0x34, 0x35}

	_, err := genotp.NewTOTP(secret, genotp.SHA1, 6, 0)
	if err != genotp.ErrInvalidPeriod {
		t.Errorf("Expected ErrInvalidPeriod, got %v", err)
	}
}

func TestTOTPInvalidSecret(t *testing.T) {
	secret := []byte{}

	_, err := genotp.NewTOTP(secret, genotp.SHA1, 6, 30)
	if err != genotp.ErrInvalidSecret {
		t.Errorf("Expected ErrInvalidSecret, got %v", err)
	}
}

func TestTOTPBoundEmptyContext(t *testing.T) {
	secret := []byte{
		0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x30,
		0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x30,
	}

	totp, err := genotp.NewTOTP(secret, genotp.SHA1, 8, 30)
	if err != nil {
		t.Fatalf("Failed to create TOTP: %v", err)
	}

	empty := genotp.NewOtpContext()
	times := []uint64{59, 1111111109, 1234567890}

	for _, timeVal := range times {
		standard, err := totp.Generate(&timeVal)
		if err != nil {
			t.Fatalf("Failed to generate standard code: %v", err)
		}
		bound, err := totp.GenerateBound(empty, &timeVal)
		if err != nil {
			t.Fatalf("Failed to generate bound code: %v", err)
		}
		if standard != bound {
			t.Errorf("Time %d: empty context should equal standard TOTP", timeVal)
		}
	}
}

func TestTOTPBoundDifferentContexts(t *testing.T) {
	secret := []byte{
		0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x30,
		0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x30,
	}

	totp, err := genotp.NewTOTP(secret, genotp.SHA1, 6, 30)
	if err != nil {
		t.Fatalf("Failed to create TOTP: %v", err)
	}

	ctx1 := genotp.NewOtpContextBuilder().IP("10.0.0.1").Build()
	ctx2 := genotp.NewOtpContextBuilder().IP("10.0.0.2").Build()

	timeVal := uint64(1234567890)
	code1, err := totp.GenerateBound(ctx1, &timeVal)
	if err != nil {
		t.Fatalf("Failed to generate bound code: %v", err)
	}

	code2, err := totp.GenerateBound(ctx2, &timeVal)
	if err != nil {
		t.Fatalf("Failed to generate bound code: %v", err)
	}

	if code1 == code2 {
		t.Error("Different contexts should produce different codes")
	}
}

func TestTOTPVerifyBound(t *testing.T) {
	secret := []byte{
		0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x30,
		0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x30,
	}

	totp, err := genotp.NewTOTP(secret, genotp.SHA1, 6, 30)
	if err != nil {
		t.Fatalf("Failed to create TOTP: %v", err)
	}

	ctx := genotp.NewOtpContextBuilder().Session("s1").Build()
	timeVal := uint64(60)
	code, err := totp.GenerateBound(ctx, &timeVal)
	if err != nil {
		t.Fatalf("Failed to generate bound code: %v", err)
	}

	valid, err := totp.VerifyBound(code, ctx, &[]uint64{90}[0], 1)
	if err != nil {
		t.Fatalf("Failed to verify bound code: %v", err)
	}
	if !valid {
		t.Error("Expected code to verify with window=1")
	}

	valid, err = totp.VerifyBound(code, ctx, &[]uint64{150}[0], 1)
	if err != nil {
		t.Fatalf("Failed to verify bound code: %v", err)
	}
	if valid {
		t.Error("Expected code to fail verification at time=150 with window=1")
	}
}
