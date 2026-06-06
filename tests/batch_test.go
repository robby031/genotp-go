package genotp_test

import (
	"errors"
	"testing"

	"github.com/robby031/genotp-go"
)

func TestHOTPVerifyBatch(t *testing.T) {
	secret := []byte("12345678901234567890")
	hotp, err := genotp.NewHOTP(secret, genotp.SHA1, 6)
	if err != nil {
		t.Fatalf("NewHOTP: %v", err)
	}

	code0, err := hotp.Generate(0)
	if err != nil {
		t.Fatalf("Generate(0): %v", err)
	}
	code1, err := hotp.Generate(1)
	if err != nil {
		t.Fatalf("Generate(1): %v", err)
	}

	results := hotp.VerifyBatch([]genotp.HOTPVerifyRequest{
		{Code: code0, Counter: 0},
		{Code: code1, Counter: 99},
		{Code: code1, Counter: 1},
	})

	if len(results) != 3 {
		t.Fatalf("expected 3 results, got %d", len(results))
	}
	if !results[0].OK || results[0].Err != nil {
		t.Fatalf("result[0] = %+v, want OK", results[0])
	}
	if results[1].OK || results[1].Err != nil {
		t.Fatalf("result[1] = %+v, want false,nil", results[1])
	}
	if !results[2].OK || results[2].Err != nil {
		t.Fatalf("result[2] = %+v, want OK", results[2])
	}
}

func TestHOTPVerifyBoundBatch(t *testing.T) {
	secret := []byte("12345678901234567890")
	hotp, err := genotp.NewHOTP(secret, genotp.SHA1, 6)
	if err != nil {
		t.Fatalf("NewHOTP: %v", err)
	}

	ctxA := genotp.NewOtpContextBuilder().Session("sess-a").Build()
	ctxB := genotp.NewOtpContextBuilder().Session("sess-b").Build()

	code, err := hotp.GenBound(7, ctxA)
	if err != nil {
		t.Fatalf("GenBound: %v", err)
	}

	results := hotp.VerifyBoundBatch([]genotp.HOTPVerifyBoundRequest{
		{Code: code, Counter: 7, Context: ctxA},
		{Code: code, Counter: 7, Context: ctxB},
	})

	if !results[0].OK || results[0].Err != nil {
		t.Fatalf("result[0] = %+v, want OK", results[0])
	}
	if results[1].OK || results[1].Err != nil {
		t.Fatalf("result[1] = %+v, want false,nil", results[1])
	}
}

func TestTOTPVerifyBatch(t *testing.T) {
	secret := []byte("12345678901234567890")
	totp, err := genotp.NewTOTP(secret, genotp.SHA1, 6, 30)
	if err != nil {
		t.Fatalf("NewTOTP: %v", err)
	}

	timeVal := uint64(1234567890)
	code, err := totp.Generate(&timeVal)
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}

	results := totp.VerifyBatch([]genotp.TOTPVerifyRequest{
		{Code: code, Time: &timeVal, Window: 1},
		{Code: code, Time: &timeVal, Window: 1001},
		{Code: "000000", Time: &timeVal, Window: 1},
	})

	if !results[0].OK || results[0].Err != nil {
		t.Fatalf("result[0] = %+v, want OK", results[0])
	}
	if results[1].OK || !errors.Is(results[1].Err, genotp.ErrInvalidTime) {
		t.Fatalf("result[1] = %+v, want ErrInvalidTime", results[1])
	}
	if results[2].OK || results[2].Err != nil {
		t.Fatalf("result[2] = %+v, want false,nil", results[2])
	}
}

func TestTOTPVerifyBoundBatch(t *testing.T) {
	secret := []byte("12345678901234567890")
	totp, err := genotp.NewTOTP(secret, genotp.SHA1, 6, 30)
	if err != nil {
		t.Fatalf("NewTOTP: %v", err)
	}

	timeVal := uint64(1234567890)
	ctxA := genotp.NewOtpContextBuilder().Region("id-jkts-sudirman").Build()
	ctxB := genotp.NewOtpContextBuilder().Region("id-jkts-kuningan").Build()

	code, err := totp.GenBound(ctxA, &timeVal)
	if err != nil {
		t.Fatalf("GenBound: %v", err)
	}

	results := totp.VerifyBoundBatch([]genotp.TOTPVerifyBoundRequest{
		{Code: code, Context: ctxA, Time: &timeVal, Window: 1},
		{Code: code, Context: ctxB, Time: &timeVal, Window: 1},
	})

	if !results[0].OK || results[0].Err != nil {
		t.Fatalf("result[0] = %+v, want OK", results[0])
	}
	if results[1].OK || results[1].Err != nil {
		t.Fatalf("result[1] = %+v, want false,nil", results[1])
	}
}

func TestBatchVerificationPropagatesProviderErrorsPerItem(t *testing.T) {
	callCount := 0
	hotp, err := genotp.NewHOTPFromSecretProvider(genotp.SecretProviderFunc(func() ([]byte, error) {
		callCount++
		if callCount == 3 {
			return nil, errors.New("temporary kms failure")
		}
		return []byte("12345678901234567890"), nil
	}), genotp.SHA1, 6)
	if err != nil {
		t.Fatalf("NewHOTPFromSecretProvider: %v", err)
	}

	code, err := hotp.Generate(3)
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}

	results := hotp.VerifyBatch([]genotp.HOTPVerifyRequest{
		{Code: code, Counter: 3},
		{Code: code, Counter: 3},
		{Code: code, Counter: 3},
	})

	if !results[0].OK || results[0].Err != nil {
		t.Fatalf("result[0] = %+v, want OK", results[0])
	}
	if results[1].OK || !errors.Is(results[1].Err, genotp.ErrSecretProvider) {
		t.Fatalf("result[1] = %+v, want ErrSecretProvider", results[1])
	}
	if !results[2].OK || results[2].Err != nil {
		t.Fatalf("result[2] = %+v, want OK", results[2])
	}
}
