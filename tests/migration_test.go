package genotp_test

import (
	"testing"

	"github.com/robby031/genotp-go"
)

func TestParseOtpAuthMigrationURI(t *testing.T) {
	uri := "otpauth-migration://offline?data=CkMKFD3GyqSCSm0oh2eyMx4gtDFmy4XZEhxBQ01FIENvOmpvaG4uZG9lQGV4YW1wbGUuY29tGgdBQ01FIENvIAEoATACCjUKCkhlbGxvId6tvu8SGEV4YW1wbGU6YWxpY2VAZ29vZ2xlLmNvbRoHRXhhbXBsZSABKAEwAhABGAAgACjn4Pv4Ag=="

	payload, err := genotp.ParseOtpAuthMigrationURI(uri)
	if err != nil {
		t.Fatalf("ParseOtpAuthMigrationURI returned error: %v", err)
	}

	if payload.Version != 1 {
		t.Fatalf("expected version 1, got %d", payload.Version)
	}
	if payload.BatchID != 790556775 {
		t.Fatalf("expected batch id 790556775, got %d", payload.BatchID)
	}
	if len(payload.Accounts) != 2 {
		t.Fatalf("expected 2 accounts, got %d", len(payload.Accounts))
	}

	first := payload.Accounts[0]
	if first.Type != genotp.TotpType {
		t.Fatalf("expected first account to be TOTP, got %v", first.Type)
	}
	if first.Issuer != "ACME Co" {
		t.Fatalf("expected issuer ACME Co, got %q", first.Issuer)
	}
	if first.Label != "john.doe@example.com" {
		t.Fatalf("expected label john.doe@example.com, got %q", first.Label)
	}
	if first.SecretB32 != "HXDMVJECJJWSRB3HWIZR4IFUGFTMXBOZ" {
		t.Fatalf("unexpected secret: %q", first.SecretB32)
	}
}

func TestBuildAndParseOtpAuthMigrationURI(t *testing.T) {
	accounts := []genotp.OtpAuthMigrationAccount{
		{
			Type:      genotp.TotpType,
			Label:     "alice@example.com",
			Issuer:    "Example",
			SecretB32: "JBSWY3DPEHPK3PXP",
			Algorithm: genotp.SHA1,
			Digits:    6,
			Period:    30,
		},
		{
			Type:      genotp.HotpType,
			Label:     "ops@example.com",
			Issuer:    "Ops",
			SecretB32: "MFRGGZDFMZTWQ2LK",
			Algorithm: genotp.SHA256,
			Digits:    8,
			Counter:   42,
		},
	}

	uri, err := genotp.BuildOtpAuthMigrationURI(accounts, &genotp.OtpAuthMigrationOptions{
		Version:    1,
		BatchSize:  2,
		BatchIndex: 0,
		BatchID:    123456,
	})
	if err != nil {
		t.Fatalf("BuildOtpAuthMigrationURI returned error: %v", err)
	}

	payload, err := genotp.ParseOtpAuthMigrationURI(uri)
	if err != nil {
		t.Fatalf("ParseOtpAuthMigrationURI returned error: %v", err)
	}

	if payload.BatchSize != 2 {
		t.Fatalf("expected batch size 2, got %d", payload.BatchSize)
	}
	if payload.BatchID != 123456 {
		t.Fatalf("expected batch id 123456, got %d", payload.BatchID)
	}
	if len(payload.Accounts) != len(accounts) {
		t.Fatalf("expected %d accounts, got %d", len(accounts), len(payload.Accounts))
	}

	second := payload.Accounts[1]
	if second.Type != genotp.HotpType {
		t.Fatalf("expected HOTP account, got %v", second.Type)
	}
	if second.Algorithm != genotp.SHA256 {
		t.Fatalf("expected SHA256, got %v", second.Algorithm)
	}
	if second.Digits != 8 {
		t.Fatalf("expected 8 digits, got %d", second.Digits)
	}
	if second.Counter != 42 {
		t.Fatalf("expected counter 42, got %d", second.Counter)
	}
}

func TestBuildOtpAuthMigrationURIRejectsInvalidDigits(t *testing.T) {
	_, err := genotp.BuildOtpAuthMigrationURI([]genotp.OtpAuthMigrationAccount{
		{
			Type:      genotp.TotpType,
			Label:     "alice@example.com",
			SecretB32: "JBSWY3DPEHPK3PXP",
			Algorithm: genotp.SHA1,
			Digits:    7,
		},
	}, nil)

	if err != genotp.ErrInvalidDigits {
		t.Fatalf("expected ErrInvalidDigits, got %v", err)
	}
}
