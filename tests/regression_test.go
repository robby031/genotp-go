package genotp_test

import (
	"errors"
	"testing"

	genotp "github.com/robby031/genotp-go"
)

func TestNewVerifierWithCapacityDoesNotPanic(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("NewVerifierWithCapacity verify panicked: %v", r)
		}
	}()
	v := genotp.NewVerifierWithCapacity(5, 100)
	if !v.VerifyWithReplayProtection("123456", "123456") {
		t.Error("first verify should succeed")
	}
	if v.VerifyWithReplayProtection("123456", "123456") {
		t.Error("second verify (replay) should fail")
	}
}

func TestHOTPClearSecretBlocksGenerate(t *testing.T) {
	secret := []byte{
		0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x30,
		0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x30,
	}
	h, err := genotp.NewHOTP(secret, genotp.SHA1, 6)
	if err != nil {
		t.Fatal(err)
	}

	for i := uint64(0); i < 5; i++ {
		_, _ = h.Generate(i)
	}
	codeBefore, _ := h.Generate(100)

	h.ClearSecret()

	_, err = h.Generate(100)
	if !errors.Is(err, genotp.ErrInvalidSecret) {
		t.Errorf("after ClearSecret, Generate should return ErrInvalidSecret, got err=%v", err)
	}
	ok, err := h.Verify(codeBefore, 100)
	if !errors.Is(err, genotp.ErrInvalidSecret) || ok {
		t.Errorf("after ClearSecret, Verify should return ErrInvalidSecret, got ok=%v err=%v", ok, err)
	}
	_, _, err = h.VerifyWithResync(codeBefore, 100, 5)
	if !errors.Is(err, genotp.ErrInvalidSecret) {
		t.Errorf("after ClearSecret, VerifyWithResync should return ErrInvalidSecret, got err=%v", err)
	}
	_, err = h.GenBound(100, genotp.NewOtpContext())
	if !errors.Is(err, genotp.ErrInvalidSecret) {
		t.Errorf("after ClearSecret, GenBound should return ErrInvalidSecret, got err=%v", err)
	}
}

func TestTOTPClearSecretBlocksGenerate(t *testing.T) {
	secret := []byte{
		0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x30,
		0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x30,
	}
	tt, err := genotp.NewTOTP(secret, genotp.SHA1, 6, 30)
	if err != nil {
		t.Fatal(err)
	}
	tv := uint64(1_700_000_000)
	for i := 0; i < 5; i++ {
		_, _ = tt.Generate(&tv)
	}

	tt.ClearSecret()

	if _, err := tt.Generate(&tv); !errors.Is(err, genotp.ErrInvalidSecret) {
		t.Errorf("Generate after ClearSecret: want ErrInvalidSecret, got %v", err)
	}
	if ok, err := tt.Verify("000000", &tv, 1); ok || !errors.Is(err, genotp.ErrInvalidSecret) {
		t.Errorf("Verify after ClearSecret: ok=%v err=%v", ok, err)
	}
	if _, err := tt.GenBound(genotp.NewOtpContext(), &tv); !errors.Is(err, genotp.ErrInvalidSecret) {
		t.Errorf("GenBound after ClearSecret: %v", err)
	}
}

func TestDecodeBase32StripsWhitespace(t *testing.T) {
	const want = "JBSWY3DPEHPK3PXP"
	cases := []struct {
		name string
		in   string
	}{
		{"trailing newline", want + "\n"},
		{"windows CRLF", want + "\r\n"},
		{"tab", want + "\t"},
		{"leading + trailing space", " " + want + " "},
		{"chunked with dashes", "JBSW-Y3DP-EHPK-3PXP"},
		{"chunked with spaces", "JBSW Y3DP EHPK 3PXP"},
		{"lowercase", "jbswy3dpehpk3pxp"},
		{"with padding", want + "===="},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			dst := make([]byte, 16)
			n, err := genotp.DecodeBase32(dst, c.in)
			if err != nil {
				t.Errorf("decode %q: %v", c.in, err)
			}
			if n == 0 {
				t.Errorf("decode %q: got 0 bytes", c.in)
			}
		})
	}
}

func TestDecodeBase32DstTooSmall(t *testing.T) {
	dst := make([]byte, 1)
	_, err := genotp.DecodeBase32(dst, "JBSWY3DPEHPK3PXP")
	if !errors.Is(err, genotp.ErrDstTooSmall) {
		t.Errorf("want ErrDstTooSmall, got %v", err)
	}
}

func TestVerifyWithResyncRejectsHugeLookAhead(t *testing.T) {
	secret := []byte{
		0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x30,
		0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x30,
	}
	h, err := genotp.NewHOTP(secret, genotp.SHA1, 6)
	if err != nil {
		t.Fatal(err)
	}

	_, _, err = h.VerifyWithResync("000000", 0, 10_000)
	if err != nil {
		t.Errorf("lookAhead at cap (10000) should be accepted, got err=%v", err)
	}

	_, _, err = h.VerifyWithResync("000000", 0, 10_001)
	if !errors.Is(err, genotp.ErrInvalidCounter) {
		t.Errorf("lookAhead > cap should return ErrInvalidCounter, got %v", err)
	}

	_, _, err = h.VerifyWithResync("000000", 0, ^uint64(0))
	if !errors.Is(err, genotp.ErrInvalidCounter) {
		t.Errorf("lookAhead u64::MAX should return ErrInvalidCounter, got %v", err)
	}
}

// Sebelumnya Verify pakai userBuf [8]byte yang memotong input via copy().
// Untuk digits=8, kode "12345678XYZ" akan ter-truncate ke "12345678"
// dan diterima sebagai valid. Test ini menjaga fix supaya kode dengan
// panjang != digits selalu ditolak.
func TestVerifyRejectsOverlengthCode(t *testing.T) {
	secret := []byte("12345678901234567890")

	// TOTP digits=8
	totp, err := genotp.NewTOTP(secret, genotp.SHA1, 8, 30)
	if err != nil {
		t.Fatalf("NewTOTP: %v", err)
	}
	timeVal := uint64(1234567890)
	code, err := totp.Generate(&timeVal)
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if len(code) != 8 {
		t.Fatalf("expected 8-digit code, got %q", code)
	}

	for _, suffix := range []string{"X", "XYZ", "0", "1234567890"} {
		tampered := code + suffix
		ok, err := totp.Verify(tampered, &timeVal, 0)
		if err != nil {
			t.Errorf("TOTP.Verify(%q) err: %v", tampered, err)
		}
		if ok {
			t.Errorf("TOTP.Verify(%q) = true; over-length code must be rejected", tampered)
		}
	}

	// TOTP VerifyBound
	ctx := genotp.NewOtpContextBuilder().IP("1.2.3.4").Build()
	boundCode, err := totp.GenBound(ctx, &timeVal)
	if err != nil {
		t.Fatalf("GenBound: %v", err)
	}
	if ok, _ := totp.VerifyBound(boundCode+"Z", ctx, &timeVal, 0); ok {
		t.Errorf("TOTP.VerifyBound accepted over-length code")
	}

	// HOTP digits=8
	hotp, err := genotp.NewHOTP(secret, genotp.SHA1, 8)
	if err != nil {
		t.Fatalf("NewHOTP: %v", err)
	}
	hcode, err := hotp.Generate(0)
	if err != nil {
		t.Fatalf("HOTP.Generate: %v", err)
	}
	if ok, _ := hotp.Verify(hcode+"X", 0); ok {
		t.Errorf("HOTP.Verify accepted over-length code")
	}
	if _, ok, _ := hotp.VerifyWithResync(hcode+"X", 0, 5); ok {
		t.Errorf("HOTP.VerifyWithResync accepted over-length code")
	}
	if ok, _ := hotp.VerifyBound(hcode+"X", 0, nil); ok {
		t.Errorf("HOTP.VerifyBound accepted over-length code")
	}

	// VerifyTracking
	detector := genotp.NewClockSkewDetector(64)
	if ok, _ := totp.VerifyTracking(code+"Z", &timeVal, 0, detector); ok {
		t.Errorf("TOTP.VerifyTracking accepted over-length code")
	}

	// Sanity: kode yang benar (panjang persis 8) tetap diterima.
	if ok, _ := totp.Verify(code, &timeVal, 0); !ok {
		t.Errorf("TOTP.Verify(correct) returned false")
	}
}
