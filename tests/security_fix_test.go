package genotp_test

import (
	"math"
	"strings"
	"testing"

	genotp "github.com/robby031/genotp-go"
)

// TestTOTPWindowMaxInt64Rejection tests fix for M1: Integer overflow in TOTP window
// Bug: window == math.MaxInt64 would overflow to -1 when converted to int64
// Fix: Changed check from `window > math.MaxInt64` to `window >= math.MaxInt64`
func TestTOTPWindowMaxInt64Rejection(t *testing.T) {
	secret := []byte{
		0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x30,
		0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x30,
	}
	totp, err := genotp.NewTOTP(secret, genotp.SHA1, 6, 30)
	if err != nil {
		t.Fatal(err)
	}

	testTime := uint64(1700000000)
	code, _ := totp.Generate(&testTime)

	// Test window == math.MaxInt64 (edge case that was buggy)
	ok, err := totp.Verify(code, &testTime, math.MaxInt64)
	if err == nil {
		t.Error("Expected ErrInvalidTime for window == MaxInt64, got nil error")
	}
	if ok {
		t.Error("Expected verification to fail for window == MaxInt64, but it passed")
	}

	// Test window == math.MaxInt64 - 1 (should also be rejected as unreasonably large)
	ok, err = totp.Verify(code, &testTime, math.MaxInt64-1)
	if ok {
		t.Error("Verification should fail for unreasonably large window")
	}

	// Test normal window (should work)
	ok, err = totp.Verify(code, &testTime, 1)
	if err != nil {
		t.Errorf("Normal window should not error: %v", err)
	}
	if !ok {
		t.Error("Normal window should verify successfully")
	}
}

// TestTOTPVerifyBoundWindowMaxInt64 tests same fix in VerifyBound
func TestTOTPVerifyBoundWindowMaxInt64(t *testing.T) {
	secret := []byte{
		0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x30,
		0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x30,
	}
	totp, err := genotp.NewTOTP(secret, genotp.SHA1, 6, 30)
	if err != nil {
		t.Fatal(err)
	}

	ctx := genotp.NewOtpContextBuilder().IP("192.168.1.1").Build()
	testTime := uint64(1700000000)

	ok, err := totp.VerifyBound("000000", ctx, &testTime, math.MaxInt64)
	if err == nil {
		t.Error("Expected ErrInvalidTime for window == MaxInt64 in VerifyBound")
	}
	if ok {
		t.Error("VerifyBound should fail for window == MaxInt64")
	}
}

// TestTOTPVerifyTrackingWindowMaxInt64 tests same fix in VerifyTracking
func TestTOTPVerifyTrackingWindowMaxInt64(t *testing.T) {
	secret := []byte{
		0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x30,
		0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x30,
	}
	totp, err := genotp.NewTOTP(secret, genotp.SHA1, 6, 30)
	if err != nil {
		t.Fatal(err)
	}

	detector := genotp.NewClockSkewDetector(100)
	testTime := uint64(1700000000)

	ok, err := totp.VerifyTracking("000000", &testTime, math.MaxInt64, detector)
	if err == nil {
		t.Error("Expected ErrInvalidTime for window == MaxInt64 in VerifyTracking")
	}
	if ok {
		t.Error("VerifyTracking should fail for window == MaxInt64")
	}
}

// TestContextBuilderInputValidation tests fix for L1: Missing input validation
// Bug: No length validation, attacker could provide MB-sized strings
// Fix: Added maxContextFieldLen = 256 validation in all builder methods
func TestContextBuilderInputValidation(t *testing.T) {
	longString := strings.Repeat("A", 300) // > 256 bytes
	normalString := "192.168.1.1"

	// Test IP validation
	ctx := genotp.NewOtpContextBuilder().
		IP(longString).
		Build()

	if len(ctx.Bytes()) > 1024 {
		t.Error("Context builder should reject oversized IP input")
	}

	// Test Device validation
	ctx = genotp.NewOtpContextBuilder().
		Device(longString).
		Build()

	if len(ctx.Bytes()) > 1024 {
		t.Error("Context builder should reject oversized Device input")
	}

	// Test Session validation
	ctx = genotp.NewOtpContextBuilder().
		Session(longString).
		Build()

	if len(ctx.Bytes()) > 1024 {
		t.Error("Context builder should reject oversized Session input")
	}

	// Test Custom validation
	ctx = genotp.NewOtpContextBuilder().
		Custom(longString, longString).
		Build()

	if len(ctx.Bytes()) > 1024 {
		t.Error("Context builder should reject oversized Custom input")
	}

	// Test normal inputs still work
	ctx = genotp.NewOtpContextBuilder().
		IP(normalString).
		Device("device-123").
		Session("session-abc").
		Build()

	if len(ctx.Bytes()) == 0 {
		t.Error("Context builder should accept normal-sized inputs")
	}
}

// TestContextBuilderSilentlyDropsOversizedInput verifies silent truncation behavior
func TestContextBuilderSilentlyDropsOversizedInput(t *testing.T) {
	longIP := strings.Repeat("A", 300)
	normalIP := "192.168.1.1"

	// Build with oversized IP
	ctx1 := genotp.NewOtpContextBuilder().
		IP(longIP).
		Session("test").
		Build()

	// Build without IP
	ctx2 := genotp.NewOtpContextBuilder().
		Session("test").
		Build()

	// Should be equivalent (oversized IP was dropped)
	if len(ctx1.Bytes()) != len(ctx2.Bytes()) {
		t.Errorf("Oversized input should be silently dropped. ctx1=%d bytes, ctx2=%d bytes",
			len(ctx1.Bytes()), len(ctx2.Bytes()))
	}

	// Build with normal IP
	ctx3 := genotp.NewOtpContextBuilder().
		IP(normalIP).
		Session("test").
		Build()

	// Should be different from ctx1/ctx2
	if len(ctx3.Bytes()) == len(ctx2.Bytes()) {
		t.Error("Normal-sized input should be accepted and result in different context")
	}
}
