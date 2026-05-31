package genotp_test

import (
	"bytes"
	"fmt"
	"math/rand"
	"testing"

	genotp "github.com/robby031/genotp-go"
)

const propIters = 200

func propRng(t *testing.T) *rand.Rand {
	t.Helper()
	h := uint64(1469598103934665603)
	for _, c := range []byte(t.Name()) {
		h ^= uint64(c)
		h *= 1099511628211
	}
	return rand.New(rand.NewSource(int64(h)))
}

func randSecret(r *rand.Rand, minLen, maxLen int) []byte {
	n := minLen + r.Intn(maxLen-minLen+1)
	b := make([]byte, n)
	for i := range b {
		b[i] = byte(r.Intn(256))
	}
	return b
}

func isAllDigits(s string) bool {
	for _, c := range s {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

func TestPropHOTPGenerateAlwaysCorrectLength(t *testing.T) {
	r := propRng(t)
	for i := 0; i < propIters; i++ {
		secret := randSecret(r, 20, 32)
		counter := uint64(r.Int63n(1_000_000))
		hotp, err := genotp.NewHOTP(secret, genotp.SHA1, 6)
		if err != nil {
			t.Fatalf("iter %d NewHOTP: %v", i, err)
		}
		code, err := hotp.Generate(counter)
		if err != nil {
			t.Fatalf("iter %d Generate: %v", i, err)
		}
		if len(code) != 6 || !isAllDigits(code) {
			t.Fatalf("iter %d invalid code %q", i, code)
		}
	}
}

func TestPropHOTPVerifyCorrectCode(t *testing.T) {
	r := propRng(t)
	for i := 0; i < propIters; i++ {
		secret := randSecret(r, 20, 32)
		counter := uint64(r.Int63n(1_000_000))
		hotp, err := genotp.NewHOTP(secret, genotp.SHA1, 6)
		if err != nil {
			t.Fatalf("iter %d NewHOTP: %v", i, err)
		}
		code, err := hotp.Generate(counter)
		if err != nil {
			t.Fatalf("iter %d Generate: %v", i, err)
		}
		ok, err := hotp.Verify(code, counter)
		if err != nil || !ok {
			t.Fatalf("iter %d verify failed: ok=%v err=%v", i, ok, err)
		}
	}
}

func TestPropTOTPGenerateAlwaysCorrectLength(t *testing.T) {
	r := propRng(t)
	for i := 0; i < propIters; i++ {
		secret := randSecret(r, 20, 32)
		tt := uint64(r.Int63n(1_000_000_000))
		totp, err := genotp.NewTOTP(secret, genotp.SHA1, 6, 30)
		if err != nil {
			t.Fatalf("iter %d NewTOTP: %v", i, err)
		}
		code, err := totp.Generate(&tt)
		if err != nil {
			t.Fatalf("iter %d Generate: %v", i, err)
		}
		if len(code) != 6 || !isAllDigits(code) {
			t.Fatalf("iter %d invalid code %q", i, code)
		}
	}
}

func TestPropTOTPVerifyCorrectCode(t *testing.T) {
	r := propRng(t)
	for i := 0; i < propIters; i++ {
		secret := randSecret(r, 20, 32)
		tt := uint64(r.Int63n(1_000_000_000))
		totp, err := genotp.NewTOTP(secret, genotp.SHA1, 6, 30)
		if err != nil {
			t.Fatalf("iter %d NewTOTP: %v", i, err)
		}
		code, err := totp.Generate(&tt)
		if err != nil {
			t.Fatalf("iter %d Generate: %v", i, err)
		}
		ok, err := totp.Verify(code, &tt, 1)
		if err != nil || !ok {
			t.Fatalf("iter %d verify failed: ok=%v err=%v", i, ok, err)
		}
	}
}

func TestPropKeyGenerateAlwaysCorrectLength(t *testing.T) {
	r := propRng(t)
	kg := &genotp.KeyGenerator{}
	for i := 0; i < propIters; i++ {
		byteLen := 16 + r.Intn(49) // 16..=64
		bitLen := byteLen * 8
		secret, err := kg.GenerateSecret(bitLen)
		if err != nil {
			t.Fatalf("iter %d GenerateSecret(%d): %v", i, bitLen, err)
		}
		if len(secret) != byteLen {
			t.Fatalf("iter %d expected %d bytes, got %d", i, byteLen, len(secret))
		}
	}
}

func TestPropTOTPBoundRoundtrip(t *testing.T) {
	r := propRng(t)
	for i := 0; i < propIters; i++ {
		secret := randSecret(r, 20, 32)
		ctxBytes := randSecret(r, 0, 64)
		tt := uint64(r.Int63n(1_000_000_000))
		totp, err := genotp.NewTOTP(secret, genotp.SHA1, 6, 30)
		if err != nil {
			t.Fatalf("iter %d NewTOTP: %v", i, err)
		}
		ctx := genotp.OtpContextFromBytes(ctxBytes)
		code, err := totp.GenerateBound(ctx, &tt)
		if err != nil {
			t.Fatalf("iter %d GenerateBound: %v", i, err)
		}
		ok, err := totp.VerifyBound(code, ctx, &tt, 0)
		if err != nil || !ok {
			t.Fatalf("iter %d round-trip failed", i)
		}
	}
}

func TestPropTOTPBoundDifferentContextsReject(t *testing.T) {
	r := propRng(t)
	for i := 0; i < propIters; i++ {
		secret := randSecret(r, 20, 32)
		ctxA := randSecret(r, 1, 64)
		ctxB := randSecret(r, 1, 64)
		if bytes.Equal(ctxA, ctxB) {
			continue
		}
		tt := uint64(r.Int63n(1_000_000_000))
		totp, err := genotp.NewTOTP(secret, genotp.SHA1, 6, 30)
		if err != nil {
			t.Fatalf("iter %d NewTOTP: %v", i, err)
		}
		oa := genotp.OtpContextFromBytes(ctxA)
		ob := genotp.OtpContextFromBytes(ctxB)
		code, err := totp.GenerateBound(oa, &tt)
		if err != nil {
			t.Fatalf("iter %d GenerateBound: %v", i, err)
		}
		ok, _ := totp.VerifyBound(code, ob, &tt, 0)
		if ok {
			t.Fatalf("iter %d code from ctxA accepted in ctxB", i)
		}
	}
}

func TestPropEmptyContextEqualsStandardTOTP(t *testing.T) {
	r := propRng(t)
	for i := 0; i < propIters; i++ {
		secret := randSecret(r, 20, 32)
		tt := uint64(r.Int63n(1_000_000_000))
		totp, err := genotp.NewTOTP(secret, genotp.SHA1, 6, 30)
		if err != nil {
			t.Fatalf("iter %d NewTOTP: %v", i, err)
		}
		empty := genotp.NewOtpContext()
		standard, err := totp.Generate(&tt)
		if err != nil {
			t.Fatalf("iter %d Generate: %v", i, err)
		}
		bound, err := totp.GenerateBound(empty, &tt)
		if err != nil {
			t.Fatalf("iter %d GenerateBound: %v", i, err)
		}
		if standard != bound {
			t.Fatalf("iter %d standard=%q bound=%q", i, standard, bound)
		}
	}
}

func TestPropHOTPBoundRoundtrip(t *testing.T) {
	r := propRng(t)
	for i := 0; i < propIters; i++ {
		secret := randSecret(r, 20, 32)
		ctxBytes := randSecret(r, 0, 64)
		counter := uint64(r.Int63n(1_000_000))
		hotp, err := genotp.NewHOTP(secret, genotp.SHA1, 6)
		if err != nil {
			t.Fatalf("iter %d NewHOTP: %v", i, err)
		}
		ctx := genotp.OtpContextFromBytes(ctxBytes)
		code, err := hotp.GenerateBound(counter, ctx)
		if err != nil {
			t.Fatalf("iter %d GenerateBound: %v", i, err)
		}
		ok, err := hotp.VerifyBound(code, counter, ctx)
		if err != nil || !ok {
			t.Fatalf("iter %d round-trip failed", i)
		}
	}
}

func TestPropHOTPBoundDifferentContextsReject(t *testing.T) {
	r := propRng(t)
	for i := 0; i < propIters; i++ {
		secret := randSecret(r, 20, 32)
		ctxA := randSecret(r, 1, 64)
		ctxB := randSecret(r, 1, 64)
		if bytes.Equal(ctxA, ctxB) {
			continue
		}
		counter := uint64(r.Int63n(1_000_000))
		hotp, err := genotp.NewHOTP(secret, genotp.SHA1, 6)
		if err != nil {
			t.Fatalf("iter %d NewHOTP: %v", i, err)
		}
		oa := genotp.OtpContextFromBytes(ctxA)
		ob := genotp.OtpContextFromBytes(ctxB)
		code, err := hotp.GenerateBound(counter, oa)
		if err != nil {
			t.Fatalf("iter %d GenerateBound: %v", i, err)
		}
		ok, _ := hotp.VerifyBound(code, counter, ob)
		if ok {
			t.Fatalf("iter %d code from ctxA accepted in ctxB", i)
		}
	}
}

func TestPropTOTPBoundWindowAcceptsWithinRange(t *testing.T) {
	r := propRng(t)
	for i := 0; i < propIters; i++ {
		secret := randSecret(r, 20, 32)
		ctxBytes := randSecret(r, 0, 32)
		baseWindow := uint64(1_000 + r.Int63n(30_000_000-1_000))
		deltaSteps := int64(-2 + r.Intn(5)) // -2..=2
		window := uint64(2 + r.Intn(4))     // 2..=5
		const period = uint64(30)
		tt := baseWindow * period
		totp, err := genotp.NewTOTP(secret, genotp.SHA1, 6, period)
		if err != nil {
			t.Fatalf("iter %d NewTOTP: %v", i, err)
		}
		ctx := genotp.OtpContextFromBytes(ctxBytes)
		code, err := totp.GenerateBound(ctx, &tt)
		if err != nil {
			t.Fatalf("iter %d GenerateBound: %v", i, err)
		}
		absDelta := deltaSteps
		if absDelta < 0 {
			absDelta = -absDelta
		}
		if uint64(absDelta) > window {
			continue
		}
		verifyTime := uint64(int64(tt) + deltaSteps*int64(period))
		ok, err := totp.VerifyBound(code, ctx, &verifyTime, window)
		if err != nil || !ok {
			t.Fatalf("iter %d delta=%d window=%d should be accepted", i, deltaSteps, window)
		}
	}
}

func TestPropContextBuilderSetterOrderInvariant(t *testing.T) {
	r := propRng(t)
	for i := 0; i < propIters; i++ {
		ip := fmt.Sprintf("ip-%d", r.Int())
		device := fmt.Sprintf("dev-%d", r.Int())
		session := fmt.Sprintf("sess-%d", r.Int())

		a := genotp.NewOtpContextBuilder().IP(ip).Device(device).Session(session).Build()
		b := genotp.NewOtpContextBuilder().Session(session).IP(ip).Device(device).Build()
		c := genotp.NewOtpContextBuilder().Device(device).Session(session).IP(ip).Build()

		if !bytes.Equal(a.Bytes(), b.Bytes()) || !bytes.Equal(a.Bytes(), c.Bytes()) {
			t.Fatalf("iter %d builder canonical bytes differ across setter orders", i)
		}
	}
}

func TestPropVerifierPerContextIsolation(t *testing.T) {
	r := propRng(t)
	for i := 0; i < propIters; i++ {
		code := fmt.Sprintf("%06d", r.Intn(1_000_000))
		ctxA := randSecret(r, 1, 32)
		ctxB := randSecret(r, 1, 32)
		if bytes.Equal(ctxA, ctxB) {
			continue
		}
		v := genotp.NewVerifier(100)
		a := genotp.OtpContextFromBytes(ctxA)
		b := genotp.OtpContextFromBytes(ctxB)

		if !v.VerifyWithContext(code, code, a, a) {
			t.Fatalf("iter %d first verify ctxA failed", i)
		}
		if !v.VerifyWithContext(code, code, b, b) {
			t.Fatalf("iter %d first verify ctxB failed", i)
		}
		if v.VerifyWithContext(code, code, a, a) {
			t.Fatalf("iter %d replay ctxA accepted", i)
		}
		if v.VerifyWithContext(code, code, b, b) {
			t.Fatalf("iter %d replay ctxB accepted", i)
		}
	}
}

func TestPropVerifierContextMismatchAlwaysRejects(t *testing.T) {
	r := propRng(t)
	for i := 0; i < propIters; i++ {
		code := fmt.Sprintf("%06d", r.Intn(1_000_000))
		issued := randSecret(r, 1, 32)
		request := randSecret(r, 1, 32)
		if bytes.Equal(issued, request) {
			continue
		}
		v := genotp.NewVerifier(100_000)
		if v.VerifyWithContext(code, code,
			genotp.OtpContextFromBytes(issued),
			genotp.OtpContextFromBytes(request),
		) {
			t.Fatalf("iter %d mismatched context accepted", i)
		}
	}
}
