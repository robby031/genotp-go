package genotp

import (
	"testing"
)

func TestVerifierReplayProtection(t *testing.T) {
	verifier := NewVerifier(5)

	if !verifier.VerifyWithReplayProtection("123456", "123456") {
		t.Error("First verification should succeed")
	}
	if verifier.VerifyWithReplayProtection("123456", "123456") {
		t.Error("Replay should be blocked")
	}
}

func TestVerifierRateLimiting(t *testing.T) {
	verifier := NewVerifier(3)

	if verifier.IsRateLimited() {
		t.Error("Should not be rate limited initially")
	}

	verifier.VerifyWithReplayProtection("wrong", "123456")
	verifier.VerifyWithReplayProtection("wrong", "123456")
	verifier.VerifyWithReplayProtection("wrong", "123456")

	if !verifier.IsRateLimited() {
		t.Error("Should be rate limited after 3 failures")
	}
}

func TestVerifierResetAttempts(t *testing.T) {
	verifier := NewVerifier(3)

	verifier.VerifyWithReplayProtection("wrong", "123456")
	verifier.VerifyWithReplayProtection("wrong", "123456")
	verifier.ResetAttempts()

	if verifier.IsRateLimited() {
		t.Error("Should not be rate limited after reset")
	}
}

func TestVerifierClearUsedCodes(t *testing.T) {
	verifier := NewVerifier(5)

	verifier.VerifyWithReplayProtection("123456", "123456")
	verifier.ClearUsedCodes()

	if !verifier.VerifyWithReplayProtection("123456", "123456") {
		t.Error("Should allow code after clearing used codes")
	}
}

func TestVerifierWithContext(t *testing.T) {
	verifier := NewVerifier(5)
	ctx := NewOtpContextBuilder().Session("s1").IP("10.0.0.1").Build()

	if !verifier.VerifyWithContext("123456", "123456", ctx, ctx) {
		t.Error("Verification with matching context should succeed")
	}
	if verifier.VerifyWithContext("123456", "123456", ctx, ctx) {
		t.Error("Replay with same context should be blocked")
	}
}

func TestVerifierPerContextReplayIsolation(t *testing.T) {
	verifier := NewVerifier(10)
	ctxA := NewOtpContextBuilder().Session("sess-A").Build()
	ctxB := NewOtpContextBuilder().Session("sess-B").Build()

	if !verifier.VerifyWithContext("987654", "987654", ctxA, ctxA) {
		t.Error("First verification for user A should succeed")
	}
	if !verifier.VerifyWithContext("987654", "987654", ctxB, ctxB) {
		t.Error("User B with same code should succeed (different context)")
	}
	if verifier.VerifyWithContext("987654", "987654", ctxA, ctxA) {
		t.Error("User A replay should be blocked")
	}
	if verifier.VerifyWithContext("987654", "987654", ctxB, ctxB) {
		t.Error("User B replay should be blocked")
	}
}

func TestVerifierEmptyContext(t *testing.T) {
	v1 := NewVerifier(5)
	if !v1.VerifyWithReplayProtection("111111", "111111") {
		t.Error("First verification should succeed")
	}
	if v1.VerifyWithReplayProtection("111111", "111111") {
		t.Error("Replay should be blocked")
	}

	v2 := NewVerifier(5)
	empty := NewOtpContext()
	if !v2.VerifyWithContext("111111", "111111", empty, empty) {
		t.Error("Verification with empty context should succeed")
	}
	if v2.VerifyWithContext("111111", "111111", empty, empty) {
		t.Error("Replay with empty context should be blocked")
	}
}
