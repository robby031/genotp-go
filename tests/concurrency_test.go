package genotp_test

import (
	"fmt"
	"sync"
	"sync/atomic"
	"testing"

	genotp "github.com/robby031/genotp-go"
)

var concurrencySecret = []byte{
	0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x30,
	0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x30,
}

func TestHOTPConcurrentGeneration(t *testing.T) {
	hotp, err := genotp.NewHOTP(concurrencySecret, genotp.SHA1, 6)
	if err != nil {
		t.Fatalf("NewHOTP: %v", err)
	}

	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func(i uint64) {
			defer wg.Done()
			for j := uint64(0); j < 100; j++ {
				if _, err := hotp.Generate(i*100 + j); err != nil {
					t.Errorf("Generate: %v", err)
					return
				}
			}
		}(uint64(i))
	}
	wg.Wait()
}

func TestTOTPConcurrentGeneration(t *testing.T) {
	totp, err := genotp.NewTOTP(concurrencySecret, genotp.SHA1, 6, 30)
	if err != nil {
		t.Fatalf("NewTOTP: %v", err)
	}

	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				if _, err := totp.Generate(nil); err != nil {
					t.Errorf("Generate: %v", err)
					return
				}
			}
		}()
	}
	wg.Wait()
}

func TestHOTPConcurrentVerification(t *testing.T) {
	hotp, err := genotp.NewHOTP(concurrencySecret, genotp.SHA1, 6)
	if err != nil {
		t.Fatalf("NewHOTP: %v", err)
	}
	code, err := hotp.Generate(0)
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}

	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				if _, err := hotp.Verify(code, 0); err != nil {
					t.Errorf("Verify: %v", err)
					return
				}
			}
		}()
	}
	wg.Wait()
}

// 100 goroutine × 50 percobaan verify code yang sama dengan context yang
// sama. HARUS hanya 1 yang sukses; sisanya ditolak karena replay.
func TestVerifierReplayUnderExtremeContention(t *testing.T) {
	v := genotp.NewVerifier(1_000_000)

	var success uint32
	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 50; j++ {
				if v.VerifyWithReplayProtection("424242", "424242") {
					atomic.AddUint32(&success, 1)
				}
			}
		}()
	}
	wg.Wait()

	if got := atomic.LoadUint32(&success); got != 1 {
		t.Errorf("expected exactly 1 success, got %d", got)
	}
}

// 100 goroutine, masing-masing dengan context UNIK, semuanya pakai kode
// yang sama. HARUS semua 100 sukses karena replay-set per-context.
func TestVerifierPerContextIsolationUnderContention(t *testing.T) {
	v := genotp.NewVerifier(1_000_000)

	var success uint32
	var wg sync.WaitGroup
	for tid := 0; tid < 100; tid++ {
		wg.Add(1)
		go func(tid int) {
			defer wg.Done()
			ctx := genotp.NewOtpContextBuilder().
				Session(fmt.Sprintf("sess-%03d", tid)).
				Build()
			for attempt := 0; attempt < 10; attempt++ {
				ok := v.VerifyWithContext("777777", "777777", ctx, ctx)
				if ok {
					atomic.AddUint32(&success, 1)
				}
				if attempt > 0 && ok {
					t.Errorf("tid=%d attempt=%d: replay should be rejected", tid, attempt)
					return
				}
			}
		}(tid)
	}
	wg.Wait()

	if got := atomic.LoadUint32(&success); got != 100 {
		t.Errorf("expected 100 successes (1 per context), got %d", got)
	}
}

// Rate limit harus aktif setelah ratusan thread bersaing menaikkan
// counter melewati max_attempts.
func TestVerifierRateLimitTriggersUnderConcurrency(t *testing.T) {
	const maxAttempts = uint32(50)
	v := genotp.NewVerifier(maxAttempts)

	var wg sync.WaitGroup
	for i := 0; i < 200; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 10; j++ {
				v.VerifyWithReplayProtection("000000", "999999")
			}
		}()
	}
	wg.Wait()

	if !v.IsRateLimited() {
		t.Errorf("expected rate-limited after thousands of failures")
	}

	if v.VerifyWithReplayProtection("888888", "888888") {
		t.Errorf("rate-limited verifier must reject even correct codes")
	}
}

// Mixed workload: plain + context-bound paths. Pastikan tidak ada
// cross-contamination antar dua jalur API.
func TestVerifierMixedAPIPathsNoCrossContamination(t *testing.T) {
	v := genotp.NewVerifier(1_000_000)

	var successPlain uint32
	var successBound uint32
	var wg sync.WaitGroup

	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 20; j++ {
				if v.VerifyWithReplayProtection("AAAAAA", "AAAAAA") {
					atomic.AddUint32(&successPlain, 1)
				}
			}
		}()
	}

	for tid := 0; tid < 50; tid++ {
		wg.Add(1)
		go func(tid int) {
			defer wg.Done()
			ctx := genotp.NewOtpContextBuilder().
				Session(fmt.Sprintf("t%02d", tid)).
				Build()
			for j := 0; j < 20; j++ {
				if v.VerifyWithContext("AAAAAA", "AAAAAA", ctx, ctx) {
					atomic.AddUint32(&successBound, 1)
				}
			}
		}(tid)
	}

	wg.Wait()

	if got := atomic.LoadUint32(&successPlain); got != 1 {
		t.Errorf("plain API: expected 1 success, got %d", got)
	}
	if got := atomic.LoadUint32(&successBound); got != 50 {
		t.Errorf("bound API: expected 50 successes, got %d", got)
	}
}

// TOTP.VerifyBound concurrent — no data race or corruption when secret
// is shared lewat pointer ke TOTP.
func TestTOTPBoundConcurrentVerify(t *testing.T) {
	totp, err := genotp.NewTOTP(concurrencySecret, genotp.SHA1, 6, 30)
	if err != nil {
		t.Fatalf("NewTOTP: %v", err)
	}

	var wg sync.WaitGroup
	for tid := 0; tid < 20; tid++ {
		wg.Add(1)
		go func(tid int) {
			defer wg.Done()
			ctx := genotp.NewOtpContextBuilder().
				Session(fmt.Sprintf("sess-%d", tid)).
				IP(fmt.Sprintf("10.0.0.%d", tid%256)).
				Build()
			otherCtx := genotp.NewOtpContextBuilder().
				Session(fmt.Sprintf("sess-%d", tid+1000)).
				Build()
			for tt := uint64(1_700_000_000); tt < 1_700_000_000+100*30; tt += 30 {
				ttCopy := tt
				code, err := totp.GenerateBound(ctx, &ttCopy)
				if err != nil {
					t.Errorf("GenerateBound: %v", err)
					return
				}
				ok, err := totp.VerifyBound(code, ctx, &ttCopy, 0)
				if err != nil || !ok {
					t.Errorf("round-trip fail tid=%d t=%d ok=%v err=%v", tid, tt, ok, err)
					return
				}
				ok, _ = totp.VerifyBound(code, otherCtx, &ttCopy, 0)
				if ok {
					t.Errorf("other context should not match (tid=%d t=%d)", tid, tt)
					return
				}
			}
		}(tid)
	}
	wg.Wait()
}
