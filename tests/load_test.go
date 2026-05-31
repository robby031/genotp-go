package genotp_test

import (
	"testing"
	"time"

	genotp "github.com/robby031/genotp-go"
)

// Threshold tester load 10_000 ops/sec. Go HMAC-SHA1 di
// hardware modern jauh di atas itu — kalau regression bikin lebih lambat
// dari ini, lebih baik diketahui lewat CI.
const loadThresholdOpsPerSec = 10_000.0

var loadSecret = []byte{
	0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x30,
	0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x30,
}

func TestHOTPLoad(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping load test in -short mode")
	}
	hotp, err := genotp.NewHOTP(loadSecret, genotp.SHA1, 6)
	if err != nil {
		t.Fatalf("NewHOTP: %v", err)
	}

	const iterations = 100_000
	start := time.Now()
	for i := uint64(0); i < iterations; i++ {
		if _, err := hotp.Generate(i); err != nil {
			t.Fatalf("Generate: %v", err)
		}
	}
	elapsed := time.Since(start)
	opsPerSec := float64(iterations) / elapsed.Seconds()

	t.Logf("HOTP load: %d ops in %.2fs (%.0f ops/sec)", iterations, elapsed.Seconds(), opsPerSec)
	if opsPerSec < loadThresholdOpsPerSec {
		t.Errorf("performance too low: %.0f ops/sec (<%.0f)", opsPerSec, loadThresholdOpsPerSec)
	}
}

func TestTOTPLoad(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping load test in -short mode")
	}
	totp, err := genotp.NewTOTP(loadSecret, genotp.SHA1, 6, 30)
	if err != nil {
		t.Fatalf("NewTOTP: %v", err)
	}

	const iterations = 100_000
	start := time.Now()
	for i := 0; i < iterations; i++ {
		if _, err := totp.Generate(nil); err != nil {
			t.Fatalf("Generate: %v", err)
		}
	}
	elapsed := time.Since(start)
	opsPerSec := float64(iterations) / elapsed.Seconds()

	t.Logf("TOTP load: %d ops in %.2fs (%.0f ops/sec)", iterations, elapsed.Seconds(), opsPerSec)
	if opsPerSec < loadThresholdOpsPerSec {
		t.Errorf("performance too low: %.0f ops/sec (<%.0f)", opsPerSec, loadThresholdOpsPerSec)
	}
}

func TestHOTPVerifyLoad(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping load test in -short mode")
	}
	hotp, err := genotp.NewHOTP(loadSecret, genotp.SHA1, 6)
	if err != nil {
		t.Fatalf("NewHOTP: %v", err)
	}
	code, err := hotp.Generate(0)
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}

	const iterations = 100_000
	start := time.Now()
	for i := 0; i < iterations; i++ {
		if _, err := hotp.Verify(code, 0); err != nil {
			t.Fatalf("Verify: %v", err)
		}
	}
	elapsed := time.Since(start)
	opsPerSec := float64(iterations) / elapsed.Seconds()

	t.Logf("HOTP verify load: %d ops in %.2fs (%.0f ops/sec)", iterations, elapsed.Seconds(), opsPerSec)
	if opsPerSec < loadThresholdOpsPerSec {
		t.Errorf("performance too low: %.0f ops/sec (<%.0f)", opsPerSec, loadThresholdOpsPerSec)
	}
}
