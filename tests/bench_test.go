package genotp_test

import (
	"runtime"
	"sync"
	"sync/atomic"
	"testing"

	genotp "github.com/robby031/genotp-go"
)

var benchSecret = []byte{
	0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x30,
	0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x30,
}

func BenchmarkHOTPGenerate(b *testing.B) {
	hotp, err := genotp.NewHOTP(benchSecret, genotp.SHA1, 6)
	if err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := hotp.Generate(0); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkHOTPVerify(b *testing.B) {
	hotp, err := genotp.NewHOTP(benchSecret, genotp.SHA1, 6)
	if err != nil {
		b.Fatal(err)
	}
	code, err := hotp.Generate(0)
	if err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := hotp.Verify(code, 0); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkTOTPGenerate(b *testing.B) {
	totp, err := genotp.NewTOTP(benchSecret, genotp.SHA1, 6, 30)
	if err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := totp.Generate(nil); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkTOTPGenerateAtFixedTime(b *testing.B) {
	totp, err := genotp.NewTOTP(benchSecret, genotp.SHA1, 6, 30)
	if err != nil {
		b.Fatal(err)
	}
	t := uint64(1_700_000_000)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := totp.Generate(&t); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkTOTPVerify(b *testing.B) {
	totp, err := genotp.NewTOTP(benchSecret, genotp.SHA1, 6, 30)
	if err != nil {
		b.Fatal(err)
	}
	t := uint64(1_700_000_000)
	code, err := totp.Generate(&t)
	if err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := totp.Verify(code, &t, 1); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkTOTPVerifyWindow0(b *testing.B) {
	totp, err := genotp.NewTOTP(benchSecret, genotp.SHA1, 6, 30)
	if err != nil {
		b.Fatal(err)
	}
	t := uint64(1_700_000_000)
	code, err := totp.Generate(&t)
	if err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := totp.Verify(code, &t, 0); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkGenerateSecretDefault(b *testing.B) {
	kg := &genotp.KeyGen{}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := kg.GenerateDefaultSecret(); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkGenerateSecret256(b *testing.B) {
	kg := &genotp.KeyGen{}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := kg.GenerateSecret(256); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkBase32Encode(b *testing.B) {
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = genotp.EncodeBase32(benchSecret)
	}
}

func BenchmarkBase32Decode(b *testing.B) {
	encoded := genotp.EncodeBase32(benchSecret)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := genotp.DecodeBase32(encoded); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkProvisioningURITOTP(b *testing.B) {
	secret, err := (&genotp.KeyGen{}).GenerateDefaultSecret()
	if err != nil {
		b.Fatal(err)
	}
	secretB32 := genotp.EncodeBase32(secret)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = genotp.NewOtpAuthUri(genotp.TotpType, "MyService:user@example.com", secretB32).
			Issuer("MyService").
			Algorithm(genotp.SHA1).
			Digits(6).
			Period(30).
			Build()
	}
}

func BenchmarkProvisioningURIHOTP(b *testing.B) {
	secret, err := (&genotp.KeyGen{}).GenerateDefaultSecret()
	if err != nil {
		b.Fatal(err)
	}
	secretB32 := genotp.EncodeBase32(secret)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = genotp.NewOtpAuthUri(genotp.HotpType, "MyService:user@example.com", secretB32).
			Issuer("MyService").
			Algorithm(genotp.SHA1).
			Digits(6).
			Counter(0).
			Build()
	}
}

func BenchmarkReplayProtectionVerify(b *testing.B) {
	v := genotp.NewVerifier(uint32(b.N) + 1)

	codes := make([]string, b.N)
	for i := range codes {
		codes[i] = pad6(i + 1)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		v.VerifyWithReplayProtection(codes[i], codes[i])
	}
}

func pad6(n int) string {
	buf := [6]byte{'0', '0', '0', '0', '0', '0'}
	for i := 5; i >= 0 && n > 0; i-- {
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	return string(buf[:])
}

func BenchmarkRateLimiterContention(b *testing.B) {
	v := genotp.NewVerifier(5)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		var wg sync.WaitGroup
		for j := 0; j < 4; j++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for k := 0; k < 100; k++ {
					v.VerifyWithReplayProtection("wrong", "123456")
				}
			}()
		}
		wg.Wait()
	}
}

func BenchmarkConcurrentHOTPVerify(b *testing.B) {
	hotp, err := genotp.NewHOTP(benchSecret, genotp.SHA1, 6)
	if err != nil {
		b.Fatal(err)
	}
	code, err := hotp.Generate(0)
	if err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		var wg sync.WaitGroup
		for j := 0; j < 4; j++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for k := 0; k < 100; k++ {
					if _, err := hotp.Verify(code, 0); err != nil {
						b.Error(err)
						return
					}
				}
			}()
		}
		wg.Wait()
	}
}

func BenchmarkTOTPVerifyParallel(b *testing.B) {
	totp, err := genotp.NewTOTP(benchSecret, genotp.SHA1, 6, 30)
	if err != nil {
		b.Fatal(err)
	}
	t := uint64(1_700_000_000)
	code, err := totp.Generate(&t)
	if err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	b.SetParallelism(runtime.GOMAXPROCS(0))
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			if _, err := totp.Verify(code, &t, 0); err != nil {
				b.Error(err)
				return
			}
		}
	})
}

func BenchmarkVerifierParallelFreshCodes(b *testing.B) {
	v := genotp.NewVerifier(1_000_000)
	b.ReportAllocs()
	b.SetParallelism(runtime.GOMAXPROCS(0))
	b.ResetTimer()
	var nextCode atomic.Uint64
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			id := nextCode.Add(1)
			code := pad6(int(id % 999_999))
			v.VerifyWithReplayProtection(code, code)
		}
	})
}
