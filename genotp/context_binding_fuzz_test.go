package genotp

import (
	"encoding/binary"
	"testing"
)

func FuzzContextBinding(f *testing.F) {
	secret := []byte{
		0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x30,
		0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x30,
		0x00, 0x00, 0x00, 0x00, 0x01, 0x02, 0x03,
	}
	f.Add(secret)

	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) < 24 {
			return
		}

		secret := data[0:20]
		counterBytes := make([]byte, 8)
		copy(counterBytes[4:8], data[20:24])
		counter := binary.BigEndian.Uint64(counterBytes)
		ctxBytes := data[24:]
		ctx := OtpContextFromBytes(ctxBytes)

		if hotp, err := NewHOTP(secret, SHA1, 6); err == nil {
			if code, err := hotp.GenerateBound(counter, ctx); err == nil {
				if ok, err := hotp.VerifyBound(code, counter, ctx); err == nil {
					if !ok {
						t.Error("round-trip HOTP bound failed")
					}
				}
			}
		}

		if totp, err := NewTOTP(secret, SHA1, 6, 30); err == nil {
			if code, err := totp.GenerateBound(ctx, &counter); err == nil {
				if ok, err := totp.VerifyBound(code, ctx, &counter, 0); err == nil {
					if !ok {
						t.Error("round-trip TOTP bound failed")
					}
				}
			}
		}

		for _, algo := range []Algorithm{SHA256, SHA512} {
			if totp, err := NewTOTP(secret, algo, 6, 30); err == nil {
				_, _ = totp.GenerateBound(ctx, &counter)
			}
		}
	})
}
