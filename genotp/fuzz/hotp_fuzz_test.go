package genotp_test

import (
	"encoding/binary"
	"testing"

	"github.com/robby031/genotp-go/genotp"
)

func FuzzHOTP(f *testing.F) {
	secret := []byte{
		0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x30,
		0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x30,
	}
	f.Add(secret)

	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) < 20 {
			return
		}

		secret := data[0:20]
		var counter uint64
		if len(data) >= 24 {
			counterBytes := make([]byte, 8)
			copy(counterBytes[4:8], data[20:24])
			counter = binary.BigEndian.Uint64(counterBytes)
		}

		if hotp, err := genotp.NewHOTP(secret, genotp.SHA1, 6); err == nil {
			_, _ = hotp.Generate(counter)
			_, _ = hotp.Verify("123456", counter)
		}

		if hotp, err := genotp.NewHOTP(secret, genotp.SHA256, 6); err == nil {
			_, _ = hotp.Generate(counter)
		}

		if hotp, err := genotp.NewHOTP(secret, genotp.SHA512, 6); err == nil {
			_, _ = hotp.Generate(counter)
		}
	})
}
