package genotp_test

import (
	"testing"

	"github.com/robby031/genotp-go/genotp"
)

func FuzzProvisioning(f *testing.F) {
	secret := []byte{
		0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x30,
		0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x30,
		0x75, 0x73, 0x65, 0x72, 0x40, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x2e, 0x63, 0x6f, 0x6d,
	}
	f.Add(secret)

	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) < 20 {
			return
		}

		secret := data[0:20]
		secretB32 := genotp.EncodeBase32(secret)

		var label string
		if len(data) > 20 {
			label = "service:" + string(data[20:])
		} else {
			label = "service:user@example.com"
		}

		_ = genotp.NewOtpAuthUri(genotp.TotpType, label, secretB32).
			Issuer("Service").
			Algorithm(genotp.SHA1).
			Digits(6).
			Period(30).
			Build()

		_ = genotp.NewOtpAuthUri(genotp.HotpType, label, secretB32).
			Issuer("Service").
			Algorithm(genotp.SHA1).
			Digits(6).
			Counter(0).
			Build()
	})
}
