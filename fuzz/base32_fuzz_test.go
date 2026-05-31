package genotp_test

import (
	"testing"

	"github.com/robby031/genotp-go"
)

func FuzzBase32EncodeDecode(f *testing.F) {
	f.Add([]byte{0x31, 0x32, 0x33, 0x34, 0x35})

	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) == 0 {
			return
		}

		encoded := genotp.EncodeBase32(data)
		dst := make([]byte, len(data))
		n, err := genotp.DecodeBase32(dst, encoded)
		if err == nil {
			if n < len(data) {
				t.Errorf("Decoded length %d < original length %d", n, len(data))
				return
			}
			for i := range data {
				if dst[i] != data[i] {
					t.Errorf("Byte %d: expected %x, got %x", i, data[i], dst[i])
					return
				}
			}
		}

		strData := string(data)
		dst2 := make([]byte, len(data))
		_, err = genotp.DecodeBase32(dst2, strData)
		if err == nil {
			_ = genotp.EncodeBase32(dst2)
		}
	})
}
