package genotp

import (
	"testing"
)

func FuzzBase32EncodeDecode(f *testing.F) {
	f.Add([]byte{0x31, 0x32, 0x33, 0x34, 0x35})

	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) == 0 {
			return
		}

		encoded := EncodeBase32(data)
		decoded, err := DecodeBase32(encoded)
		if err == nil {
			if len(decoded) < len(data) {
				t.Errorf("Decoded length %d < original length %d", len(decoded), len(data))
				return
			}
			for i := range data {
				if decoded[i] != data[i] {
					t.Errorf("Byte %d: expected %x, got %x", i, data[i], decoded[i])
					return
				}
			}
		}

		strData := string(data)
		decoded2, err := DecodeBase32(strData)
		if err == nil {
			_ = EncodeBase32(decoded2)
		}
	})
}
