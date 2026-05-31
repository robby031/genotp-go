package genotp_test

import (
	"testing"

	"github.com/robby031/genotp-go"
)

func TestBase32EncodeDecode(t *testing.T) {
	data := []byte{0x31, 0x32, 0x33, 0x34, 0x35}
	encoded := genotp.EncodeBase32(data)
	decoded, err := genotp.DecodeBase32(encoded)
	if err != nil {
		t.Fatalf("Failed to decode: %v", err)
	}

	if len(decoded) != len(data) {
		t.Errorf("Expected length %d, got %d", len(data), len(decoded))
	}

	for i := range data {
		if decoded[i] != data[i] {
			t.Errorf("Byte %d: expected %x, got %x", i, data[i], decoded[i])
		}
	}
}

func TestBase32EncodeEmpty(t *testing.T) {
	data := []byte{}
	encoded := genotp.EncodeBase32(data)
	if encoded != "" {
		t.Errorf("Expected empty string, got %s", encoded)
	}
}

func TestBase32DecodeInvalid(t *testing.T) {
	_, err := genotp.DecodeBase32("invalid!!!@#")
	if err == nil {
		t.Error("Expected error for invalid base32")
	}
}
