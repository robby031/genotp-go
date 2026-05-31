package genotp_test

import (
	"testing"

	"github.com/robby031/genotp-go"
)

func TestKeyGenFillSecret(t *testing.T) {
	kg := &genotp.KeyGen{}
	buf := make([]byte, genotp.DefaultSecretBytes)

	err := kg.FillSecret(buf)
	if err != nil {
		t.Fatalf("Failed to fill secret: %v", err)
	}

	allZero := true
	for _, b := range buf {
		if b != 0 {
			allZero = false
			break
		}
	}
	if allZero {
		t.Error("Secret should not be all zeros")
	}
}

func TestKeyGenFillSecretTooSmall(t *testing.T) {
	kg := &genotp.KeyGen{}
	buf := make([]byte, genotp.MinSecretBytes-1)

	err := kg.FillSecret(buf)
	if err != genotp.ErrInvalidSecret {
		t.Errorf("Expected ErrInvalidSecret, got %v", err)
	}
}

func TestKeyGenGenerateSecret(t *testing.T) {
	kg := &genotp.KeyGen{}
	secret, err := kg.GenerateSecret(160)
	if err != nil {
		t.Fatalf("Failed to generate secret: %v", err)
	}

	if len(secret) != 20 {
		t.Errorf("Expected secret length 20, got %d", len(secret))
	}
}

func TestKeyGenGenerateSecretTooSmall(t *testing.T) {
	kg := &genotp.KeyGen{}
	_, err := kg.GenerateSecret(64)
	if err != genotp.ErrInvalidSecret {
		t.Errorf("Expected ErrInvalidSecret, got %v", err)
	}
}

func TestKeyGenGenerateSecretNotMultipleOf8(t *testing.T) {
	kg := &genotp.KeyGen{}
	_, err := kg.GenerateSecret(129)
	if err != genotp.ErrInvalidSecret {
		t.Errorf("Expected ErrInvalidSecret, got %v", err)
	}
}

func TestKeyGenGenerateDefaultSecret(t *testing.T) {
	kg := &genotp.KeyGen{}
	secret, err := kg.GenerateDefaultSecret()
	if err != nil {
		t.Fatalf("Failed to generate default secret: %v", err)
	}

	if len(secret) != genotp.DefaultSecretBytes {
		t.Errorf("Expected secret length %d, got %d", genotp.DefaultSecretBytes, len(secret))
	}
}
