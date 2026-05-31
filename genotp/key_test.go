package genotp

import (
	"testing"
)

func TestKeyGeneratorFillSecret(t *testing.T) {
	kg := &KeyGenerator{}
	buf := make([]byte, DefaultSecretBytes)

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

func TestKeyGeneratorFillSecretTooSmall(t *testing.T) {
	kg := &KeyGenerator{}
	buf := make([]byte, MinSecretBytes-1)

	err := kg.FillSecret(buf)
	if err != ErrInvalidSecret {
		t.Errorf("Expected ErrInvalidSecret, got %v", err)
	}
}

func TestKeyGeneratorGenerateSecret(t *testing.T) {
	kg := &KeyGenerator{}
	secret, err := kg.GenerateSecret(160)
	if err != nil {
		t.Fatalf("Failed to generate secret: %v", err)
	}

	if len(secret) != 20 {
		t.Errorf("Expected secret length 20, got %d", len(secret))
	}
}

func TestKeyGeneratorGenerateSecretTooSmall(t *testing.T) {
	kg := &KeyGenerator{}
	_, err := kg.GenerateSecret(64)
	if err != ErrInvalidSecret {
		t.Errorf("Expected ErrInvalidSecret, got %v", err)
	}
}

func TestKeyGeneratorGenerateSecretNotMultipleOf8(t *testing.T) {
	kg := &KeyGenerator{}
	_, err := kg.GenerateSecret(129)
	if err != ErrInvalidSecret {
		t.Errorf("Expected ErrInvalidSecret, got %v", err)
	}
}

func TestKeyGeneratorGenerateDefaultSecret(t *testing.T) {
	kg := &KeyGenerator{}
	secret, err := kg.GenerateDefaultSecret()
	if err != nil {
		t.Fatalf("Failed to generate default secret: %v", err)
	}

	if len(secret) != DefaultSecretBytes {
		t.Errorf("Expected secret length %d, got %d", DefaultSecretBytes, len(secret))
	}
}
