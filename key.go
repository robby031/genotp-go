package genotp

import (
	"crypto/rand"
	"errors"
)

const (
	MinSecretBytes     = 16
	DefaultSecretBytes = 20
)

type KeyGen struct{}

func (k *KeyGen) FillSecret(buf []byte) error {
	if len(buf) < MinSecretBytes {
		return ErrInvalidSecret
	}

	_, err := rand.Read(buf)
	if err != nil {
		return errors.Join(ErrInvalidSecret, err)
	}
	return nil
}

func (k *KeyGen) GenerateSecret(bitLength int) ([]byte, error) {
	if bitLength < 128 {
		return nil, ErrInvalidSecret
	}

	if bitLength%8 != 0 {
		return nil, ErrInvalidSecret
	}

	byteLength := bitLength / 8
	secret := make([]byte, byteLength)

	_, err := rand.Read(secret)
	if err != nil {
		return nil, errors.Join(ErrInvalidSecret, err)
	}

	return secret, nil
}

func (k *KeyGen) GenerateDefaultSecret() ([]byte, error) {
	return k.GenerateSecret(160)
}

func CreateSecret() ([]byte, error) {
	kg := &KeyGen{}
	return kg.GenerateDefaultSecret()
}
