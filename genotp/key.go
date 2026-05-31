package genotp

import (
	"crypto/rand"
	"errors"
	"math/big"
)

const (
	MinSecretBytes     = 16
	DefaultSecretBytes = 20
)

type KeyGenerator struct{}

func (k *KeyGenerator) FillSecret(buf []byte) error {
	if len(buf) < MinSecretBytes {
		return ErrInvalidSecret
	}

	_, err := rand.Read(buf)
	if err != nil {
		return errors.Join(ErrInvalidSecret, err)
	}
	return nil
}

func (k *KeyGenerator) GenerateSecret(bitLength int) ([]byte, error) {
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

func (k *KeyGenerator) GenerateDefaultSecret() ([]byte, error) {
	return k.GenerateSecret(160)
}

func CreateSecret() ([]byte, error) {
	kg := &KeyGenerator{}
	return kg.GenerateDefaultSecret()
}

func RandomInt(max *big.Int) (int, error) {
	n, err := rand.Int(rand.Reader, max)
	if err != nil {
		return 0, err
	}
	return int(n.Int64()), nil
}
