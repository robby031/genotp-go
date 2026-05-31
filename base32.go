package genotp

import (
	"encoding/base32"
	"errors"
)

func EncodeBase32(data []byte) string {
	return base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(data)
}

func DecodeBase32(data string) ([]byte, error) {
	decoded, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(data)
	if err != nil {
		return nil, errors.Join(ErrInvalidSecret, err)
	}
	return decoded, nil
}
