package genotp

import (
	"encoding/base32"
	"errors"
	"strings"
)

func EncodeBase32(data []byte) string {
	return base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(data)
}

func DecodeBase32(data string) ([]byte, error) {
	cleaned := normalizeBase32Secret(data)
	upper := strings.ToUpper(cleaned)
	decoded, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(upper)
	if err != nil {
		return nil, errors.Join(ErrInvalidSecret, err)
	}
	return decoded, nil
}
