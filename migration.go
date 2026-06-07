package genotp

import (
	"encoding/base64"
	"net/url"
	"strings"
)

type OtpAuthMigrationAccount struct {
	Type      OtpType   `json:"type"`
	Label     string    `json:"label"`
	Issuer    string    `json:"issuer,omitempty"`
	SecretB32 string    `json:"secretB32"`
	Algorithm Algorithm `json:"algorithm"`
	Digits    uint32    `json:"digits"`
	Period    uint64    `json:"period"`
	Counter   uint64    `json:"counter"`
}

type OtpAuthMigrationOptions struct {
	Version    int32 `json:"version"`
	BatchSize  int32 `json:"batchSize"`
	BatchIndex int32 `json:"batchIndex"`
	BatchID    int32 `json:"batchId"`
}

type OtpAuthMigrationPayload struct {
	Accounts   []OtpAuthMigrationAccount `json:"accounts"`
	Version    int32                     `json:"version"`
	BatchSize  int32                     `json:"batchSize"`
	BatchIndex int32                     `json:"batchIndex"`
	BatchID    int32                     `json:"batchId"`
}

func BuildOtpAuthMigrationURI(
	accounts []OtpAuthMigrationAccount,
	opts *OtpAuthMigrationOptions,
) (string, error) {
	var payload []byte

	for _, account := range accounts {
		accountBytes, err := encodeMigrationAccount(account)
		if err != nil {
			return "", err
		}
		payload = appendProtoBytesField(payload, 1, accountBytes)
	}

	version := int32(1)
	var batchSize, batchIndex, batchID int32
	if opts != nil {
		if opts.Version > 0 {
			version = opts.Version
		}
		batchSize = opts.BatchSize
		batchIndex = opts.BatchIndex
		batchID = opts.BatchID
	}

	payload = appendProtoVarintField(payload, 2, uint64(version))
	if batchSize != 0 {
		payload = appendProtoVarintField(payload, 3, uint64(batchSize))
	}
	if batchIndex != 0 {
		payload = appendProtoVarintField(payload, 4, uint64(batchIndex))
	}
	if batchID != 0 {
		payload = appendProtoVarintField(payload, 5, uint64(batchID))
	}

	encoded := base64.RawURLEncoding.EncodeToString(payload)
	u := url.URL{
		Scheme:   "otpauth-migration",
		Host:     "offline",
		RawQuery: "data=" + encoded,
	}
	return u.String(), nil
}

func ParseOtpAuthMigrationURI(raw string) (*OtpAuthMigrationPayload, error) {
	parsed, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return nil, ErrInvalidMigration
	}
	if parsed.Scheme != "otpauth-migration" {
		return nil, ErrInvalidURI
	}

	data := parsed.Query().Get("data")
	if data == "" {
		return nil, ErrInvalidMigration
	}

	decoded, err := base64.RawURLEncoding.DecodeString(data)
	if err != nil {
		decoded, err = base64.StdEncoding.DecodeString(data)
		if err != nil {
			return nil, ErrInvalidMigration
		}
	}

	payload := &OtpAuthMigrationPayload{}
	for i := 0; i < len(decoded); {
		tag, next, err := readProtoVarint(decoded, i)
		if err != nil {
			return nil, ErrInvalidMigration
		}
		i = next

		fieldNum := int(tag >> 3)
		wireType := int(tag & 0x7)

		switch fieldNum {
		case 1:
			if wireType != 2 {
				return nil, ErrInvalidMigration
			}
			value, next, err := readProtoBytes(decoded, i)
			if err != nil {
				return nil, ErrInvalidMigration
			}
			account, err := decodeMigrationAccount(value)
			if err != nil {
				return nil, err
			}
			payload.Accounts = append(payload.Accounts, account)
			i = next
		case 2:
			value, next, err := readProtoScalar(decoded, i, wireType)
			if err != nil {
				return nil, ErrInvalidMigration
			}
			payload.Version = int32(value)
			i = next
		case 3:
			value, next, err := readProtoScalar(decoded, i, wireType)
			if err != nil {
				return nil, ErrInvalidMigration
			}
			payload.BatchSize = int32(value)
			i = next
		case 4:
			value, next, err := readProtoScalar(decoded, i, wireType)
			if err != nil {
				return nil, ErrInvalidMigration
			}
			payload.BatchIndex = int32(value)
			i = next
		case 5:
			value, next, err := readProtoScalar(decoded, i, wireType)
			if err != nil {
				return nil, ErrInvalidMigration
			}
			payload.BatchID = int32(value)
			i = next
		default:
			next, err := skipProtoField(decoded, i, wireType)
			if err != nil {
				return nil, ErrInvalidMigration
			}
			i = next
		}
	}

	return payload, nil
}

func encodeMigrationAccount(account OtpAuthMigrationAccount) ([]byte, error) {
	normalizedSecret := normalizeBase32Secret(account.SecretB32)
	if normalizedSecret == "" {
		return nil, ErrInvalidSecret
	}

	secretBuf := make([]byte, len(normalizedSecret)*5/8+1)
	n, err := DecodeBase32(secretBuf, normalizedSecret)
	if err != nil {
		return nil, err
	}

	digits := account.Digits
	if digits == 0 {
		digits = 6
	}

	algorithmEnum, err := migrationAlgorithmFromAlgorithm(account.Algorithm)
	if err != nil {
		return nil, err
	}

	digitEnum, err := migrationDigitEnum(digits)
	if err != nil {
		return nil, err
	}

	otpTypeEnum := uint64(2)
	if account.Type == HotpType {
		otpTypeEnum = 1
	}

	name := account.Label
	if account.Issuer != "" && !strings.HasPrefix(name, account.Issuer+":") {
		name = account.Issuer + ":" + account.Label
	}

	var msg []byte
	msg = appendProtoBytesField(msg, 1, secretBuf[:n])
	msg = appendProtoStringField(msg, 2, name)
	if account.Issuer != "" {
		msg = appendProtoStringField(msg, 3, account.Issuer)
	}
	msg = appendProtoVarintField(msg, 4, algorithmEnum)
	msg = appendProtoVarintField(msg, 5, digitEnum)
	msg = appendProtoVarintField(msg, 6, otpTypeEnum)
	if account.Type == HotpType && account.Counter != 0 {
		msg = appendProtoVarintField(msg, 7, account.Counter)
	}
	if account.Type == HotpType && account.Counter == 0 {
		msg = appendProtoVarintField(msg, 7, 0)
	}

	return msg, nil
}

func decodeMigrationAccount(data []byte) (OtpAuthMigrationAccount, error) {
	account := OtpAuthMigrationAccount{
		Type:      TotpType,
		Algorithm: SHA1,
		Digits:    6,
		Period:    30,
	}

	for i := 0; i < len(data); {
		tag, next, err := readProtoVarint(data, i)
		if err != nil {
			return OtpAuthMigrationAccount{}, ErrInvalidMigration
		}
		i = next

		fieldNum := int(tag >> 3)
		wireType := int(tag & 0x7)

		switch fieldNum {
		case 1:
			value, next, err := readProtoBytes(data, i)
			if err != nil {
				return OtpAuthMigrationAccount{}, ErrInvalidMigration
			}
			account.SecretB32 = EncodeBase32(value)
			i = next
		case 2:
			value, next, err := readProtoString(data, i)
			if err != nil {
				return OtpAuthMigrationAccount{}, ErrInvalidMigration
			}
			account.Label = value
			i = next
		case 3:
			value, next, err := readProtoString(data, i)
			if err != nil {
				return OtpAuthMigrationAccount{}, ErrInvalidMigration
			}
			account.Issuer = value
			i = next
		case 4:
			value, next, err := readProtoScalar(data, i, wireType)
			if err != nil {
				return OtpAuthMigrationAccount{}, ErrInvalidMigration
			}
			account.Algorithm, err = algorithmFromMigrationEnum(value)
			if err != nil {
				return OtpAuthMigrationAccount{}, err
			}
			i = next
		case 5:
			value, next, err := readProtoScalar(data, i, wireType)
			if err != nil {
				return OtpAuthMigrationAccount{}, ErrInvalidMigration
			}
			account.Digits, err = digitsFromMigrationEnum(value)
			if err != nil {
				return OtpAuthMigrationAccount{}, err
			}
			i = next
		case 6:
			value, next, err := readProtoScalar(data, i, wireType)
			if err != nil {
				return OtpAuthMigrationAccount{}, ErrInvalidMigration
			}
			account.Type = otpTypeFromMigrationEnum(value)
			i = next
		case 7:
			value, next, err := readProtoScalar(data, i, wireType)
			if err != nil {
				return OtpAuthMigrationAccount{}, ErrInvalidMigration
			}
			account.Counter = value
			i = next
		default:
			next, err := skipProtoField(data, i, wireType)
			if err != nil {
				return OtpAuthMigrationAccount{}, ErrInvalidMigration
			}
			i = next
		}
	}

	if account.SecretB32 == "" || account.Label == "" {
		return OtpAuthMigrationAccount{}, ErrInvalidMigration
	}

	account.Issuer, account.Label = splitMigrationLabel(account.Issuer, account.Label)

	return account, nil
}

func splitMigrationLabel(issuer, name string) (string, string) {
	if issuer != "" {
		prefix := issuer + ":"
		if strings.HasPrefix(name, prefix) {
			return issuer, strings.TrimSpace(name[len(prefix):])
		}
	}

	if idx := strings.IndexByte(name, ':'); idx > 0 {
		return strings.TrimSpace(name[:idx]), strings.TrimSpace(name[idx+1:])
	}

	return issuer, name
}

func migrationAlgorithmFromAlgorithm(algo Algorithm) (uint64, error) {
	switch algo {
	case SHA1:
		return 1, nil
	case SHA256:
		return 2, nil
	case SHA512:
		return 3, nil
	default:
		return 0, ErrInvalidAlgorithm
	}
}

func algorithmFromMigrationEnum(value uint64) (Algorithm, error) {
	switch value {
	case 0, 1:
		return SHA1, nil
	case 2:
		return SHA256, nil
	case 3:
		return SHA512, nil
	default:
		return 0, ErrInvalidAlgorithm
	}
}

func migrationDigitEnum(digits uint32) (uint64, error) {
	switch digits {
	case 6:
		return 1, nil
	case 8:
		return 2, nil
	default:
		return 0, ErrInvalidDigits
	}
}

func digitsFromMigrationEnum(value uint64) (uint32, error) {
	switch value {
	case 0, 1:
		return 6, nil
	case 2:
		return 8, nil
	default:
		return 0, ErrInvalidDigits
	}
}

func otpTypeFromMigrationEnum(value uint64) OtpType {
	if value == 1 {
		return HotpType
	}
	return TotpType
}

func appendProtoStringField(dst []byte, field int, value string) []byte {
	return appendProtoBytesField(dst, field, []byte(value))
}

func appendProtoBytesField(dst []byte, field int, value []byte) []byte {
	dst = appendProtoVarint(dst, uint64(field<<3|2))
	dst = appendProtoVarint(dst, uint64(len(value)))
	return append(dst, value...)
}

func appendProtoVarintField(dst []byte, field int, value uint64) []byte {
	dst = appendProtoVarint(dst, uint64(field<<3))
	return appendProtoVarint(dst, value)
}

func appendProtoVarint(dst []byte, value uint64) []byte {
	for value >= 0x80 {
		dst = append(dst, byte(value)|0x80)
		value >>= 7
	}
	return append(dst, byte(value))
}

func readProtoVarint(data []byte, offset int) (uint64, int, error) {
	var value uint64
	var shift uint
	for i := offset; i < len(data); i++ {
		b := data[i]
		value |= uint64(b&0x7f) << shift
		if b < 0x80 {
			return value, i + 1, nil
		}
		shift += 7
		if shift > 63 {
			break
		}
	}
	return 0, offset, ErrInvalidMigration
}

func readProtoBytes(data []byte, offset int) ([]byte, int, error) {
	size, next, err := readProtoVarint(data, offset)
	if err != nil {
		return nil, offset, err
	}
	end := next + int(size)
	if end < next || end > len(data) {
		return nil, offset, ErrInvalidMigration
	}
	return data[next:end], end, nil
}

func readProtoString(data []byte, offset int) (string, int, error) {
	value, next, err := readProtoBytes(data, offset)
	if err != nil {
		return "", offset, err
	}
	return string(value), next, nil
}

func readProtoScalar(data []byte, offset, wireType int) (uint64, int, error) {
	if wireType != 0 {
		return 0, offset, ErrInvalidMigration
	}
	return readProtoVarint(data, offset)
}

func skipProtoField(data []byte, offset, wireType int) (int, error) {
	switch wireType {
	case 0:
		_, next, err := readProtoVarint(data, offset)
		return next, err
	case 2:
		_, next, err := readProtoBytes(data, offset)
		return next, err
	default:
		return offset, ErrInvalidMigration
	}
}
