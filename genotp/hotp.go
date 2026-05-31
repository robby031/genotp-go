package genotp

import (
	"crypto/hmac"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/binary"
	"fmt"
	"hash"
	"math"
)

const contextBindTag = "genotp-ctx-v1\x00"

type HOTP struct {
	secret    []byte
	algorithm Algorithm
	digits    uint32
	modValue  uint32
}

func NewHOTP(secret []byte, algorithm Algorithm, digits uint32) (*HOTP, error) {
	if digits < 6 || digits > 8 {
		return nil, ErrInvalidDigits
	}

	if len(secret) == 0 {
		return nil, ErrInvalidSecret
	}

	modValue := uint32(math.Pow10(int(digits)))

	return &HOTP{
		secret:    secret,
		algorithm: algorithm,
		digits:    digits,
		modValue:  modValue,
	}, nil
}

func (h *HOTP) Generate(counter uint64) (string, error) {
	hmacBytes, err := h.computeHMAC(counter, nil)
	if err != nil {
		return "", err
	}

	code := h.dynamicTruncate(hmacBytes)
	return fmt.Sprintf("%0*d", h.digits, code), nil
}

func (h *HOTP) Verify(code string, counter uint64) (bool, error) {
	expected, err := h.Generate(counter)
	if err != nil {
		return false, err
	}

	return constantTimeEq(code, expected), nil
}

func (h *HOTP) VerifyWithResync(code string, counter uint64, lookAhead uint64) (uint64, bool, error) {
	for i := uint64(0); i <= lookAhead; i++ {
		testCounter := counter + i
		if testCounter < counter {
			break
		}

		expected, err := h.Generate(testCounter)
		if err != nil {
			continue
		}

		if constantTimeEq(code, expected) {
			return testCounter, true, nil
		}
	}

	return 0, false, nil
}

func (h *HOTP) GenerateBound(counter uint64, context *OtpContext) (string, error) {
	ctxBytes := []byte{}
	if context != nil {
		ctxBytes = context.Bytes()
	}

	hmacBytes, err := h.computeHMAC(counter, ctxBytes)
	if err != nil {
		return "", err
	}

	code := h.dynamicTruncate(hmacBytes)
	return fmt.Sprintf("%0*d", h.digits, code), nil
}

func (h *HOTP) VerifyBound(code string, counter uint64, context *OtpContext) (bool, error) {
	expected, err := h.GenerateBound(counter, context)
	if err != nil {
		return false, err
	}

	return constantTimeEq(code, expected), nil
}

func (h *HOTP) computeHMAC(counter uint64, context []byte) ([]byte, error) {
	counterBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(counterBytes, counter)

	var mac hash.Hash

	switch h.algorithm {
	case SHA1:
		mac = hmac.New(sha1.New, h.secret)
	case SHA256:
		mac = hmac.New(sha256.New, h.secret)
	case SHA512:
		mac = hmac.New(sha512.New, h.secret)
	default:
		return nil, ErrInvalidSecret
	}

	mac.Write(counterBytes)

	if len(context) > 0 {
		mac.Write([]byte(contextBindTag))
		mac.Write(context)
	}

	return mac.Sum(nil), nil
}

func (h *HOTP) dynamicTruncate(hmac []byte) uint32 {
	offset := int(hmac[len(hmac)-1] & 0x0f)

	binary := ((uint32(hmac[offset]) & 0x7f) << 24) |
		(uint32(hmac[offset+1]) << 16) |
		(uint32(hmac[offset+2]) << 8) |
		uint32(hmac[offset+3])

	return binary % h.modValue
}

func (h *HOTP) ClearSecret() {
	for i := range h.secret {
		h.secret[i] = 0
	}
}
