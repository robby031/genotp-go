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
	"time"
)

const totpContextBindTag = "genotp-ctx-v1\x00"

type TOTP struct {
	secret    []byte
	algorithm Algorithm
	digits    uint32
	period    uint64
	modValue  uint32
}

func NewTOTP(secret []byte, algorithm Algorithm, digits uint32, period uint64) (*TOTP, error) {
	if digits < 6 || digits > 8 {
		return nil, ErrInvalidDigits
	}

	if period == 0 {
		return nil, ErrInvalidTime
	}

	if len(secret) == 0 {
		return nil, ErrInvalidSecret
	}

	modValue := uint32(math.Pow10(int(digits)))

	return &TOTP{
		secret:    secret,
		algorithm: algorithm,
		digits:    digits,
		period:    period,
		modValue:  modValue,
	}, nil
}

func (t *TOTP) Generate(timeVal *uint64) (string, error) {
	var current uint64
	if timeVal != nil {
		current = *timeVal
	} else {
		current = uint64(time.Now().Unix())
	}

	counter := current / t.period

	hmacBytes, err := t.computeHMAC(counter, nil)
	if err != nil {
		return "", err
	}

	code := t.dynamicTruncate(hmacBytes)
	return fmt.Sprintf("%0*d", t.digits, code), nil
}

func (t *TOTP) Verify(code string, timeVal *uint64, window uint64) (bool, error) {
	var current uint64
	if timeVal != nil {
		current = *timeVal
	} else {
		current = uint64(time.Now().Unix())
	}

	counter := current / t.period
	if window > math.MaxInt64 {
		return false, ErrInvalidTime
	}
	windowInt64 := int64(window)

	var matched byte
	for i := -windowInt64; i <= windowInt64; i++ {
		testCounter := addCounterSigned(counter, i)
		testTime := saturatingMul(testCounter, t.period)
		expected, err := t.Generate(&testTime)
		if err != nil {
			return false, err
		}

		var m byte
		if constantTimeEq(code, expected) {
			m = 1
		}
		matched |= m
	}

	return matched != 0, nil
}

func (t *TOTP) GenerateBound(context *OtpContext, timeVal *uint64) (string, error) {
	var current uint64
	if timeVal != nil {
		current = *timeVal
	} else {
		current = uint64(time.Now().Unix())
	}

	counter := current / t.period

	ctxBytes := []byte{}
	if context != nil {
		ctxBytes = context.Bytes()
	}

	hmacBytes, err := t.computeHMAC(counter, ctxBytes)
	if err != nil {
		return "", err
	}

	code := t.dynamicTruncate(hmacBytes)
	return fmt.Sprintf("%0*d", t.digits, code), nil
}

func (t *TOTP) VerifyBound(code string, context *OtpContext, timeVal *uint64, window uint64) (bool, error) {
	var current uint64
	if timeVal != nil {
		current = *timeVal
	} else {
		current = uint64(time.Now().Unix())
	}

	counter := current / t.period
	if window > math.MaxInt64 {
		return false, ErrInvalidTime
	}
	windowInt64 := int64(window)

	var matched byte
	for i := -windowInt64; i <= windowInt64; i++ {
		testCounter := addCounterSigned(counter, i)
		testTime := saturatingMul(testCounter, t.period)
		expected, err := t.GenerateBound(context, &testTime)
		if err != nil {
			return false, err
		}

		var m byte
		if constantTimeEq(code, expected) {
			m = 1
		}
		matched |= m
	}

	return matched != 0, nil
}

func (t *TOTP) VerifyTracking(code string, timeVal *uint64, window uint64, detector *ClockSkewDetector) (bool, error) {
	var current uint64
	if timeVal != nil {
		current = *timeVal
	} else {
		current = uint64(time.Now().Unix())
	}

	baseCounter := current / t.period
	adjustedCounter, ok := checkedAddSigned(baseCounter, detector.CurrentOffset())
	if !ok {
		adjustedCounter = baseCounter
	}

	if window > math.MaxInt64 {
		return false, ErrInvalidTime
	}
	windowInt64 := int64(window)

	for i := -windowInt64; i <= windowInt64; i++ {
		testCounter, ok := checkedAddSigned(adjustedCounter, i)
		if !ok {
			continue
		}
		testTime := saturatingMul(testCounter, t.period)
		expected, err := t.Generate(&testTime)
		if err != nil {
			return false, err
		}

		if constantTimeEq(code, expected) {
			detector.Record(i, window)
			return true, nil
		}
	}

	return false, nil
}

func (t *TOTP) computeHMAC(counter uint64, context []byte) ([]byte, error) {
	counterBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(counterBytes, counter)

	var mac hash.Hash

	switch t.algorithm {
	case SHA1:
		mac = hmac.New(sha1.New, t.secret)
	case SHA256:
		mac = hmac.New(sha256.New, t.secret)
	case SHA512:
		mac = hmac.New(sha512.New, t.secret)
	default:
		return nil, ErrInvalidSecret
	}

	mac.Write(counterBytes)

	if len(context) > 0 {
		mac.Write([]byte(totpContextBindTag))
		mac.Write(context)
	}

	return mac.Sum(nil), nil
}

func (t *TOTP) dynamicTruncate(hmac []byte) uint32 {
	offset := int(hmac[len(hmac)-1] & 0x0f)

	binary := ((uint32(hmac[offset]) & 0x7f) << 24) |
		(uint32(hmac[offset+1]) << 16) |
		(uint32(hmac[offset+2]) << 8) |
		uint32(hmac[offset+3])

	return binary % t.modValue
}

func (t *TOTP) ClearSecret() {
	for i := range t.secret {
		t.secret[i] = 0
	}
}

func addCounterSigned(counter uint64, delta int64) uint64 {
	v, ok := checkedAddSigned(counter, delta)
	if !ok {
		return 0
	}
	return v
}

func checkedAddSigned(counter uint64, delta int64) (uint64, bool) {
	if delta >= 0 {
		d := uint64(delta)
		sum := counter + d
		if sum < counter {
			return 0, false
		}
		return sum, true
	}
	d := uint64(-delta)
	if d > counter {
		return 0, false
	}
	return counter - d, true
}

func saturatingMul(a, b uint64) uint64 {
	if a == 0 || b == 0 {
		return 0
	}
	if a > math.MaxUint64/b {
		return math.MaxUint64
	}
	return a * b
}
