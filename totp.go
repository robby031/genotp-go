package genotp

import (
	"crypto/hmac"
	"encoding/binary"
	"hash"
	"math"
	"sync"
	"time"
)

type TOTP struct {
	secret    []byte
	algorithm Algorithm
	digits    uint32
	period    uint64
	modValue  uint32
	hashFunc  func() hash.Hash
	mu        sync.RWMutex
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
	hashFn, ok := hashFuncFor(algorithm)
	if !ok {
		return nil, ErrInvalidAlgorithm
	}
	secretCopy := make([]byte, len(secret))
	copy(secretCopy, secret)

	return &TOTP{
		secret:    secretCopy,
		algorithm: algorithm,
		digits:    digits,
		period:    period,
		modValue:  uint32(math.Pow10(int(digits))),
		hashFunc:  hashFn,
	}, nil
}

func (t *TOTP) Generate(timeVal *uint64) (string, error) {
	current := nowOr(timeVal)
	counter := current / t.period

	var buf [8]byte
	out := t.genDigits(buf[:], counter, nil)
	return string(out), nil
}

func (t *TOTP) Verify(code string, timeVal *uint64, window uint64) (bool, error) {
	current := nowOr(timeVal)
	counter := current / t.period
	if window > math.MaxInt64 {
		return false, ErrInvalidTime
	}
	windowInt64 := int64(window)

	var userBuf [8]byte
	userBytes := userBuf[:copy(userBuf[:], code)]

	var matched byte
	for i := -windowInt64; i <= windowInt64; i++ {
		testCounter := addCounterSigned(counter, i)
		var expectedBuf [8]byte
		expected := t.genDigits(expectedBuf[:], testCounter, nil)
		matched |= constantTimeEqByteResult(userBytes, expected)
	}

	return matched != 0, nil
}

func (t *TOTP) GenBound(context *OtpContext, timeVal *uint64) (string, error) {
	current := nowOr(timeVal)
	counter := current / t.period

	var ctxBytes []byte
	if context != nil {
		ctxBytes = context.Bytes()
	}

	var buf [8]byte
	out := t.genDigits(buf[:], counter, ctxBytes)
	return string(out), nil
}

func (t *TOTP) VerifyBound(code string, context *OtpContext, timeVal *uint64, window uint64) (bool, error) {
	current := nowOr(timeVal)
	counter := current / t.period
	if window > math.MaxInt64 {
		return false, ErrInvalidTime
	}
	windowInt64 := int64(window)

	var ctxBytes []byte
	if context != nil {
		ctxBytes = context.Bytes()
	}

	var userBuf [8]byte
	userBytes := userBuf[:copy(userBuf[:], code)]

	var matched byte
	for i := -windowInt64; i <= windowInt64; i++ {
		testCounter := addCounterSigned(counter, i)
		var expectedBuf [8]byte
		expected := t.genDigits(expectedBuf[:], testCounter, ctxBytes)
		matched |= constantTimeEqByteResult(userBytes, expected)
	}

	return matched != 0, nil
}

func (t *TOTP) VerifyTracking(code string, timeVal *uint64, window uint64, detector *ClockSkewDetector) (bool, error) {
	current := nowOr(timeVal)
	baseCounter := current / t.period
	adjustedCounter, ok := checkedAddSigned(baseCounter, detector.CurrentOffset())
	if !ok {
		adjustedCounter = baseCounter
	}

	if window > math.MaxInt64 {
		return false, ErrInvalidTime
	}
	windowInt64 := int64(window)

	var userBuf [8]byte
	userBytes := userBuf[:copy(userBuf[:], code)]

	for i := -windowInt64; i <= windowInt64; i++ {
		testCounter, ok := checkedAddSigned(adjustedCounter, i)
		if !ok {
			continue
		}
		var expectedBuf [8]byte
		expected := t.genDigits(expectedBuf[:], testCounter, nil)
		if constTimeEqBytes(userBytes, expected) {
			detector.Record(i, window)
			return true, nil
		}
	}

	return false, nil
}

func (t *TOTP) genDigits(dst []byte, counter uint64, context []byte) []byte {
	code := t.computeTruncated(counter, context)
	return formatOTP(dst, code, t.digits)
}

func (t *TOTP) computeTruncated(counter uint64, context []byte) uint32 {
	t.mu.RLock()
	secret := t.secret
	hashFn := t.hashFunc
	t.mu.RUnlock()

	mac := hmac.New(hashFn, secret)
	var counterBytes [8]byte
	binary.BigEndian.PutUint64(counterBytes[:], counter)
	mac.Write(counterBytes[:])
	if len(context) > 0 {
		mac.Write(contextBindTagBytes)
		mac.Write(context)
	}
	hmacBytes := mac.Sum(nil)
	return dynamicTruncate(hmacBytes, t.modValue)
}

func (t *TOTP) ClearSecret() {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.secret == nil {
		return
	}
	for i := range t.secret {
		t.secret[i] = 0
	}
	t.secret = nil
}

func nowOr(timeVal *uint64) uint64 {
	if timeVal != nil {
		return *timeVal
	}
	return uint64(time.Now().Unix())
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

// func saturatingMul(a, b uint64) uint64 {
// 	if a == 0 || b == 0 {
// 		return 0
// 	}
// 	if a > math.MaxUint64/b {
// 		return math.MaxUint64
// 	}
// 	return a * b
// }
