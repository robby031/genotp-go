package genotp

import (
	"crypto/hmac"
	"encoding/binary"
	"hash"
	"math"
	"sync"
	"sync/atomic"
	"time"
)

type TOTP struct {
	runtime   secretRuntime
	algorithm Algorithm
	digits    uint32
	period    uint64
	modValue  uint32
	macPool   sync.Pool
	hashFn    func() hash.Hash
	cleared   atomic.Bool
}

func NewTOTP(secret []byte, algorithm Algorithm, digits uint32, period uint64) (*TOTP, error) {
	return newTOTPWithRuntime(newStaticSecretRuntime(secret), algorithm, digits, period)
}

func NewTOTPFromSecretProvider(provider SecretProvider, algorithm Algorithm, digits uint32, period uint64) (*TOTP, error) {
	if provider == nil {
		return nil, ErrInvalidSecret
	}
	return newTOTPWithRuntime(newProviderSecretRuntime(provider), algorithm, digits, period)
}

func NewTOTPFromHMACProvider(provider HMACProvider, algorithm Algorithm, digits uint32, period uint64) (*TOTP, error) {
	if provider == nil {
		return nil, ErrInvalidSecret
	}
	return newTOTPWithRuntime(newHMACProviderRuntime(provider), algorithm, digits, period)
}

func newTOTPWithRuntime(runtime secretRuntime, algorithm Algorithm, digits uint32, period uint64) (*TOTP, error) {
	if digits < 6 || digits > 8 {
		return nil, ErrInvalidDigits
	}

	if period == 0 {
		return nil, ErrInvalidTime
	}

	if !runtime.hasStaticSecret() && !runtime.hasExternalProvider() {
		return nil, ErrInvalidSecret
	}

	hashFn, ok := hashFuncFor(algorithm)
	if !ok {
		return nil, ErrInvalidAlgorithm
	}

	t := &TOTP{
		runtime:   runtime,
		algorithm: algorithm,
		digits:    digits,
		period:    period,
		modValue:  uint32(math.Pow10(int(digits))),
		hashFn:    hashFn,
	}

	if runtime.hasStaticSecret() {
		t.macPool.New = func() any {
			return &macBuf{mac: hmac.New(hashFn, t.runtime.secret)}
		}
	}
	return t, nil
}

func (t *TOTP) Generate(timeVal *uint64) (string, error) {
	if t.cleared.Load() {
		return "", ErrInvalidSecret
	}
	current := nowOr(timeVal)
	counter := current / t.period

	var buf [8]byte
	out, err := t.genDigits(buf[:], counter, nil)
	if err != nil {
		return "", err
	}
	return string(out), nil
}

func (t *TOTP) Verify(code string, timeVal *uint64, window uint64) (bool, error) {
	if t.cleared.Load() {
		return false, ErrInvalidSecret
	}
	current := nowOr(timeVal)
	counter := current / t.period
	// Reject unreasonably large windows: max 1000 steps is far beyond any practical use.
	// Also prevents integer overflow when converting to int64.
	if window > 1000 {
		return false, ErrInvalidTime
	}
	windowInt64 := int64(window)

	userBytes := []byte(code)

	var matched byte
	for i := -windowInt64; i <= windowInt64; i++ {
		testCounter := addCounterSigned(counter, i)
		var expectedBuf [8]byte
		expected, err := t.genDigits(expectedBuf[:], testCounter, nil)
		if err != nil {
			return false, err
		}
		matched |= constantTimeEqByteResult(userBytes, expected)
	}

	return matched != 0, nil
}

func (t *TOTP) GenBound(context *OtpContext, timeVal *uint64) (string, error) {
	if t.cleared.Load() {
		return "", ErrInvalidSecret
	}
	current := nowOr(timeVal)
	counter := current / t.period

	var ctxBytes []byte
	if context != nil {
		ctxBytes = context.Bytes()
	}

	var buf [8]byte
	out, err := t.genDigits(buf[:], counter, ctxBytes)
	if err != nil {
		return "", err
	}
	return string(out), nil
}

func (t *TOTP) VerifyBound(code string, context *OtpContext, timeVal *uint64, window uint64) (bool, error) {
	if t.cleared.Load() {
		return false, ErrInvalidSecret
	}
	current := nowOr(timeVal)
	counter := current / t.period
	if window > 1000 {
		return false, ErrInvalidTime
	}
	windowInt64 := int64(window)

	var ctxBytes []byte
	if context != nil {
		ctxBytes = context.Bytes()
	}

	userBytes := []byte(code)

	var matched byte
	for i := -windowInt64; i <= windowInt64; i++ {
		testCounter := addCounterSigned(counter, i)
		var expectedBuf [8]byte
		expected, err := t.genDigits(expectedBuf[:], testCounter, ctxBytes)
		if err != nil {
			return false, err
		}
		matched |= constantTimeEqByteResult(userBytes, expected)
	}

	return matched != 0, nil
}

func (t *TOTP) VerifyTracking(code string, timeVal *uint64, window uint64, detector *ClockSkewDetector) (bool, error) {
	if t.cleared.Load() {
		return false, ErrInvalidSecret
	}
	current := nowOr(timeVal)
	baseCounter := current / t.period
	adjustedCounter, ok := checkedAddSigned(baseCounter, detector.CurrentOffset())
	if !ok {
		adjustedCounter = baseCounter
	}

	if window > 1000 {
		return false, ErrInvalidTime
	}
	windowInt64 := int64(window)

	userBytes := []byte(code)

	for i := -windowInt64; i <= windowInt64; i++ {
		testCounter, ok := checkedAddSigned(adjustedCounter, i)
		if !ok {
			continue
		}
		var expectedBuf [8]byte
		expected, err := t.genDigits(expectedBuf[:], testCounter, nil)
		if err != nil {
			return false, err
		}
		if constTimeEqBytes(userBytes, expected) {
			detector.Record(i, window)
			return true, nil
		}
	}

	return false, nil
}

func (t *TOTP) genDigits(dst []byte, counter uint64, context []byte) ([]byte, error) {
	code, err := t.computeTruncated(counter, context)
	if err != nil {
		return nil, err
	}
	return formatOTP(dst, code, t.digits), nil
}

func (t *TOTP) computeTruncated(counter uint64, context []byte) (uint32, error) {
	if t.runtime.hasStaticSecret() {
		return t.computeTruncatedStatic(counter, context), nil
	}

	var counterBuf [8]byte
	binary.BigEndian.PutUint64(counterBuf[:], counter)
	message := counterBuf[:]
	if len(context) > 0 {
		message = append(message, contextBindTagBytes...)
		message = append(message, context...)
	}
	hmacBytes, err := t.runtime.computeHMAC(t.algorithm, t.hashFn, message)
	if err != nil {
		return 0, err
	}
	return dynamicTruncate(hmacBytes, t.modValue), nil
}

func (t *TOTP) computeTruncatedStatic(counter uint64, context []byte) uint32 {
	mb := t.macPool.Get().(*macBuf)
	binary.BigEndian.PutUint64(mb.counter[:], counter)
	mb.mac.Reset()
	mb.mac.Write(mb.counter[:])
	if len(context) > 0 {
		mb.mac.Write(contextBindTagBytes)
		mb.mac.Write(context)
	}
	hmacBytes := mb.mac.Sum(mb.sum[:0])
	truncated := dynamicTruncate(hmacBytes, t.modValue)
	t.macPool.Put(mb)
	return truncated
}

func (t *TOTP) ClearSecret() {
	t.cleared.Store(true)
	t.runtime.clearStaticSecret()
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
