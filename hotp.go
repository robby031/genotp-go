package genotp

import (
	"crypto/hmac"
	// #nosec G505 -- SHA1 remains required for RFC 4226 / Google Authenticator compatibility.
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/binary"
	"hash"
	"math"
	"sync"
	"sync/atomic"
)

const contextBindTag = "genotp-ctx-v1\x00"
const maxLookAhead = 10000

var contextBindTagBytes = []byte(contextBindTag)

const maxHMACSize = 64

type macBuf struct {
	mac     hash.Hash
	counter [8]byte
	sum     [maxHMACSize]byte
}

type HOTP struct {
	runtime   secretRuntime
	algorithm Algorithm
	digits    uint32
	modValue  uint32
	macPool   sync.Pool
	hashFn    func() hash.Hash
	cleared   atomic.Bool
}

func NewHOTP(secret []byte, algorithm Algorithm, digits uint32) (*HOTP, error) {
	return newHOTPWithRuntime(newStaticSecretRuntime(secret), algorithm, digits)
}

func NewHOTPFromSecretProvider(provider SecretProvider, algorithm Algorithm, digits uint32) (*HOTP, error) {
	if provider == nil {
		return nil, ErrInvalidSecret
	}
	return newHOTPWithRuntime(newProviderSecretRuntime(provider), algorithm, digits)
}

func NewHOTPFromHMACProvider(provider HMACProvider, algorithm Algorithm, digits uint32) (*HOTP, error) {
	if provider == nil {
		return nil, ErrInvalidSecret
	}
	return newHOTPWithRuntime(newHMACProviderRuntime(provider), algorithm, digits)
}

func newHOTPWithRuntime(runtime secretRuntime, algorithm Algorithm, digits uint32) (*HOTP, error) {
	if digits < 6 || digits > 8 {
		return nil, ErrInvalidDigits
	}

	if !runtime.hasStaticSecret() && !runtime.hasExternalProvider() {
		return nil, ErrInvalidSecret
	}

	hashFn, ok := hashFuncFor(algorithm)
	if !ok {
		return nil, ErrInvalidAlgorithm
	}

	h := &HOTP{
		runtime:   runtime,
		algorithm: algorithm,
		digits:    digits,
		modValue:  uint32(math.Pow10(int(digits))),
		hashFn:    hashFn,
	}

	if runtime.hasStaticSecret() {
		h.macPool.New = func() any {
			return &macBuf{
				mac: hmac.New(hashFn, h.runtime.secret),
			}
		}
	}
	return h, nil
}

func hashFuncFor(algorithm Algorithm) (func() hash.Hash, bool) {
	switch algorithm {
	case SHA1:
		return sha1.New, true
	case SHA256:
		return sha256.New, true
	case SHA512:
		return sha512.New, true
	default:
		return nil, false
	}
}

func (h *HOTP) Generate(counter uint64) (string, error) {
	if h.cleared.Load() {
		return "", ErrInvalidSecret
	}
	var buf [8]byte
	out, err := h.genDigits(buf[:], counter, nil)
	if err != nil {
		return "", err
	}
	return string(out), nil
}

func (h *HOTP) Verify(code string, counter uint64) (bool, error) {
	if h.cleared.Load() {
		return false, ErrInvalidSecret
	}
	userBytes := []byte(code)

	var expectedBuf [8]byte
	expected, err := h.genDigits(expectedBuf[:], counter, nil)
	if err != nil {
		return false, err
	}
	return constTimeEqBytes(userBytes, expected), nil
}

func (h *HOTP) VerifyWithResync(code string, counter uint64, lookAhead uint64) (uint64, bool, error) {
	if h.cleared.Load() {
		return 0, false, ErrInvalidSecret
	}
	if lookAhead > maxLookAhead {
		return 0, false, ErrInvalidCounter
	}

	userBytes := []byte(code)

	for i := uint64(0); i <= lookAhead; i++ {
		testCounter := counter + i
		if testCounter < counter {
			break
		}

		var expectedBuf [8]byte
		expected, err := h.genDigits(expectedBuf[:], testCounter, nil)
		if err != nil {
			return 0, false, err
		}
		if constTimeEqBytes(userBytes, expected) {
			return testCounter, true, nil
		}
	}

	return 0, false, nil
}

func (h *HOTP) GenBound(counter uint64, context *OtpContext) (string, error) {
	if h.cleared.Load() {
		return "", ErrInvalidSecret
	}
	var ctxBytes []byte
	if context != nil {
		ctxBytes = context.Bytes()
	}
	var buf [8]byte
	out, err := h.genDigits(buf[:], counter, ctxBytes)
	if err != nil {
		return "", err
	}
	return string(out), nil
}

func (h *HOTP) VerifyBound(code string, counter uint64, context *OtpContext) (bool, error) {
	if h.cleared.Load() {
		return false, ErrInvalidSecret
	}
	var ctxBytes []byte
	if context != nil {
		ctxBytes = context.Bytes()
	}
	userBytes := []byte(code)

	var expectedBuf [8]byte
	expected, err := h.genDigits(expectedBuf[:], counter, ctxBytes)
	if err != nil {
		return false, err
	}
	return constTimeEqBytes(userBytes, expected), nil
}

func (h *HOTP) genDigits(dst []byte, counter uint64, context []byte) ([]byte, error) {
	code, err := h.computeTruncated(counter, context)
	if err != nil {
		return nil, err
	}
	return formatOTP(dst, code, h.digits), nil
}

func (h *HOTP) computeTruncated(counter uint64, context []byte) (uint32, error) {
	if h.runtime.hasStaticSecret() {
		return h.computeTruncatedStatic(counter, context), nil
	}

	var counterBuf [8]byte
	binary.BigEndian.PutUint64(counterBuf[:], counter)
	message := counterBuf[:]
	if len(context) > 0 {
		message = append(message, contextBindTagBytes...)
		message = append(message, context...)
	}
	hmacBytes, err := h.runtime.computeHMAC(h.algorithm, h.hashFn, message)
	if err != nil {
		return 0, err
	}
	return dynamicTruncate(hmacBytes, h.modValue), nil
}

func (h *HOTP) computeTruncatedStatic(counter uint64, context []byte) uint32 {
	mb := h.macPool.Get().(*macBuf)
	binary.BigEndian.PutUint64(mb.counter[:], counter)
	mb.mac.Reset()
	mb.mac.Write(mb.counter[:])
	if len(context) > 0 {
		mb.mac.Write(contextBindTagBytes)
		mb.mac.Write(context)
	}
	hmacBytes := mb.mac.Sum(mb.sum[:0])
	truncated := dynamicTruncate(hmacBytes, h.modValue)
	h.macPool.Put(mb)
	return truncated
}

func dynamicTruncate(hmacBytes []byte, modValue uint32) uint32 {
	offset := int(hmacBytes[len(hmacBytes)-1] & 0x0f)
	binary := ((uint32(hmacBytes[offset]) & 0x7f) << 24) |
		(uint32(hmacBytes[offset+1]) << 16) |
		(uint32(hmacBytes[offset+2]) << 8) |
		uint32(hmacBytes[offset+3])
	return binary % modValue
}

func formatOTP(dst []byte, code, digits uint32) []byte {
	d := int(digits)
	for i := d - 1; i >= 0; i-- {
		dst[i] = byte('0' + code%10)
		code /= 10
	}
	return dst[:d]
}

func (h *HOTP) ClearSecret() {
	h.cleared.Store(true)
	h.runtime.clearStaticSecret()
}
